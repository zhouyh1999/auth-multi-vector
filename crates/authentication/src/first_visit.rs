use super::*;

use openssl::{
    ssl::{
        Ssl, SslContext, SslMethod, SslOptions, SslSessionCacheMode, SslStream, SslVerifyMode,
        SslVersion,
    },
    x509::{X509, store::X509StoreBuilder},
};
use std::io::{BufRead as VisitBufRead, Read as VisitRead, Write as VisitWrite};
use std::net::{SocketAddr as VisitAddress, TcpStream as VisitTcp};
use std::path::Path as VisitPath;
pub(super) const VISIT_HOST: &str = "gem-owner.lotte.test";
pub(super) const VISIT_METHODS: [(u8, &str); 4] = [
    (0, "raw"),
    (1, "vida_per_token"),
    (2, "vida_batched"),
    (5, "block_fast"),
];
pub(super) const VISIT_STAGES: [&str; 4] = ["coarse", "fine", "rerank", "all"];
pub(super) fn owner_key_for_server() -> [u8; 32] {
    SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes()
}
pub(super) fn visit_method(p: u8) -> anyhow::Result<&'static str> {
    VISIT_METHODS
        .iter()
        .find(|v| v.0 == p)
        .map(|v| v.1)
        .ok_or_else(|| anyhow::anyhow!("unknown first-visit method"))
}
#[derive(Serialize, Deserialize)]
pub(super) struct VisitBundle {
    pub(super) source: TrustedSchemeSnapshotV3,
    pub(super) stages: Vec<EAuth>,
}
pub(super) struct VisitTrust {
    pub(super) index: Hash,
    pub(super) stages: [Hash; 3],
    pub(super) book_sizes: [usize; 2],
}
pub(super) fn verify_visit(
    body: &[u8],
    keys: &[[u8; 32]; 2],
    policy: u8,
    scope: usize,
) -> anyhow::Result<VisitTrust> {
    anyhow::ensure!(scope <= 3 && body.len() <= 32768);
    let packet: VisitBundle = e_decode(body)?;
    anyhow::ensure!(packet.source.owner_public_key == keys[0], "index owner key");
    validate_trusted_scheme_snapshot_v3(&packet.source)?;
    let index = packet.source.expected_manifest_digest;
    let base = packet.source.signed.manifest.source();
    let ids = if scope == 3 {
        vec![0, 1, 2]
    } else {
        vec![scope]
    };
    anyhow::ensure!(packet.stages.len() == ids.len(), "wrong manifest count");
    let (_, heights) = pop_route(policy, false);
    let mut stages = [[0; 32]; 3];
    for (a, i) in packet.stages.iter().zip(ids) {
        e_auth(a, keys[1])?;
        let m = &a.manifest;
        anyhow::ensure!(
            m.stage as usize == i
                && m.source == index
                && m.h == heights[i]
                && m.dimension == 128
                && m.representation == e_repr(policy)
                && m.leaf_count == if i == 2 { base.document_count } else { 1 },
            "stage manifest binding"
        );
        stages[i] = hash(b"four-method.snapshot.v1", m)?;
    }
    Ok(VisitTrust {
        index,
        stages,
        book_sizes: [base.coarse_count as usize, base.fine_count as usize],
    })
}
pub(super) fn visit_keys(data: &[u8]) -> anyhow::Result<[[u8; 32]; 2]> {
    anyhow::ensure!(data.len() == 64, "two long-term owner public keys");
    Ok([data[..32].try_into()?, data[32..].try_into()?])
}
pub fn publish_visit_bundles(input: &VisitPath, out: &VisitPath) -> anyhow::Result<()> {
    std::fs::create_dir_all(out)?;
    let keybytes = std::fs::read(input.join("anchors.bin"))?;
    let keys = visit_keys(&keybytes)?;
    std::fs::write(out.join("anchors.bin"), keybytes)?;
    for (policy, name) in VISIT_METHODS {
        let (source, auth): (TrustedSchemeSnapshotV3, [EAuth; 3]) =
            e_decode(&std::fs::read(input.join(format!("{name}.bin")))?)?;
        let oracle = std::fs::read(input.join(format!("{name}.pins")))?;
        anyhow::ensure!(oracle.len() == 128);
        for (stage, scope) in VISIT_STAGES.iter().enumerate() {
            let stages = if stage == 3 {
                auth.to_vec()
            } else {
                vec![auth[stage].clone()]
            };
            let bytes = e_encode(&VisitBundle {
                source: source.clone(),
                stages,
            })?;
            let t = verify_visit(&bytes, &keys, policy, stage)?;
            anyhow::ensure!(oracle[..32] == t.index);
            for i in 0..3 {
                if stage == 3 || stage == i {
                    anyhow::ensure!(oracle[32 + 32 * i..64 + 32 * i] == t.stages[i]);
                }
            }
            std::fs::write(out.join(format!("{name}.{scope}.bin")), bytes)?;
        }
    }
    Ok(())
}
pub struct VisitClient {
    pub(super) address: VisitAddress,
    pub(super) ca: X509,
    pub(super) certificate_hash: Vec<u8>,
    pub(super) token: String,
    pub(super) keys: [[u8; 32]; 2],
}
impl VisitClient {
    pub fn open(root: &VisitPath) -> anyhow::Result<Self> {
        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("connection.json"))?)?;
        anyhow::ensure!(config["tls_name"] == VISIT_HOST);
        let address = config["address"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("digest address"))?
            .parse()?;
        let ca = X509::from_pem(&std::fs::read(root.join("source.pem"))?)?;
        let certificate_hash = ca.digest(openssl::hash::MessageDigest::sha256())?.to_vec();
        let token = std::fs::read_to_string(root.join("auth-token"))?
            .trim()
            .to_owned();
        anyhow::ensure!(token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()));
        let keys = visit_keys(&std::fs::read(root.join("anchors.bin"))?)?;
        Ok(Self {
            address,
            ca,
            certificate_hash,
            token,
            keys,
        })
    }
    pub(super) fn fetch(
        &self,
        policy: u8,
        stage: usize,
    ) -> anyhow::Result<(VisitTrust, serde_json::Value)> {
        let begin = Instant::now();
        let name = visit_method(policy)?;
        let scope = VISIT_STAGES
            .get(stage)
            .ok_or_else(|| anyhow::anyhow!("bad scope"))?;
        let id = hex::encode(rand::random::<[u8; 16]>());
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(self.ca.clone())?;
        let mut context = SslContext::builder(SslMethod::tls_client())?;
        context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        context.set_options(SslOptions::NO_TICKET);
        context.set_session_cache_mode(SslSessionCacheMode::OFF);
        context.set_cert_store(store.build());
        context.set_verify(SslVerifyMode::PEER);
        let mut session = Ssl::new(&context.build())?;
        session.set_hostname(VISIT_HOST)?;
        session.param_mut().set_host(VISIT_HOST)?;
        let timeout = std::time::Duration::from_secs(8);
        let tcp = VisitTcp::connect_timeout(&self.address, timeout)?;
        tcp.set_nodelay(true)?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        let mut tls = SslStream::new(session, tcp)?;
        tls.connect()?;
        anyhow::ensure!(
            tls.ssl().version_str() == "TLSv1.3"
                && !tls.ssl().session_reused()
                && tls.ssl().verify_result() == openssl::x509::X509VerifyResult::OK,
            "fresh TLS peer"
        );
        let peer = tls
            .ssl()
            .peer_certificate()
            .ok_or_else(|| anyhow::anyhow!("source certificate"))?;
        anyhow::ensure!(
            peer.digest(openssl::hash::MessageDigest::sha256())?
                .as_ref()
                == self.certificate_hash.as_slice(),
            "source identity"
        );
        let connected = Instant::now();
        let request = format!(
            "GET /lotte-pooled-dev/{name}/{scope} HTTP/1.0\r\nHost: {VISIT_HOST}\r\nAuthorization: Bearer {}\r\nX-Visit: {id}\r\nConnection: close\r\n\r\n",
            self.token
        );
        tls.write_all(request.as_bytes())?;
        tls.flush()?;
        let mut response = std::io::BufReader::new(tls);
        let mut line = String::new();
        let mut header_bytes = response.read_line(&mut line)?;
        anyhow::ensure!(
            line.starts_with("HTTP/1.0 200 ") || line.starts_with("HTTP/1.1 200 "),
            "owner HTTP status"
        );
        let mut length = None;
        let mut receipt = false;
        loop {
            line.clear();
            let n = response.read_line(&mut line)?;
            header_bytes += n;
            anyhow::ensure!(n > 0 && header_bytes <= 8192, "owner response headers");
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                if key.eq_ignore_ascii_case("Content-Length") {
                    anyhow::ensure!(length.is_none());
                    length = Some(value.trim().parse::<usize>()?);
                }
                if key.eq_ignore_ascii_case("X-Visit") {
                    anyhow::ensure!(!receipt && value.trim() == id);
                    receipt = true;
                }
            }
        }
        let len = length.ok_or_else(|| anyhow::anyhow!("owner response size"))?;
        anyhow::ensure!(
            receipt && (1..=32768).contains(&len),
            "owner response binding"
        );
        let mut body = vec![0; len];
        response.read_exact(&mut body)?;
        let received = Instant::now();
        let trust = verify_visit(&body, &self.keys, policy, stage)?;
        let verified = Instant::now();
        let ms = |a: Instant, b: Instant| b.duration_since(a).as_secs_f64() * 1000.;
        Ok((
            trust,
            serde_json::json!({"id":id,"tls":"TLSv1.3","session_reused":false,"origin_verified":true,
            "source_manifests":1,"stage_manifests":if stage==3{3}else{1},"receipt_checked":true,
            "connect_tls_ms":ms(begin,connected),"http_ms":ms(connected,received),"verify_derive_ms":ms(received,verified),
            "http_request_bytes":request.len(),"http_header_bytes":header_bytes,"payload_bytes":len,"body_sha256":hex::encode(openssl::sha::sha256(&body))}),
        ))
    }
}
