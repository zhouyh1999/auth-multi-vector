use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use gem_auth_scheme_multi::compact as gem;
use gem_core::{Hash, hash_serialized};
use std::{fs, path::Path};

// Fixed-width bincode fields of EManifest and EAuth, in their original wire order.
type Manifest = (u32, Hash, String, String, u8, usize, usize, u32, Hash, u8);
type Signed = (Manifest, Vec<u8>);
type Bundle = (gem::TrustedSchemeSnapshotV3, [Signed; 3]);
type Result<T> = anyhow::Result<T>;
const METHODS: [&str; 4] = ["raw", "vida_per_token", "vida_batched", "block_fast"];

fn layout(method: usize, stage: usize) -> (usize, u8) {
    (
        if method == 3 { [8, 32, 128][stage] } else { 1 },
        u8::from(method != 0),
    )
}

fn sign_book(
    source: Hash,
    stage: usize,
    coords: &[i16],
    h: usize,
    repr: u8,
    key: &SigningKey,
) -> Result<Signed> {
    let points = if repr == 1 {
        gem_matrix_proof::prepare_projection_generators_v1(h * 128)?;
        coords
            .chunks(h * 128)
            .map(|chunk| {
                let mut block = chunk.to_vec();
                block.resize(h * 128, 0);
                gem::numeric::commit_matrix(&block)
            })
            .collect::<gem_core::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let raw = if repr == 0 { coords } else { &[] };
    let material = (
        0u32,
        coords.len() / 128,
        raw,
        Vec::<u16>::new(),
        Vec::<u32>::new(),
        points,
    );
    // Each static book is a single authenticated leaf in e_prepare.
    let root = hash_serialized(b"four-method.material.v1", &material)?;
    let manifest = (
        1,
        source,
        gem::numeric::PROFILE_ID.to_owned(),
        gem_matrix_proof::GENERATOR_ID_V1.to_owned(),
        stage as u8,
        h,
        128,
        1,
        root,
        repr,
    );
    let signature = key
        .sign(&bincode::serialize(&manifest)?)
        .to_bytes()
        .to_vec();
    Ok((manifest, signature))
}

fn verify(packet: &[u8], anchors: &[u8], method: usize) -> Result<[u8; 128]> {
    anyhow::ensure!(method < METHODS.len() && anchors.len() == 64 && packet.len() < 65536);
    let (snapshot, stages): Bundle = bincode::deserialize(packet)?;
    anyhow::ensure!(snapshot.owner_public_key == anchors[..32]);
    gem::validate_trusted_scheme_snapshot_v3(&snapshot)?;
    let stage_key = VerifyingKey::from_bytes(anchors[32..].try_into()?)?;
    let mut digests = [0; 128];
    digests[..32].copy_from_slice(&snapshot.expected_manifest_digest);
    for (i, (m, sig)) in stages.iter().enumerate() {
        let (height, representation) = layout(method, i);
        anyhow::ensure!(
            m.0 == 1
                && m.1 == snapshot.expected_manifest_digest
                && m.2 == gem::numeric::PROFILE_ID
                && m.3 == gem_matrix_proof::GENERATOR_ID_V1
                && m.4 as usize == i
                && m.5 == height
                && m.6 == 128
                && m.7
                    == if i < 2 {
                        1
                    } else {
                        snapshot.signed.manifest.source().document_count
                    }
                && m.9 == representation
        );
        stage_key.verify_strict(&bincode::serialize(m)?, &Signature::from_slice(sig)?)?;
        digests[32 * (i + 1)..32 * (i + 2)]
            .copy_from_slice(&hash_serialized(b"four-method.snapshot.v1", m)?);
    }
    Ok(digests)
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    anyhow::ensure!(
        args.len() == 2,
        "expected dataset directory and bundle output directory"
    );
    let full = Path::new(&args[0]);

    let out = Path::new(&args[1]);
    gem_lotte_auth_pilot::workspace_output(out)?;
    let snapshot: gem::TrustedSchemeSnapshotV3 =
        serde_json::from_slice(&fs::read(full.join("inputs/trusted.json"))?)?;
    let envelope: gem_lotte_auth_pilot::Envelope =
        gem_lotte_auth_pilot::offline::load_offline(&full.join("inputs/offline.compact"))?;
    anyhow::ensure!(
        envelope.version == 1
            && envelope.input_binding
                == gem_core::sha256_file(full.join("inputs/input-bindings.json"))?
            && envelope.prepared.trusted == snapshot
    );
    let raw = envelope.prepared.public;
    let public = gem::SchemePublicPayloadV3 {
        entries: raw.entries.clone(),
        raw_centroids: Some(raw.clone()),
    };
    gem::authenticate_scheme_public_data_v3(
        &snapshot,
        gem::SchemeBackendV3::FixedRawFp16,
        &public,
    )?;
    let coarse = gem::numeric::fixed_coordinates_v1(
        &raw.coarse_bits
            .iter()
            .copied()
            .map(f32::from_bits)
            .collect::<Vec<_>>(),
    )?;
    let fine = gem::numeric::fixed_fp16_v1(&raw.fine_bits)?;
    // Same test owner as population_owner.rs and PopulationService::open.
    let key = SigningKey::from_bytes(&[19; 32]);
    let anchors = [snapshot.owner_public_key, key.verifying_key().to_bytes()].concat();
    fs::write(out.join("anchors.bin"), &anchors)?;
    for (method, name) in METHODS.iter().enumerate() {
        let mut stages = Vec::new();
        for (stage, coords) in [&coarse, &fine].into_iter().enumerate() {
            let (h, repr) = layout(method, stage);
            stages.push(sign_book(
                snapshot.expected_manifest_digest,
                stage,
                coords,
                h,
                repr,
                &key,
            )?);
        }
        let (h, repr) = layout(method, 2);
        let doc_file = full.join(format!("native-material/global-h{h}-r{repr}.auth"));
        stages.push(bincode::deserialize(&fs::read(doc_file)?)?);
        let stages: [Signed; 3] = stages.try_into().ok().unwrap();
        let packet = bincode::serialize(&(&snapshot, stages))?;
        fs::write(
            out.join(format!("{name}.pins")),
            verify(&packet, &anchors, method)?,
        )?;
        fs::write(out.join(format!("{name}.bin")), packet)?;
    }
    Ok(())
}
