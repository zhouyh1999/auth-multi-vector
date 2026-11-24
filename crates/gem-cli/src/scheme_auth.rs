//! File-isolated owner/server/client interface and source-bound acceptance benchmark.
use super::fixed_reference::{
    FixedReferenceRecordV3, independent_components_v3, independent_fixed_reference_v3,
};
use super::scheme_family::*;
use anyhow::{Context, Result, bail};
use bincode::Options;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use gem_auth_v3::{MAX_VO_BYTES, PreparedRawSnapshotV3, PublicModeV3};
use gem_core::{QueryV3, hash_bytes, sha256_bytes, sha256_file};
use gem_matrix_proof::prepare_projection_generators_v1;
use gem_search::import_queries;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
const VO_SHA256_KIND: &str = "sha256-file-v1";
fn default_scheme_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(48))
}
#[derive(Parser)]
#[command(
    name = "gem-scheme-auth-v3",
    version = "V3R3-auth8-s16-auth9-compact-v1"
)]
struct Cli {
    /// New preparation defaults to compact/schema 9; existing snapshots detect their signed profile.
    #[arg(long, global = true, value_enum)]
    numeric_profile: Option<NumericProfileArg>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum NumericProfileArg {
    S16,
    Compact,
}
#[derive(Clone, Copy, ValueEnum)]
enum Backend {
    FixedRawFp16,
    FixedRawFp32,
    MatrixScheme,
}
impl From<Backend> for SchemeBackendV3 {
    fn from(b: Backend) -> Self {
        match b {
            Backend::FixedRawFp16 => Self::FixedRawFp16,
            Backend::FixedRawFp32 => Self::FixedRawFp32,
            Backend::MatrixScheme => Self::MatrixScheme,
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Cold,
}
impl From<Mode> for PublicModeV3 {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Cold => Self::Cold,
        }
    }
}
#[derive(Subcommand)]
enum Command {
    AuditComponents {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = default_scheme_threads())]
        threads: usize,
    },
    AttackCheck {
        #[arg(long)]
        trusted: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        vo: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = default_scheme_threads())]
        threads: usize,
    },
    Keygen {
        #[arg(long)]
        output_dir: PathBuf,
    },
    Prepare {
        #[arg(long)]
        raw_snapshot: PathBuf,
        #[arg(long)]
        owner_key: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = default_scheme_threads())]
        threads: usize,
    },
    Validate {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = default_scheme_threads())]
        threads: usize,
    },
    Request {
        #[arg(long)]
        trusted: PathBuf,
        #[arg(long)]
        queries_npy: PathBuf,
        #[arg(long)]
        query_id: usize,
        #[arg(long, value_enum)]
        backend: Backend,
        #[arg(long, value_enum, default_value = "cold")]
        mode: Mode,
        #[arg(long)]
        output: PathBuf,
    },
    Reference {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        queries_npy: PathBuf,
        #[arg(long)]
        query_ids: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = default_scheme_threads())]
        threads: usize,
    },
    Prove {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = default_scheme_threads())]
        threads: usize,
        /// Pay local centroid preprocessing once before proving (useful for persistent servers).
        #[arg(long)]
        preprocess_centroids: bool,
    },
    Verify {
        #[arg(long)]
        trusted: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        vo: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = default_scheme_threads())]
        threads: usize,
    },
    Bench {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        queries_npy: PathBuf,
        #[arg(long)]
        query_ids: PathBuf,
        #[arg(long)]
        reference: Option<PathBuf>,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "fixed-raw-fp16,fixed-raw-fp32,matrix-scheme"
        )]
        backends: Vec<Backend>,
        #[arg(long, default_value_t = default_scheme_threads())]
        server_threads: usize,
        #[arg(long, value_delimiter = ',', default_values_t = [default_scheme_threads()])]
        client_threads: Vec<usize>,
        #[arg(long, default_value_t = 0)]
        warmups: usize,
        #[arg(long, default_value_t = 0)]
        rotation: usize,
        #[arg(long)]
        persist: bool,
        #[arg(long)]
        persist_ids: Option<PathBuf>,
    },
}
fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}
fn bounded(p: &Path, max: usize) -> Result<Vec<u8>> {
    if fs::metadata(p)?.len() > max as u64 {
        bail!("input exceeds bounded file limit");
    }
    let mut b = vec![];
    fs::File::open(p)?
        .take(max as u64 + 1)
        .read_to_end(&mut b)?;
    if b.len() > max {
        bail!("input grew beyond bounded file limit");
    }
    Ok(b)
}
fn new_write(p: &Path, b: &[u8]) -> Result<()> {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create_new(true).write(true).open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
fn json<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    new_write(p, &serde_json::to_vec_pretty(v)?)
}
fn load_json<T: serde::de::DeserializeOwned>(p: &Path, max: usize) -> Result<T> {
    Ok(serde_json::from_slice(&bounded(p, max)?)?)
}
fn trusted(p: &Path) -> Result<TrustedSchemeSnapshotV3> {
    let t = load_json(p, 1 << 16)?;
    validate_trusted_scheme_snapshot_v3(&t)?;
    Ok(t)
}
fn frame<T: Serialize>(magic: &[u8; 8], schema: u16, s: &T) -> Result<Vec<u8>> {
    let payload = options().serialize(s)?;
    let mut b = magic.to_vec();
    b.extend(schema.to_le_bytes());
    b.extend((payload.len() as u64).to_le_bytes());
    b.extend(payload);
    Ok(b)
}
fn load_frame<T: serde::de::DeserializeOwned>(p: &Path, magic: &[u8; 8], schema: u16) -> Result<T> {
    crate::full_snapshot::load_legacy_offline_frame(p, magic, schema)
}
fn load_snapshot(p: &Path) -> Result<SchemeServerSnapshotV3> {
    Ok(initialize_scheme_server_snapshot_v3(load_frame(
        p,
        SNAPSHOT_MAGIC,
        SCHEME_AUTH_SCHEMA_V3,
    )?)?)
}
fn pool(n: usize) -> Result<rayon::ThreadPool> {
    let available = std::thread::available_parallelism()?.get();
    if n == 0 || n > available {
        bail!("thread count must be between 1 and {available} available logical CPUs");
    }
    Ok(rayon::ThreadPoolBuilder::new().num_threads(n).build()?)
}
fn query_request(
    t: &TrustedSchemeSnapshotV3,
    q: QueryV3,
    b: SchemeBackendV3,
    m: PublicModeV3,
) -> SchemeRequestV3 {
    SchemeRequestV3 {
        manifest_digest: t.expected_manifest_digest,
        query: q,
        backend: b,
        public_mode: m,
    }
}
fn load_queries(t: &TrustedSchemeSnapshotV3, p: &Path) -> Result<Vec<QueryV3>> {
    let m = t.signed.manifest.source();
    Ok(import_queries(
        p,
        m.dimension,
        m.query_tokens,
        m.params.clone(),
    )?)
}
fn ids(p: &Path, n: usize) -> Result<Vec<usize>> {
    let ids: Vec<usize> = load_json(p, 1 << 20)?;
    if ids.is_empty()
        || ids.iter().any(|&id| id >= n)
        || ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != ids.len()
    {
        bail!("invalid query IDs");
    }
    Ok(ids)
}
fn peak_memory() -> Result<String> {
    Ok(fs::read_to_string("/proc/self/status")?
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .unwrap_or("unavailable")
        .into())
}
fn measure_ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
fn initialize_generators(t: &TrustedSchemeSnapshotV3) -> Result<f64> {
    let start = Instant::now();
    let m = &t.signed.manifest;
    let d = usize::from(m.source().dimension);
    for n in [
        usize::from(m.document_rows) * d,
        m.source().coarse_count as usize * d,
        m.source().fine_count as usize * d,
    ] {
        prepare_projection_generators_v1(n)?;
    }
    Ok(measure_ms(start))
}
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if !IS_COMPACT {
        let detected = match &cli.command {
            Command::Prepare { .. } => {
                cli.numeric_profile.unwrap_or(NumericProfileArg::Compact)
                    == NumericProfileArg::Compact
            }
            Command::Keygen { .. } => false,
            Command::AuditComponents { snapshot, .. }
            | Command::Validate { snapshot, .. }
            | Command::Reference { snapshot, .. }
            | Command::Prove { snapshot, .. }
            | Command::Bench { snapshot, .. } => {
                let mut magic = [0u8; 8];
                fs::File::open(snapshot)?.read_exact(&mut magic)?;
                &magic == b"G3CMPSNP"
            }
            Command::Request { trusted, .. }
            | Command::Verify { trusted, .. }
            | Command::AttackCheck { trusted, .. } => {
                let value: serde_json::Value = load_json(trusted, 1 << 16)?;
                {
                    let schema = value["signed"]["manifest"]["authentication_schema"].as_u64();
                    if matches!(schema, Some(2..=7)) {
                        bail!(
                            "scheme schema 2-7 snapshots use a retired authentication layout; rerun prepare from the raw snapshot"
                        );
                    }
                    schema
                        == Some(u64::from(
                            gem_auth_scheme_v3::compact::SCHEME_AUTH_SCHEMA_V3,
                        ))
                }
            }
        };
        if detected || cli.numeric_profile == Some(NumericProfileArg::Compact) {
            if detected && cli.numeric_profile == Some(NumericProfileArg::S16) {
                bail!("numeric profile differs from pinned snapshot");
            }
            return crate::compact_cli::run();
        }
    } else if cli.numeric_profile == Some(NumericProfileArg::S16) {
        bail!("numeric profile differs from compact snapshot");
    }
    match cli.command {
        Command::AuditComponents {
            snapshot,
            output,
            threads,
        } => {
            let s: PreparedSchemeSnapshotV3 =
                load_frame(&snapshot, SNAPSHOT_MAGIC, SCHEME_AUTH_SCHEMA_V3)?;
            let start = Instant::now();
            let audit = pool(threads)?.install(|| independent_components_v3(&s))?;
            json(
                &output,
                &serde_json::json!({"audit":audit,"elapsed_ms":measure_ms(start),"peak_memory":peak_memory()?}),
            )?;
        }
        Command::AttackCheck {
            trusted: t,
            request: r,
            vo,
            output,
            threads,
        } => {
            let t = trusted(&t)?;
            let r: SchemeRequestV3 = load_json(&r, 1 << 20)?;
            validate_scheme_request_v3(&t, &r)?;
            let p = pool(threads)?;
            let b = bounded(&vo, MAX_VO_BYTES)?;
            let attacks = p.install(|| attack_scheme_retrieval_v3(&t, &r, &b))?;
            json(
                &output,
                &serde_json::json!({"query_id":r.query.query_id,"backend":r.backend,"public_mode":r.public_mode,"passed":true,"attacks":attacks}),
            )?;
        }
        Command::Keygen { output_dir } => {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            fs::create_dir(&output_dir)?;
            fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))?;
            let key = SigningKey::generate(&mut OsRng);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(output_dir.join("owner.key"))?;
            f.write_all(&key.to_bytes())?;
            f.sync_all()?;
            json(
                &output_dir.join("owner-public.json"),
                &key.verifying_key().to_bytes(),
            )?;
        }
        Command::Prepare {
            raw_snapshot,
            owner_key,
            output_dir,
            threads,
        } => {
            if output_dir.exists() {
                bail!("refusing to overwrite snapshot output");
            }
            let p = pool(threads)?;
            let raw: PreparedRawSnapshotV3 =
                load_frame(&raw_snapshot, b"G3SNAP!!", gem_auth_v3::AUTH_SCHEMA_V3)?;
            let key = SigningKey::from_bytes(
                &bounded(&owner_key, 32)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid key length"))?,
            );
            let (s, timings) = p.install(|| prepare_scheme_snapshot_v3(raw, &key))?;
            fs::create_dir(&output_dir)?;
            let server = output_dir.join("server");
            let client = output_dir.join("client");
            fs::create_dir(&server)?;
            fs::create_dir(&client)?;
            let start = Instant::now();
            let bytes = frame(SNAPSHOT_MAGIC, SCHEME_AUTH_SCHEMA_V3, &s)?;
            let snapshot_bytes = bytes.len();
            new_write(&server.join("snapshot.scheme3"), &bytes)?;
            drop(bytes);
            new_write(
                &server.join("component-hashes.bin"),
                &options().serialize(&s.component_hashes)?,
            )?;
            new_write(
                &server.join("document-mht.bin"),
                &options().serialize(&s.tree)?,
            )?;
            new_write(
                &server.join("raw-component-hashes.bin"),
                &options().serialize(&s.raw_component_hashes)?,
            )?;
            new_write(
                &server.join("raw-document-mht.bin"),
                &options().serialize(&s.raw_tree)?,
            )?;
            new_write(
                &server.join("document-commitments.bin"),
                &options().serialize(&s.commitments)?,
            )?;
            let persistence_ms = measure_ms(start);
            let start = Instant::now();
            let reloaded: PreparedSchemeSnapshotV3 = load_frame(
                &server.join("snapshot.scheme3"),
                SNAPSHOT_MAGIC,
                SCHEME_AUTH_SCHEMA_V3,
            )?;
            p.install(|| validate_scheme_snapshot_v3(&reloaded))?;
            let reload_deep_validation_ms = measure_ms(start);
            // Provision client trust only after source conversion and all commitments
            // were deeply checked on the persisted/reloaded owner snapshot.
            let publishing = Instant::now();
            json(&client.join("trusted.json"), &reloaded.trusted)?;
            let persistence_ms = persistence_ms + measure_ms(publishing);
            json(
                &output_dir.join("preparation.json"),
                &serde_json::json!({"raw_snapshot":raw_snapshot,"raw_snapshot_sha256":hex::encode(sha256_file(&raw_snapshot)?),"source_manifest":s.trusted.signed.manifest.source(),"manifest_digest":hex::encode(s.trusted.expected_manifest_digest),"timings":timings,"snapshot_bytes":snapshot_bytes,"persistence_ms":persistence_ms,"reload_deep_validation_ms":reload_deep_validation_ms,"client_published_after_deep_validation":true,"peak_memory":peak_memory()?,"threads":threads,"reloaded_commitments_rebuilt":true}),
            )?;
            new_write(
                &output_dir.join("SNAPSHOT_COMPLETE"),
                format!(
                    "schema {} prepared and deeply revalidated\n",
                    SCHEME_AUTH_SCHEMA_V3
                )
                .as_bytes(),
            )?;
        }
        Command::Validate {
            snapshot,
            output,
            threads,
        } => {
            let s: PreparedSchemeSnapshotV3 =
                load_frame(&snapshot, SNAPSHOT_MAGIC, SCHEME_AUTH_SCHEMA_V3)?;
            let start = Instant::now();
            pool(threads)?.install(|| validate_scheme_snapshot_v3(&s))?;
            json(
                &output,
                &serde_json::json!({"passed":true,"deep_commitment_rebuild":true,"manifest":hex::encode(s.trusted.expected_manifest_digest),"elapsed_ms":measure_ms(start),"peak_memory":peak_memory()?}),
            )?;
        }
        Command::Request {
            trusted: t,
            queries_npy,
            query_id,
            backend,
            mode,
            output,
        } => {
            let t = trusted(&t)?;
            let qs = load_queries(&t, &queries_npy)?;
            let q = qs.get(query_id).context("invalid query ID")?.clone();
            json(&output, &query_request(&t, q, backend.into(), mode.into()))?;
        }
        Command::Reference {
            snapshot,
            queries_npy,
            query_ids,
            output_dir,
            threads,
        } => {
            fs::create_dir(&output_dir)?;
            let p = pool(threads)?;
            let s: PreparedSchemeSnapshotV3 =
                load_frame(&snapshot, SNAPSHOT_MAGIC, SCHEME_AUTH_SCHEMA_V3)?;
            validate_trusted_scheme_snapshot_v3(&s.trusted)?;
            let queries = load_queries(&s.trusted, &queries_npy)?;
            let ids = ids(&query_ids, queries.len())?;
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(output_dir.join("reference.jsonl"))?;
            let start = Instant::now();
            for (position, id) in ids.iter().enumerate() {
                let row = p.install(|| independent_fixed_reference_v3(&s, &queries[*id]))?;
                writeln!(f, "{}", serde_json::to_string(&row)?)?;
                f.flush()?;
                if position % 20 == 0 {
                    println!("reference {}/{} query={}", position + 1, ids.len(), id);
                }
            }
            f.sync_all()?;
            json(
                &output_dir.join("summary.json"),
                &serde_json::json!({"queries":ids.len(),"independent_numeric_replay_maxsim":true,"elapsed_ms":measure_ms(start),"peak_memory":peak_memory()?}),
            )?;
            new_write(
                &output_dir.join("RUN_COMPLETE"),
                b"independent reference complete\n",
            )?;
        }
        Command::Prove {
            snapshot,
            request: r,
            output,
            threads,
            preprocess_centroids,
        } => {
            let p = pool(threads)?;
            let s = p.install(|| load_snapshot(&snapshot))?;
            let r: SchemeRequestV3 = load_json(&r, 1 << 20)?;
            let centroid_preparation_ms =
                if preprocess_centroids && r.backend == SchemeBackendV3::MatrixScheme {
                    p.install(|| prepare_scheme_server_proofs_v3(&s))?
                } else {
                    0.
                };
            let (vo, e, mut timings) =
                p.install(|| execute_scheme_retrieval_measured_v3(&s, &r))?;
            let start = Instant::now();
            let (bytes, parts) = encode_scheme_vo_v3(&vo)?;
            let encoding_ms = measure_ms(start);
            timings.phases.insert("encoding".into(), encoding_ms);
            timings.total_ms += encoding_ms;
            new_write(&output, &bytes)?;
            json(
                &output.with_extension("server.json"),
                &serde_json::json!({"centroid_preparation_ms":centroid_preparation_ms,"execution":e,"results":vo.results,"timings":timings,"bytes":parts,"vo_sha256":hex::encode(sha256_bytes(&bytes)),"vo_sha256_kind":VO_SHA256_KIND,"vo_domain_digest":hex::encode(hash_bytes(b"gem.scheme.vo.file",&bytes))}),
            )?;
        }
        Command::Verify {
            trusted: t,
            request: r,
            vo,
            output,
            threads,
        } => {
            let t = trusted(&t)?;
            let r: SchemeRequestV3 = load_json(&r, 1 << 20)?;
            validate_scheme_request_v3(&t, &r)?;
            let p = pool(threads)?;
            let start = Instant::now();
            let generator_ms = if r.backend == SchemeBackendV3::MatrixScheme {
                p.install(|| initialize_generators(&t))?
            } else {
                0.
            };
            let setup_ms = measure_ms(start);
            let bytes = bounded(&vo, MAX_VO_BYTES)?;
            let verified = p.install(|| verify_scheme_retrieval_v3(&t, &r, &bytes))?;
            json(
                &output,
                &serde_json::json!({"execution":verified.execution,"results":verified.results,"timings":verified.timings,"generator_initialization_ms":generator_ms,"setup_ms":setup_ms,"first_query_total_ms":setup_ms+verified.timings.total_ms,"client_threads":threads,"peak_memory":peak_memory()?}),
            )?;
        }
        Command::Bench {
            snapshot,
            queries_npy,
            query_ids,
            reference,
            output_dir,
            backends,
            server_threads,
            client_threads,
            warmups,
            rotation,
            persist,
            persist_ids,
        } => {
            bench(
                &snapshot,
                &queries_npy,
                &query_ids,
                reference.as_deref(),
                &output_dir,
                &backends,
                server_threads,
                &client_threads,
                warmups,
                rotation,
                persist,
                persist_ids.as_deref(),
            )?;
        }
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
struct BenchmarkTrace {
    query_id: usize,
    execution: FixedExecutionV3,
    results: Vec<FixedNodeDistanceV3>,
    candidate_tokens: usize,
}
#[allow(clippy::too_many_arguments)]
fn bench(
    snapshot: &Path,
    query_file: &Path,
    id_file: &Path,
    reference: Option<&Path>,
    out: &Path,
    backends: &[Backend],
    server_threads: usize,
    client_threads: &[usize],
    warmups: usize,
    rotation: usize,
    persist: bool,
    persist_ids: Option<&Path>,
) -> Result<()> {
    fs::create_dir(out)?;
    let initialize = Instant::now();
    let server = pool(server_threads)?;
    let s = server.install(|| load_snapshot(snapshot))?;
    let queries = load_queries(&s.trusted, query_file)?;
    let persist_set = persist_ids
        .map(|p| ids(p, queries.len()))
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let ids = ids(id_file, queries.len())?;
    let reference = reference
        .map(|p| -> Result<BTreeMap<u64, FixedReferenceRecordV3>> {
            let mut rows = BTreeMap::new();
            for line in BufReader::new(fs::File::open(p)?).lines() {
                let row: FixedReferenceRecordV3 = serde_json::from_str(&line?)?;
                if rows.insert(row.query_id, row).is_some() {
                    bail!("duplicate reference query");
                }
            }
            Ok(rows)
        })
        .transpose()?;
    if reference
        .as_ref()
        .is_some_and(|r| ids.iter().any(|id| !r.contains_key(&(*id as u64))))
    {
        bail!("incomplete independent reference");
    }
    let clients = client_threads
        .iter()
        .map(|&n| Ok((n, pool(n)?)))
        .collect::<Result<Vec<_>>>()?;
    let generator_ms = if backends
        .iter()
        .copied()
        .any(|b| SchemeBackendV3::from(b) == SchemeBackendV3::MatrixScheme)
    {
        server.install(|| initialize_generators(&s.trusted))?
    } else {
        0.
    };
    let centroid_preparation_ms = if backends
        .iter()
        .copied()
        .any(|b| SchemeBackendV3::from(b) == SchemeBackendV3::MatrixScheme)
    {
        server.install(|| prepare_scheme_server_proofs_v3(&s))?
    } else {
        0.
    };
    let mut configs = backends
        .iter()
        .map(|&b| (SchemeBackendV3::from(b), PublicModeV3::Cold))
        .collect::<Vec<_>>();
    if configs.is_empty() {
        bail!("empty benchmark backends");
    }
    let len = configs.len();
    configs.rotate_left(rotation % len);
    let initialization_ms = measure_ms(initialize);
    for &(backend, mode) in &configs {
        for i in 0..warmups {
            let r = query_request(
                &s.trusted,
                queries[ids[i % ids.len()]].clone(),
                backend,
                mode,
            );
            let vo = server.install(|| execute_scheme_retrieval_v3(&s, &r))?;
            let (bytes, _) = encode_scheme_vo_v3(&vo)?;
            for (_, p) in &clients {
                p.install(|| verify_scheme_retrieval_v3(&s.trusted, &r, &bytes))?;
            }
        }
    }
    let mut rows = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("rows.jsonl"))?;
    let mut traces = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("traces.jsonl"))?;
    let mut count = 0;
    for (position, &id) in ids.iter().enumerate() {
        let mut expected = None;
        if let Some(reference) = &reference {
            let rr = &reference[&(id as u64)];
            let q = FixedQueryV3::new(queries[id].clone())?;
            let coarse = server.install(|| fixed_similarity_table_v3(&q, &s.coarse_fixed))?;
            let fine = if rr.execution.trace.queue_entries.is_empty() {
                vec![]
            } else {
                server.install(|| fixed_similarity_table_v3(&q, &s.fine_fixed))?
            };
            let h = |v: &Vec<Similarity>| -> Result<_> {
                Ok(hash_bytes(
                    b"gem.fixed.reference.value.v1",
                    &bincode::serialize(v)?,
                ))
            };
            if h(&coarse)? != rr.coarse_digest || h(&fine)? != rr.fine_digest {
                bail!("independent full centroid tables mismatch query {id}");
            }
            let mut scores = Vec::new();
            let mut hashes = Vec::new();
            for &doc in &rr.execution.component_usage.raw {
                let n = usize::from(s.metadata[doc as usize].token_count);
                let matrix = server
                    .install(|| fixed_similarity_table_v3(&q, &s.fixed_documents[doc as usize]))?;
                hashes.push((doc, h(&matrix)?));
                scores.push(gem_search::ExecutionNodeV3 {
                    doc_id: doc,
                    distance: maxsim_fixed_matrix_v3(
                        usize::from(q.source.token_count),
                        n,
                        &matrix,
                    )?,
                });
            }
            if scores != rr.all_candidate_scores || hashes != rr.candidate_matrix_digests {
                bail!("independent all candidate matrix/MaxSim mismatch query {id}");
            }
        }
        let mut ordered = configs.clone();
        let len = ordered.len();
        ordered.rotate_left(position % len);
        for &(backend, mode) in &ordered {
            let r = query_request(&s.trusted, queries[id].clone(), backend, mode);
            let start = Instant::now();
            let (vo, execution, mut st) =
                server.install(|| execute_scheme_retrieval_measured_v3(&s, &r))?;
            let enc = Instant::now();
            let (bytes, parts) = encode_scheme_vo_v3(&vo)?;
            let enc_ms = measure_ms(enc);
            st.phases.insert("encoding".into(), enc_ms);
            st.total_ms += enc_ms;
            let server_wall_ms = measure_ms(start);
            if let Some(ref prev) = expected {
                if prev != &(execution.clone(), vo.results.clone()) {
                    bail!("cross-backend trace/result mismatch query {id}");
                }
            } else {
                expected = Some((execution.clone(), vo.results.clone()));
            }
            if let Some(reference) = &reference {
                let rr = &reference[&(id as u64)];
                if rr.execution != execution || rr.results != vo.results {
                    bail!("independent reference mismatch query {id}");
                }
                if let Some(y) = &vo.reranking {
                    let boundaries: Vec<_> = vo
                        .documents
                        .iter()
                        .filter(|d| d.vector.is_revealed())
                        .map(|d| &d.metadata)
                        .collect();
                    let total_tokens = boundaries
                        .iter()
                        .map(|b| usize::from(b.token_count))
                        .sum::<usize>();
                    let mut offset = 0usize;
                    let mut candidate_digests = Vec::new();
                    for boundary in &boundaries {
                        let n = usize::from(boundary.token_count);
                        let mut matrix = Vec::new();
                        for j in 0..usize::from(r.query.token_count) {
                            matrix.extend_from_slice(
                                &y.similarities
                                    [j * total_tokens + offset..j * total_tokens + offset + n],
                            );
                        }
                        candidate_digests.push((
                            boundary.doc_id,
                            hash_bytes(
                                b"gem.fixed.reference.value.v1",
                                &bincode::serialize(&matrix)?,
                            ),
                        ));
                        offset += n;
                    }
                    if candidate_digests != rr.candidate_matrix_digests {
                        bail!("independent complete Y mismatch query {id}");
                    }
                }
                if let Some(metrics) = &vo.metrics {
                    let h = |v: &Vec<Similarity>| -> Result<_> {
                        Ok(hash_bytes(
                            b"gem.fixed.reference.value.v1",
                            &bincode::serialize(v)?,
                        ))
                    };
                    if h(&metrics.coarse)? != rr.coarse_digest
                        || h(&metrics.fine)? != rr.fine_digest
                    {
                        bail!("independent centroid tables mismatch");
                    }
                }
            }
            let mut clients_order = clients.iter().collect::<Vec<_>>();
            // Reporting only: these digests never enter the VO or proof transcript.
            // Compute once for the same serialized VO used by every client pool.
            let vo_sha256 = hex::encode(sha256_bytes(&bytes));
            let vo_domain_digest = hex::encode(hash_bytes(b"gem.scheme.vo.file", &bytes));
            if (position + rotation) % 2 == 1 {
                clients_order.reverse();
            }
            for (threads, p) in clients_order {
                let start = Instant::now();
                let verified = p.install(|| verify_scheme_retrieval_v3(&s.trusted, &r, &bytes))?;
                let wall_ms = measure_ms(start);
                if verified.execution != execution || verified.results != vo.results {
                    bail!("serialized client mismatch query {id}");
                }
                writeln!(
                    rows,
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"query_id":id,"backend":backend,"public_mode":mode,"server_threads":server_threads,"client_threads":threads,"server":st,"server_wall_ms":server_wall_ms,"client_wall_ms":wall_ms,"client":verified.timings,"bytes":parts,"accepted":true,"vo_sha256":vo_sha256,"vo_sha256_kind":VO_SHA256_KIND,"vo_domain_digest":vo_domain_digest})
                    )?
                )?;
                count += 1;
            }
            if persist || persist_set.contains(&id) {
                let name = format!(
                    "q{id}-{}-{}",
                    serde_json::to_value(backend)?.as_str().unwrap(),
                    serde_json::to_value(mode)?.as_str().unwrap()
                );
                json(&out.join(format!("{name}.request.json")), &r)?;
                new_write(&out.join(format!("{name}.vo")), &bytes)?;
                json(
                    &out.join(format!("{name}.expected.json")),
                    &serde_json::json!({"execution":execution,"results":vo.results}),
                )?;
            }
        }
        let (execution, results) = expected.context("missing execution")?;
        let candidate_tokens = execution
            .component_usage
            .raw
            .iter()
            .map(|&id| usize::from(s.metadata[id as usize].token_count))
            .sum();
        writeln!(
            traces,
            "{}",
            serde_json::to_string(&BenchmarkTrace {
                query_id: id,
                execution,
                results,
                candidate_tokens
            })?
        )?;
        rows.flush()?;
        traces.flush()?;
        println!(
            "verified {}/{} query={} validations={}",
            position + 1,
            ids.len(),
            id,
            count
        );
    }
    rows.sync_all()?;
    traces.sync_all()?;
    json(
        &out.join("summary.json"),
        &serde_json::json!({"queries":ids.len(),"server_threads":server_threads,"serialized_verifications":count,"reference_checked":reference.is_some(),"generator_initialization_ms":generator_ms,"centroid_preparation_ms":centroid_preparation_ms,"initialization_ms":initialization_ms,"warmups_per_configuration":warmups,"rotation":rotation,"peak_memory":peak_memory()?}),
    )?;
    new_write(
        &out.join("RUN_COMPLETE"),
        b"actual serialized generation and independent verification complete\n",
    )?;
    Ok(())
}
