//! Independent file-based owner, server, and client commands.
use anyhow::{Context, Result, bail};
use bincode::Options;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use gem_auth_v3::*;
use gem_core::{INDEX_MAGIC_V3, SearchParamsV3, hash_bytes, sha256_file};
use gem_search::{
    NativeQueryResultV3, SearchIndexV3, execute_search_v3, import_compact_codes, import_queries,
};
use rand::{SeedableRng, rngs::OsRng, seq::SliceRandom};
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Parser)]
#[command(name = "gem-raw-auth-v3", version = "V3R3-auth2")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Wire {
    Fp16,
    Fp32,
}
#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Cold,
}
#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        output_dir: PathBuf,
    },
    Prepare {
        #[arg(long)]
        index: PathBuf,
        #[arg(long)]
        encoder_dir: PathBuf,
        #[arg(long)]
        code_dir: PathBuf,
        #[arg(long)]
        source_ids: PathBuf,
        #[arg(long)]
        provenance: PathBuf,
        #[arg(long)]
        owner_key: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 32)]
        query_tokens: u16,
        #[arg(long, default_value_t = 100)]
        k: u32,
        #[arg(long, default_value_t = 1024)]
        rerank_k: u32,
        #[arg(long, default_value_t = 1024)]
        ef_search: u32,
        #[arg(long, default_value_t = 4)]
        cluster_top_t: u32,
    },
    Request {
        #[arg(long)]
        trusted: PathBuf,
        #[arg(long)]
        queries_npy: PathBuf,
        #[arg(long)]
        query_id: usize,
        #[arg(long, value_enum)]
        wire: Wire,
        #[arg(long, value_enum, default_value = "cold")]
        mode: Mode,
        #[arg(long)]
        output: PathBuf,
    },
    Prove {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 8)]
        threads: usize,
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
        #[arg(long, default_value_t = 1)]
        threads: usize,
    },
    Validate {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Bench {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        queries_npy: PathBuf,
        #[arg(long)]
        query_ids: PathBuf,
        #[arg(long)]
        frozen_native: Option<PathBuf>,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, value_delimiter = ',', default_value = "1,8")]
        client_threads: Vec<usize>,
        #[arg(long, default_value_t = 0)]
        warmups: usize,
        #[arg(long, default_value_t = 20261005)]
        seed: u64,
    },
}
fn bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let size = fs::metadata(path)?.len();
    if size > max as u64 {
        bail!("input exceeds bounded file limit")
    };
    let mut f = fs::File::open(path)?;
    let mut b = Vec::new();
    use std::io::Read;
    std::io::Read::by_ref(&mut f)
        .take(max as u64 + 1)
        .read_to_end(&mut b)?;
    if b.len() > max {
        bail!("input grew beyond bounded limit")
    }
    Ok(b)
}
fn new_write(path: &Path, b: &[u8]) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?
    }
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
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
fn trusted(p: &Path) -> Result<TrustedSnapshotV3> {
    let t: TrustedSnapshotV3 = load_json(p, 1 << 16)?;
    if t.signed.manifest.authentication_schema == 1 {
        bail!(
            "raw schema 1 uses retired document metadata; rerun raw prepare from the index and input data"
        );
    }
    validate_trusted_snapshot_v3(&t)?;
    Ok(t)
}
fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}
fn save_snapshot(s: &PreparedRawSnapshotV3) -> Result<Vec<u8>> {
    let payload = options().serialize(s)?;
    let mut b = b"G3SNAP!!".to_vec();
    b.extend(AUTH_SCHEMA_V3.to_le_bytes());
    b.extend((payload.len() as u64).to_le_bytes());
    b.extend(payload);
    Ok(b)
}
fn load_snapshot(p: &Path) -> Result<ServerSnapshotV3> {
    let s = crate::full_snapshot::load_legacy_offline_frame(p, b"G3SNAP!!", AUTH_SCHEMA_V3)?;
    Ok(initialize_server_snapshot_v3(s)?)
}
fn pool(n: usize) -> Result<rayon::ThreadPool> {
    if n == 0 || n > 56 {
        bail!("invalid physical thread count")
    };
    Ok(ThreadPoolBuilder::new().num_threads(n).build()?)
}
fn millis(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
fn request_for(
    t: &TrustedSnapshotV3,
    q: gem_core::QueryV3,
    w: RawWireV3,
    m: PublicModeV3,
) -> RawRequestV3 {
    RawRequestV3 {
        manifest_digest: t.expected_manifest_digest,
        query: q,
        raw_wire: w,
        public_mode: m,
    }
}
fn file_evidence(p: &Path) -> Result<serde_json::Value> {
    Ok(
        serde_json::json!({"path":p,"bytes":fs::metadata(p)?.len(),"sha256":hex::encode(sha256_file(p)?)}),
    )
}
pub fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { output_dir } => {
            fs::create_dir(&output_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&output_dir, fs::Permissions::from_mode(0o700))?;
            }
            let key = SigningKey::generate(&mut OsRng);
            let p = output_dir.join("owner.key");
            new_write(&p, &key.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
            }
            new_write(
                &output_dir.join("owner.public"),
                &key.verifying_key().to_bytes(),
            )?;
        }
        Command::Prepare {
            index,
            encoder_dir,
            code_dir,
            source_ids,
            provenance,
            owner_key,
            output_dir,
            query_tokens,
            k,
            rerank_k,
            ef_search,
            cluster_top_t,
        } => {
            if output_dir.exists() {
                bail!("refusing to overwrite snapshot output")
            };
            let started = Instant::now();
            let index_data: SearchIndexV3 =
                crate::full_snapshot::load_legacy_offline_frame(&index, &INDEX_MAGIC_V3, 2)?;
            let raw = crate::load_raw_corpus(
                &encoder_dir,
                &code_dir,
                index_data.dimension,
                index_data.max_doc_tokens,
            )?;
            let codes = import_compact_codes(
                &code_dir,
                &encoder_dir,
                index_data.fine_centroids.len() / usize::from(index_data.dimension),
                index_data.max_doc_tokens,
            )?;
            if codes
                != index_data
                    .documents
                    .iter()
                    .map(|d| d.compact_codes.clone())
                    .collect::<Vec<_>>()
            {
                bail!("index codes do not match authoritative input")
            }
            let source_id_limit = index_data
                .documents
                .len()
                .checked_mul(32)
                .and_then(|n| n.checked_add(2))
                .context("source-ID size overflow")?;
            let ids: Vec<u64> = load_json(&source_ids, source_id_limit)?;
            let keybytes: [u8; 32] = bounded(&owner_key, 32)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid owner key length"))?;
            let key = SigningKey::from_bytes(&keybytes);
            let input_ms = millis(started);
            let started = Instant::now();
            let (s, build_timings) = prepare_raw_snapshot_measured_v3(
                index_data,
                &raw,
                &ids,
                query_tokens,
                SearchParamsV3 {
                    k,
                    rerank_k,
                    cluster_top_t,
                    ef_search,
                },
                sha256_file(&provenance)?,
                &key,
            )?;
            let hashing_mht_ms = millis(started);
            let staging = output_dir.with_extension(format!("staging-{}", std::process::id()));
            fs::create_dir(&staging)?;
            let server = staging.join("server");
            let client = staging.join("client");
            fs::create_dir(&server)?;
            fs::create_dir(&client)?;
            new_write(&server.join("snapshot.auth3"), &save_snapshot(&s)?)?;
            new_write(
                &server.join("component-hashes.bin"),
                &options().serialize(&s.component_hashes)?,
            )?;
            new_write(
                &server.join("document-mht.bin"),
                &options().serialize(&s.tree)?,
            )?;
            json(&client.join("trusted.json"), &s.trusted)?;
            let start = Instant::now();
            let reloaded = load_snapshot(&server.join("snapshot.auth3"))?;
            let reload_validate_ms = millis(start);
            if reloaded.trusted != s.trusted {
                bail!("persisted snapshot differs")
            }
            let files = [
                server.join("snapshot.auth3"),
                server.join("component-hashes.bin"),
                server.join("document-mht.bin"),
                client.join("trusted.json"),
            ];
            let mut evidence = files
                .iter()
                .map(|p| file_evidence(p))
                .collect::<Result<Vec<_>>>()?;
            for item in &mut evidence {
                if let Some(path) = item["path"].as_str() {
                    item["path"] =
                        serde_json::json!(output_dir.join(Path::new(path).strip_prefix(&staging)?));
                }
            }
            json(
                &staging.join("prepare-validation.json"),
                &serde_json::json!({"validated":true,"input_ms":input_ms,"snapshot_build_ms":hashing_mht_ms,"snapshot_phases":build_timings,"reload_validate_ms":reload_validate_ms,"document_root":hex::encode(s.tree.root()?),"index_input":file_evidence(&index)?,"source_ids_input":file_evidence(&source_ids)?,"provenance":file_evidence(&provenance)?,"files":evidence,"ads_serialized_bytes":fs::metadata(&files[1])?.len()+fs::metadata(&files[2])?.len()}),
            )?;
            new_write(
                &staging.join("SNAPSHOT_COMPLETE"),
                b"validated round-trip and recorded file hashes\n",
            )?;
            fs::rename(&staging, &output_dir)?;
        }
        Command::Request {
            trusted: tp,
            queries_npy,
            query_id,
            wire,
            mode,
            output,
        } => {
            let t = trusted(&tp)?;
            let m = &t.signed.manifest;
            let qs = import_queries(queries_npy, m.dimension, m.query_tokens, m.params.clone())?;
            let q = qs.get(query_id).context("query ID out of range")?.clone();
            json(
                &output,
                &request_for(
                    &t,
                    q,
                    match wire {
                        Wire::Fp16 => RawWireV3::Fp16,
                        Wire::Fp32 => RawWireV3::Fp32,
                    },
                    match mode {
                        Mode::Cold => PublicModeV3::Cold,
                    },
                ),
            )?;
        }
        Command::Prove {
            snapshot,
            request,
            output,
            threads,
        } => {
            let audit = output.with_extension("audit.json");
            if output.exists() || audit.exists() {
                bail!("refusing to overwrite VO")
            };
            let start = Instant::now();
            let s = load_snapshot(&snapshot)?;
            let initialization_ms = millis(start);
            let r = load_json(&request, 1 << 20)?;
            let (v, execution, mut timings) =
                pool(threads)?.install(|| execute_raw_retrieval_measured_v3(&s, &r))?;
            let start = Instant::now();
            let (b, stats) = encode_raw_vo_v3(&v)?;
            timings.encoding_ms = millis(start);
            new_write(&output, &b)?;
            json(
                &audit,
                &serde_json::json!({"request_digest":hex::encode(request_digest_v3(&r)?),"execution":execution,"claimed_results":v.results,"server":timings,"initialization_ms":initialization_ms,"bytes":stats,"vo":file_evidence(&output)?}),
            )?;
            println!("{}", serde_json::to_string(&stats)?);
        }
        Command::Verify {
            trusted: tp,
            request,
            vo,
            output,
            threads,
        } => {
            if output.exists() {
                bail!("refusing to overwrite verifier output")
            };
            let t = trusted(&tp)?;
            let r = load_json(&request, 1 << 20)?;
            let b = bounded(&vo, MAX_VO_BYTES)?;
            let v = pool(threads)?.install(|| verify_raw_retrieval_v3(&t, &r, &b))?;
            json(&output, &v)?;
            println!(
                "verified=true query_id={} vo_bytes={}",
                r.query.query_id,
                b.len()
            );
        }
        Command::Validate { snapshot, output } => {
            if output.exists() {
                bail!("refusing to overwrite validation")
            };
            let s = load_snapshot(&snapshot)?;
            json(
                &output,
                &serde_json::json!({"validated":true,"root":hex::encode(s.tree.root()?),"snapshot":file_evidence(&snapshot)?,"index":s.index.validate_policy()?}),
            )?;
        }
        Command::Bench {
            snapshot,
            queries_npy,
            query_ids,
            frozen_native,
            output_dir,
            client_threads,
            warmups,
            seed,
        } => bench(
            &snapshot,
            &queries_npy,
            &query_ids,
            frozen_native.as_deref(),
            &output_dir,
            &client_threads,
            warmups,
            seed,
        )?,
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Ids {
    Bare(Vec<usize>),
    Object { query_ids: Vec<usize> },
}
#[derive(Deserialize)]
struct Frozen {
    rows: Vec<FrozenRow>,
}
#[derive(Deserialize)]
struct FrozenRow {
    query_id: u64,
    native: NativeQueryResultV3,
}
#[allow(clippy::too_many_arguments)]
fn bench(
    snapshot: &Path,
    queries_path: &Path,
    ids_path: &Path,
    frozen_path: Option<&Path>,
    out: &Path,
    threads: &[usize],
    warmups: usize,
    seed: u64,
) -> Result<()> {
    fs::create_dir(out)?;
    let initialized = Instant::now();
    let s = load_snapshot(snapshot)?;
    let m = &s.trusted.signed.manifest;
    let queries = import_queries(queries_path, m.dimension, m.query_tokens, m.params.clone())?;
    let ids = match load_json(ids_path, 1 << 20)? {
        Ids::Bare(v) | Ids::Object { query_ids: v } => v,
    };
    if ids.is_empty()
        || ids.iter().any(|&id| id >= queries.len())
        || ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != ids.len()
    {
        bail!("invalid query IDs")
    }
    let frozen: BTreeMap<u64, NativeQueryResultV3> = frozen_path
        .map(|p| -> Result<_> {
            let f: Frozen = load_json(p, MAX_VO_BYTES)?;
            Ok(f.rows.into_iter().map(|r| (r.query_id, r.native)).collect())
        })
        .transpose()?
        .unwrap_or_default();
    if frozen_path.is_some() && ids.iter().any(|&id| !frozen.contains_key(&(id as u64))) {
        bail!("incomplete frozen Native reference")
    }
    let server = pool(8)?;
    let clients = threads
        .iter()
        .map(|&n| Ok((n, pool(n)?)))
        .collect::<Result<Vec<_>>>()?;
    let initialization_ms = millis(initialized);
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("rows.jsonl"))?;
    let mut count = 0usize;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut configs = vec![
        (RawWireV3::Fp16, PublicModeV3::Cold),
        (RawWireV3::Fp32, PublicModeV3::Cold),
    ];
    configs.shuffle(&mut rng);
    // Warm up each full configuration using real serialization and verification.
    for &(w, mode) in &configs {
        for i in 0..warmups {
            let r = request_for(&s.trusted, queries[ids[i % ids.len()]].clone(), w, mode);
            let vo = server.install(|| execute_raw_retrieval_v3(&s, &r))?;
            let (b, _) = encode_raw_vo_v3(&vo)?;
            for (_, p) in &clients {
                p.install(|| verify_raw_retrieval_v3(&s.trusted, &r, &b))?;
            }
        }
    }
    for i in 0..warmups {
        let q = &queries[ids[i % ids.len()]];
        server.install(|| -> gem_core::Result<_> {
            let e = execute_search_v3(&s.index, (&s.index).into(), q)?;
            let ids = e
                .trace
                .candidates
                .iter()
                .map(|r| r.doc_id)
                .collect::<Vec<_>>();
            s.rerank_candidates_v3(q, &ids)
        })?;
    }
    let mut max_vis = (0, 0usize);
    let mut max_prune = (0, 0usize);
    let mut max_tokens = (0, 0usize);
    let mut audits = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("audit-traces.jsonl"))?;
    for (position, &id) in ids.iter().enumerate() {
        let q = &queries[id];
        let mut observed: Option<NativeQueryResultV3> = None;
        let mut order = configs.iter().copied().map(Some).collect::<Vec<_>>();
        order.push(None);
        order.shuffle(&mut rng);
        for configuration in order {
            let Some((w, mode)) = configuration else {
                let start = Instant::now();
                let native = server.install(|| -> gem_core::Result<_> {
                    let execution = execute_search_v3(&s.index, (&s.index).into(), q)?;
                    let candidates = execution
                        .trace
                        .candidates
                        .iter()
                        .map(|r| r.doc_id)
                        .collect::<Vec<_>>();
                    let exact = s.rerank_candidates_v3(q, &candidates)?;
                    Ok(NativeQueryResultV3 {
                        trace: execution.trace,
                        exact,
                    })
                })?;
                let native_ms = millis(start);
                if let Some(previous) = &observed
                    && previous != &native
                {
                    bail!("Native/authentication mismatch query {}", id)
                }
                let trace_digest = hex::encode(hash_bytes(
                    b"gem.native.v3.query",
                    &serde_json::to_vec(&native)?,
                ));
                writeln!(
                    f,
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"query_id":id,"configuration":"native","server_threads":8,"compute_ms":native_ms,"trace_digest":trace_digest})
                    )?
                )?;
                observed = Some(native);
                continue;
            };
            let r = request_for(&s.trusted, q.clone(), w, mode);
            let server_start = Instant::now();
            let (vo, execution, mut st) =
                server.install(|| execute_raw_retrieval_measured_v3(&s, &r))?;
            let start = Instant::now();
            let (b, bytes) = encode_raw_vo_v3(&vo)?;
            st.encoding_ms = millis(start);
            let server_wall_ms = millis(server_start);
            let native = NativeQueryResultV3 {
                trace: execution.trace.clone(),
                exact: gem_search::ExactRerankResultV3 {
                    results: vo.results.clone(),
                },
            };
            if let Some(previous) = &observed
                && previous != &native
            {
                bail!("cross-configuration result/trace mismatch")
            }
            let trace_digest = hex::encode(hash_bytes(
                b"gem.native.v3.query",
                &serde_json::to_vec(&native)?,
            ));
            observed = Some(native.clone());
            let mut client_order = clients.iter().collect::<Vec<_>>();
            client_order.shuffle(&mut rng);
            for (n, client) in client_order {
                let start = Instant::now();
                let verified = client.install(|| verify_raw_retrieval_v3(&s.trusted, &r, &b))?;
                let client_wall_ms = millis(start);
                if verified.result != native || verified.execution != execution {
                    bail!("full verifier parity mismatch query {}", id)
                }
                let u = &verified.execution.component_usage;
                let candidate_tokens = u
                    .raw
                    .iter()
                    .map(|&id| usize::from(s.metadata[id as usize].token_count))
                    .sum::<usize>();
                if u.membership.len() > max_vis.1 {
                    max_vis = (id, u.membership.len())
                }
                if native.trace.cluster_pruned.len() > max_prune.1 {
                    max_prune = (id, native.trace.cluster_pruned.len())
                }
                if candidate_tokens > max_tokens.1 {
                    max_tokens = (id, candidate_tokens)
                }
                writeln!(
                    f,
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({"query_id":id,"wire":w,"public_mode":mode,"client_threads":n,"server_threads":8,"root":hex::encode(m.document_root),"trace_digest":trace_digest,"server":st,"server_wall_ms":server_wall_ms,"client":verified.timings,"client_wall_ms":client_wall_ms,"bytes":bytes,"visited":u.membership.len(),"quantized":u.codes.len(),"expanded":u.adjacency.len(),"candidates":u.raw.len(),"candidate_tokens":candidate_tokens,"pruned_events":native.trace.cluster_pruned.len(),"early_stops":native.trace.early_stops.len(),"accepted":true})
                    )?
                )?;
                count += 1;
            }
        }
        let result = observed.context("missing reference result")?;
        if frozen_path.is_some() && frozen.get(&q.query_id) != Some(&result) {
            bail!("frozen Native mismatch query {}", id)
        }
        writeln!(
            audits,
            "{}",
            serde_json::to_string(&serde_json::json!({"query_id":id,"native":result}))?
        )?;
        f.flush()?;
        audits.flush()?;
        if (position + 1) % 25 == 0 {
            println!(
                "completed_queries={} total_queries={} verified_rows={}",
                position + 1,
                ids.len(),
                count
            );
        }
    }
    audits.sync_all()?;
    f.sync_all()?;
    json(
        &out.join("validation.json"),
        &serde_json::json!({"passed":true,"queries":ids.len(),"verified_rows":count,"frozen_native_compared":frozen_path.is_some(),"client_threads":threads,"server_threads":8,"warmups_per_configuration":warmups,"seed":seed,"initialization_ms":initialization_ms,"max_visited_query":max_vis,"max_pruning_query":max_prune,"max_candidate_tokens_query":max_tokens,"snapshot":file_evidence(snapshot)?,"query_ids":file_evidence(ids_path)?,"queries_input":file_evidence(queries_path)?,"records":file_evidence(&out.join("rows.jsonl"))?,"audit_traces":file_evidence(&out.join("audit-traces.jsonl"))?,"command":std::env::args().collect::<Vec<_>>() }),
    )?;
    new_write(
        &out.join("RUN_COMPLETE"),
        b"full serialized verification and parity passed\n",
    )?;
    Ok(())
}
