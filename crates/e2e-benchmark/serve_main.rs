use anyhow::{Context, Result, ensure};
use gem_auth_scheme_multi::compact as scheme;
use gem_core::{hash_serialized, sha256_file};
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use gem_lotte_auth_pilot::{Envelope, offline};
#[derive(Deserialize)]
struct Plan {
    policies: Vec<u8>,
    stages: Vec<usize>,
    warmups: usize,
    repeats: usize,
    ids: Vec<usize>,
    seed: u64,
    label: String,
}

fn policy_name(policy: u8) -> &'static str {
    match policy {
        0 => "raw",
        1 => "vida_per_token",
        2 => "vida_batched",
        5 => "block_fast",
        _ => unreachable!(),
    }
}

fn atomic_json(path: &Path, value: &Value) -> Result<()> {
    let tmp = path.with_extension("pending");
    let mut f = fs::File::create(&tmp)?;
    serde_json::to_writer(&mut f, value)?;
    writeln!(f)?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();

    if args.len() == 4 && args[1] == "check-fixture" {
        let report = scheme::check_full_fixture(Path::new(&args[2]), Path::new(&args[3]))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if args.len() == 4 && args[1] == "publish" {
        gem_lotte_auth_pilot::workspace_output(Path::new(&args[3]))?;
        return scheme::publish_visit_bundles(Path::new(&args[2]), Path::new(&args[3]));
    }
    ensure!(args.len() == 4, "usage: first-visit DATA PLAN RUN");
    gem_lotte_auth_pilot::workspace_output(Path::new(&args[3]))?;
    let root = Path::new(&args[1]).canonicalize()?;
    let plan_path = PathBuf::from(&args[2]);
    let plan: Plan = serde_json::from_slice(&fs::read(&plan_path)?)?;
    let unique = plan.ids.iter().copied().collect::<BTreeSet<_>>();
    ensure!(unique.len() == plan.ids.len() && !unique.is_empty());
    ensure!(plan.policies == [0, 1, 2, 5] && (plan.stages == [0, 1, 2, 3] || plan.stages == [3]));
    let wireplan: Value = serde_json::from_slice(&fs::read(&plan_path)?)?;
    ensure!(
        wireplan["caches"] == json!(["first_visit"])
            && wireplan["digest_requests_per_measurement"] == 1
    );
    match plan.label.as_str() {
        "full" => ensure!(
            unique == (0..2931).collect::<BTreeSet<_>>() && plan.warmups == 2 && plan.repeats == 5
        ),
        "smoke" => ensure!(plan.ids == [0, 2857] && plan.warmups == 0 && plan.repeats == 1),
        "sample" => ensure!(plan.ids == [0] && plan.warmups == 0 && plan.repeats == 1),
        "prefix512" => ensure!(
            plan.ids.len() == 512 && plan.stages == [3] && plan.warmups == 0 && plan.repeats == 1
        ),
        _ => anyhow::bail!("unknown phase"),
    }
    let affinity = fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|s| s.strip_prefix("Cpus_allowed_list:"))
        .context("CPU affinity")?
        .trim()
        .to_owned();

    rayon::ThreadPoolBuilder::new().build_global()?;
    let input = root.join("inputs");
    let s: Envelope = offline::load_offline(&input.join("offline.compact"))?;
    ensure!(s.version == 1 && s.input_binding == sha256_file(input.join("input-bindings.json"))?);
    let trusted: scheme::TrustedSchemeSnapshotV3 =
        serde_json::from_slice(&fs::read(input.join("trusted.json"))?)?;
    let queries = gem_search::import_queries(
        input.join("queries.npy"),
        128,
        32,
        trusted.signed.manifest.source().params.clone(),
    )?;
    ensure!(
        unique.iter().all(|&id| id < queries.len())
            && queries.len() == s.corpus.queries
            && trusted.signed.manifest.source().document_count as usize == s.corpus.documents
    );
    if plan.label != "sample" {
        ensure!(
            s.corpus.documents == 2_428_854
                && queries.len() == 2931
                && s.corpus.tokens == 266_205_513
        );
        ensure!(
            hex::encode(trusted.expected_manifest_digest)
                == "07987e1d0ddd7a5176ec3befff58167f29aa9e114c20cfa4840f63e903baeaac"
                && queries[0].params == offline::params()
        );
    }
    let offsets = offline::u64s(&input.join("token-offsets.u64"))?;
    let refs_path = root.join("native-reference.jsonl");
    let mut refs = BTreeMap::new();
    for line in BufReader::new(fs::File::open(&refs_path)?).lines() {
        let reference: Value = serde_json::from_str(&line?)?;
        let id = reference["query_id"].as_u64().context("reference query")? as usize;
        ensure!(reference["snapshot"] == hex::encode(trusted.expected_manifest_digest));
        ensure!(
            id < queries.len()
                && queries[id].query_id == id as u64
                && reference["query_sha256"]
                    == hex::encode(hash_serialized(b"query", &queries[id])?)
        );
        ensure!(refs.insert(id, reference).is_none());
    }
    ensure!(unique.iter().all(|id| refs.contains_key(id)));
    let run = Path::new(&args[3]);
    let dest = run.join("records");
    fs::create_dir_all(&dest)?;
    let identity = json!({"binary":hex::encode(sha256_file(env::current_exe()?)?),"plan":hex::encode(sha256_file(&plan_path)?),
        "sample":plan.ids.len(),"source":hex::encode(trusted.expected_manifest_digest),"native_reference":hex::encode(sha256_file(&refs_path)?),
        "threads":rayon::current_num_threads(),"cpu_affinity":affinity,"network_mbps":300,"rtt_ms":0,"owner_documents":s.corpus.documents,"client_trust":"fresh_tls_signed_manifests",
        "certificate_sha256":hex::encode(sha256_file(run.join("client-runtime/source.pem"))?),
        "owner_keys_sha256":hex::encode(sha256_file(run.join("client-runtime/anchors.bin"))?)});
    let id_file = dest.join("identity.json");
    if id_file.exists() {
        ensure!(
            serde_json::from_slice::<Value>(&fs::read(&id_file)?)? == identity,
            "campaign identity changed"
        );
    } else {
        atomic_json(&id_file, &identity)?;
    }
    let shards = s
        .corpus
        .shards
        .iter()
        .map(|v| scheme::PopulationShard {
            doc_start: v.doc_start,
            doc_end: v.doc_end,
            token_start: v.token_start,
            raw_offset: v.raw_offset as usize,
        })
        .collect::<Vec<_>>();
    eprintln!("loading all corpus coordinates and selected signed native catalogs");
    let mut service = scheme::PopulationService::open(
        &root.join("native-material"),
        s.prepared,
        &trusted,
        offsets,
        &shards,
        queries[0].clone(),
        &plan.policies,
    )?;
    eprintln!("full corpus service ready");
    let capture = run.join("fixtures");
    if plan.label == "sample" {
        fs::create_dir_all(&capture)?;
    }
    let client = scheme::VisitClient::open(&run.join("client-runtime"))?;
    let options = plan
        .policies
        .iter()
        .flat_map(|&method| plan.stages.iter().map(move |&stage| (method, stage)))
        .collect::<Vec<_>>();

    for (i, &id) in plan.ids.iter().enumerate() {
        let path = dest.join(format!("q{id:04}.jsonl"));
        if path.exists() {
            eprintln!("{} / {} resume q{id}", i + 1, plan.ids.len());
            continue;
        }
        let t = Instant::now();
        atomic_json(
            &dest.join("status.json"),
            &json!({"state":"running","completed":i,"total":plan.ids.len(),"query":id}),
        )?;
        let tmp = path.with_extension("pending");
        let mut out = std::io::BufWriter::new(fs::File::create(&tmp)?);
        let mut rng = StdRng::seed_from_u64(plan.seed ^ id as u64);
        let mut count = 0;
        let reference = &refs[&id];
        // A standalone rerank request starts with candidate IDs. Full requests accept only the query.
        let stage_candidates = service.standalone_candidates(&queries[id])?;
        ensure!(reference["candidates"] == stage_candidates.len());
        let expected = service.reference_stage_hashes(&queries[id], &stage_candidates)?;
        for round in 0..plan.warmups + plan.repeats {
            let mut order = options.clone();
            order.shuffle(&mut rng);
            for (position, (p, stage)) in order.into_iter().enumerate() {
                let mut row = service.measure_visit(
                    &client,
                    &queries[id],
                    p,
                    stage,
                    &stage_candidates,
                    &expected,
                    reference["execution_digest"]
                        .as_str()
                        .context("native execution digest")?,
                    (plan.label == "sample").then_some(capture.as_path()),
                )?;
                if stage == 3 {
                    ensure!(
                        row["server_phases"]["candidates"] == reference["candidates"]
                            && row["server_phases"]["ranked"] == reference["result_count"]
                    );
                } else if stage == 2 {
                    ensure!(
                        row["real_rows"] == reference["rerank_tokens"]
                            && row["candidate_count"] == reference["candidates"]
                    );
                }
                ensure!(
                    row["verified"] == true
                        && row["reference_parity"] == true
                        && row["query_id"] == id
                );
                row["cpu_affinity"] = affinity.clone().into();
                row["round"] = round.into();
                row["warmup"] = (round < plan.warmups).into();
                row["position"] = position.into();
                row["policy"] = policy_name(p).into();
                serde_json::to_writer(&mut out, &row)?;
                writeln!(out)?;
                count += 1;
            }
        }
        ensure!(count == options.len() * (plan.warmups + plan.repeats));
        out.flush()?;
        out.get_ref().sync_all()?;
        fs::rename(tmp, &path)?;
        eprintln!(
            "completed {}/{} query {id} in {:.2}s",
            i + 1,
            plan.ids.len(),
            t.elapsed().as_secs_f64()
        );
    }
    atomic_json(
        &dest.join("status.json"),
        &json!({"state":"complete","completed":plan.ids.len(),"total":plan.ids.len()}),
    )?;
    Ok(())
}
