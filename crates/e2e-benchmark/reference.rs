//! Untimed reference computed from the original full index and FP16 shards on csr38.
use anyhow::{Context, Result, ensure};
use gem_auth_scheme_multi::compact as scheme;
use gem_core::{CompactQueryV3, compact_fp16_v1, hash_serialized, sha256_file};
use gem_search::compact::{
    FixedMetricTablesV3, fixed_similarity_table_serial_v3, fixed_similarity_table_v3,
    replay_fixed_search_v3, rerank_fixed_matrices_v3,
};
use rayon::prelude::*;

use serde_json::json;
use std::{env, fs, io::Write, path::Path};

use gem_lotte_auth_pilot::{Envelope, offline};

fn main() -> Result<()> {
    let out = env::args().nth(1).context("expected campaign directory")?;
    gem_lotte_auth_pilot::workspace_output(Path::new(&out))?;
    let out = Path::new(&out).canonicalize()?;
    let input = out.join("inputs");
    let snapshot: Envelope = offline::load_offline(&input.join("offline.compact"))?;
    ensure!(
        snapshot.version == 1
            && snapshot.input_binding == sha256_file(input.join("input-bindings.json"))?
    );
    let s = &snapshot.prepared;
    scheme::validate_trusted_scheme_snapshot_v3(&s.trusted)?;
    let queries = gem_search::import_queries(
        input.join("queries.npy"),
        128,
        32,
        s.trusted.signed.manifest.source().params.clone(),
    )?;
    ensure!(queries.len() == snapshot.corpus.queries);
    let data = offline::DiskCorpus::new(snapshot.corpus, &input)?;
    let outpath = out.join(if env::args().nth(2).as_deref() == Some("--compare-frozen") {
        "recomputed-reference.jsonl"
    } else {
        "native-reference.jsonl"
    });
    let query_count = queries.len();
    let tmp = outpath.with_extension("pending");
    let mut writer = fs::File::create(&tmp)?;
    for (id, query) in queries.into_iter().enumerate() {
        ensure!(query.query_id == id as u64);
        let q = CompactQueryV3::new(query.clone())?;
        let coarse = fixed_similarity_table_v3(&q, &s.coarse_fixed)?;
        let fine = fixed_similarity_table_v3(&q, &s.fine_fixed)?;
        let tables = FixedMetricTablesV3::from_tables(
            &coarse,
            fine,
            s.fine_fixed.len() / 128,
            &q,
            &s.index.cluster_entries,
        )?;
        let ex = replay_fixed_search_v3(&s.index, &s.index.cluster_entries, &q, &tables)?;
        let ids = ex.component_usage.raw.iter().copied().collect::<Vec<_>>();
        let matrices = ids
            .par_iter()
            .map(|&doc| -> Result<_> {
                let raw = data.bits(doc)?;
                let fixed = compact_fp16_v1(&raw)?;
                Ok((
                    doc,
                    raw.len() / 128,
                    fixed_similarity_table_serial_v3(&q, &fixed)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let ranking = rerank_fixed_matrices_v3(&q, &matrices)?;
        let digest = hex::encode(hash_serialized(
            b"gem.csr38.execution-and-results.v1",
            &(&ex, &ranking),
        )?);
        let stage_digest = |rows: &Vec<(u32, usize, Vec<i32>)>| -> Result<String> {
            Ok(hex::encode(hash_serialized(
                b"four-method.stage-verified-matrices.v1",
                rows,
            )?))
        };
        let stage_digests = [
            stage_digest(&vec![(0, coarse.len() / 32, coarse)])?,
            stage_digest(&vec![(
                0,
                s.fine_fixed.len() / 128,
                fixed_similarity_table_v3(&q, &s.fine_fixed)?,
            )])?,
            stage_digest(&matrices)?,
        ];
        let query_sha = hex::encode(hash_serialized(b"query", &query)?);
        writeln!(
            writer,
            "{}",
            json!({"query_id":id,"query_sha256":query_sha,"snapshot":hex::encode(s.trusted.expected_manifest_digest),
            "execution_digest":digest,"candidates":ids.len(),"result_count":ranking.len(),"ranking":ranking,"candidate_ids":ids,"stage_digests":stage_digests,
            "rerank_tokens":matrices.iter().map(|x|x.1).sum::<usize>()})
        )?;
        if (id + 1) % 100 == 0 {
            writer.sync_data()?;
            eprintln!("verified native reference {}/{}", id + 1, query_count);
        }
    }
    writer.sync_all()?;
    fs::rename(tmp, outpath)?;
    Ok(())
}
