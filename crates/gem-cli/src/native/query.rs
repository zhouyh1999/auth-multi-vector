//! Native qCH query execution, exhaustive reranking, and determinism reports.

use std::{collections::BTreeSet, fs, path::Path, time::Instant};

use anyhow::{Result, bail};
use gem_core::{RawDocumentF32V3, SearchParamsV3, decode_f16, hash_bytes};
use gem_search::{NativeQueryResultV3, exact_maxsim_rerank_v3, import_queries, native_query_v3};
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};

use super::{
    build::load_index,
    evidence::{FileEvidence, file_evidence},
};
use crate::{atomic_write, load_raw_corpus};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum QueryIdInput {
    Bare(Vec<usize>),
    Object { query_ids: Vec<usize> },
}

fn query_ids(path: &Path, query_count: usize) -> Result<Vec<usize>> {
    let input: QueryIdInput = serde_json::from_slice(&fs::read(path)?)?;
    let ids = match input {
        QueryIdInput::Bare(ids) | QueryIdInput::Object { query_ids: ids } => ids,
    };
    if ids.is_empty()
        || ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len()
        || ids.iter().any(|&query_id| query_id >= query_count)
    {
        bail!("query IDs must be nonempty, unique, and in range");
    }
    Ok(ids)
}

fn raw_documents_f32(
    encoder_dir: &Path,
    code_dir: &Path,
    dimension: u16,
    max_doc_tokens: u16,
) -> Result<Vec<RawDocumentF32V3>> {
    load_raw_corpus(encoder_dir, code_dir, dimension, max_doc_tokens)?
        .into_iter()
        .map(|document| {
            let coordinates = document
                .coordinate_bits
                .into_iter()
                .map(decode_f16)
                .collect::<gem_core::Result<Vec<_>>>()?;
            Ok(RawDocumentF32V3 {
                doc_id: document.doc_id,
                token_count: document.token_count,
                dimension: document.dimension,
                coordinates,
            })
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct QueryRow {
    query_id: u64,
    elapsed_micros: u64,
    trace_sha256: String,
    native: NativeQueryResultV3,
}

#[derive(Debug, Serialize)]
struct QueryReport {
    report_version: u16,
    semantics: &'static str,
    raw_artifact_semantics: &'static str,
    index: FileEvidence,
    queries: FileEvidence,
    query_ids: FileEvidence,
    threads: usize,
    command: Vec<String>,
    rows: Vec<QueryRow>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn query(
    index_path: &Path,
    encoder_dir: &Path,
    code_dir: &Path,
    queries_npy: &Path,
    query_ids_path: &Path,
    output: &Path,
    query_tokens: u16,
    params: SearchParamsV3,
    threads: usize,
) -> Result<()> {
    if output.exists() || threads == 0 || threads > 56 {
        bail!("invalid query output or physical thread count");
    }
    let index = load_index(index_path)?;
    let queries = import_queries(queries_npy, index.dimension, query_tokens, params)?;
    let ids = query_ids(query_ids_path, queries.len())?;
    let raw = raw_documents_f32(encoder_dir, code_dir, index.dimension, index.max_doc_tokens)?;
    if raw.len() != index.documents.len() {
        bail!("raw corpus and V3 index document counts differ");
    }
    let pool = ThreadPoolBuilder::new().num_threads(threads).build()?;
    let mut rows = Vec::with_capacity(ids.len());
    for query_id in ids {
        let started = Instant::now();
        let native = pool.install(|| native_query_v3(&index, &raw, &queries[query_id]))?;
        let trace_bytes = serde_json::to_vec(&native)?;
        rows.push(QueryRow {
            query_id: queries[query_id].query_id,
            elapsed_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            trace_sha256: hex::encode(hash_bytes(b"gem.native.v3.query", &trace_bytes)),
            native,
        });
    }
    let report = QueryReport {
        report_version: 3,
        semantics: "repo-qch-round-robin-plus-strict-fp32-exact-maxsim-distance-v3",
        raw_artifact_semantics: "official-f16-artifact-decoded-exactly-to-f32",
        index: file_evidence(index_path)?,
        queries: file_evidence(queries_npy)?,
        query_ids: file_evidence(query_ids_path)?,
        threads,
        command: std::env::args().collect(),
        rows,
    };
    atomic_write(output, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "gem_v3_native_query_complete queries={} threads={} output={}",
        report.rows.len(),
        threads,
        output.display()
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct ExactRow {
    query_id: u64,
    elapsed_micros: u64,
    results: Vec<gem_core::NodeDistanceF32V3>,
}

#[derive(Debug, Serialize)]
struct ExactReport {
    report_version: u16,
    semantics: &'static str,
    raw_artifact_semantics: &'static str,
    index: FileEvidence,
    queries: FileEvidence,
    query_ids: FileEvidence,
    threads: usize,
    documents: usize,
    rows: Vec<ExactRow>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn exact_oracle(
    index_path: &Path,
    encoder_dir: &Path,
    code_dir: &Path,
    queries_npy: &Path,
    query_ids_path: &Path,
    output: &Path,
    query_tokens: u16,
    k: u32,
    threads: usize,
) -> Result<()> {
    if output.exists() || k == 0 || threads == 0 || threads > 56 {
        bail!("invalid exact-oracle output, k, or thread count");
    }
    let index = load_index(index_path)?;
    let params = SearchParamsV3 {
        k,
        rerank_k: k,
        cluster_top_t: 1,
        ef_search: k,
    };
    let queries = import_queries(queries_npy, index.dimension, query_tokens, params)?;
    let ids = query_ids(query_ids_path, queries.len())?;
    let raw = raw_documents_f32(encoder_dir, code_dir, index.dimension, index.max_doc_tokens)?;
    if raw.len() != index.documents.len() {
        bail!("raw corpus and V3 index document counts differ");
    }
    let candidates: Vec<u32> = (0..raw.len())
        .map(u32::try_from)
        .collect::<std::result::Result<_, _>>()?;
    let pool = ThreadPoolBuilder::new().num_threads(threads).build()?;
    let mut rows = Vec::with_capacity(ids.len());
    for query_id in ids {
        let started = Instant::now();
        let result =
            pool.install(|| exact_maxsim_rerank_v3(&queries[query_id], &raw, &candidates))?;
        rows.push(ExactRow {
            query_id: queries[query_id].query_id,
            elapsed_micros: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            results: result.results,
        });
    }
    let report = ExactReport {
        report_version: 3,
        semantics: "exhaustive-corpus-strict-fp32-maxsim-one-minus-average-v3",
        raw_artifact_semantics: "official-f16-artifact-decoded-exactly-to-f32",
        index: file_evidence(index_path)?,
        queries: file_evidence(queries_npy)?,
        query_ids: file_evidence(query_ids_path)?,
        threads,
        documents: raw.len(),
        rows,
    };
    atomic_write(output, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "gem_v3_exact_oracle_complete queries={} documents={} output={}",
        report.rows.len(),
        report.documents,
        output.display()
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct DeterminismRow {
    threads: usize,
    repetition: u32,
    digest: String,
}

#[derive(Debug, Serialize)]
struct DeterminismReport {
    report_version: u16,
    status: &'static str,
    index: FileEvidence,
    queries: FileEvidence,
    query_ids: FileEvidence,
    thread_counts: Vec<usize>,
    repetitions: u32,
    rows: Vec<DeterminismRow>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn determinism(
    index_path: &Path,
    encoder_dir: &Path,
    code_dir: &Path,
    queries_npy: &Path,
    query_ids_path: &Path,
    output: &Path,
    query_tokens: u16,
    params: SearchParamsV3,
    threads: Vec<usize>,
    repetitions: u32,
) -> Result<()> {
    if output.exists()
        || repetitions < 2
        || threads.is_empty()
        || threads.iter().any(|&value| value == 0 || value > 56)
        || threads.iter().copied().collect::<BTreeSet<_>>().len() != threads.len()
    {
        bail!("invalid determinism configuration");
    }
    let index = load_index(index_path)?;
    let queries = import_queries(queries_npy, index.dimension, query_tokens, params)?;
    let ids = query_ids(query_ids_path, queries.len())?;
    let raw = raw_documents_f32(encoder_dir, code_dir, index.dimension, index.max_doc_tokens)?;
    if raw.len() != index.documents.len() {
        bail!("raw corpus and V3 index document counts differ");
    }
    let mut rows = Vec::new();
    let mut expected: Option<[u8; 32]> = None;
    for &thread_count in &threads {
        let pool = ThreadPoolBuilder::new().num_threads(thread_count).build()?;
        for repetition in 0..repetitions {
            let outputs: Vec<NativeQueryResultV3> = ids
                .iter()
                .map(|&query_id| pool.install(|| native_query_v3(&index, &raw, &queries[query_id])))
                .collect::<gem_core::Result<_>>()?;
            let digest = hash_bytes(b"gem.native.v3.determinism", &serde_json::to_vec(&outputs)?);
            if expected.is_some_and(|value| value != digest) {
                bail!(
                    "Native V3 determinism mismatch at threads={thread_count} repetition={repetition}"
                );
            }
            expected.get_or_insert(digest);
            rows.push(DeterminismRow {
                threads: thread_count,
                repetition,
                digest: hex::encode(digest),
            });
        }
    }
    let report = DeterminismReport {
        report_version: 3,
        status: "pass",
        index: file_evidence(index_path)?,
        queries: file_evidence(queries_npy)?,
        query_ids: file_evidence(query_ids_path)?,
        thread_counts: threads,
        repetitions,
        rows,
    };
    atomic_write(output, &serde_json::to_vec_pretty(&report)?)?;
    println!("gem_v3_determinism=pass output={}", output.display());
    Ok(())
}
