//! Representative-cluster performance and deterministic-wavefront benchmark.

use std::{collections::BTreeSet, fs::OpenOptions, io::Write, path::Path, time::Instant};

use anyhow::{Context, Result, bail};
use gem_core::{GraphBuilderKindV3, RepairPolicyV3, hash_bytes, read_npy_i32};
use gem_search::{
    GraphBuildParamsV3, MembershipIndexV3, PhaseTimingsV3, QemdCodebookV3, QemdRuntimeStatsV3,
    RepairRunStatsV3, build_qemd_graph_v3_with_control, build_repo_memberships_v3,
    import_coarse_centroids, import_compact_codes, import_fine_centroids,
};
use rayon::ThreadPoolBuilder;
use serde::Serialize;

use super::{
    args::{RepairPolicyArg, semantic_profile},
    build::{ReachabilityDiagnostics, add_phase_totals, directed_reachability_diagnostics},
    evidence::{
        FileEvidence, ProcessSample, file_evidence, input_digest, input_files, process_sample,
    },
};
use crate::atomic_write;

#[derive(Clone, Debug, Serialize)]
struct ClusterBenchmarkRow {
    cluster_id: u32,
    full_posting_size: usize,
    builder_kind: &'static str,
    repair_policy: RepairPolicyV3,
    wave_size: u32,
    threads: usize,
    repetition: u32,
    wall_micros: u64,
    cpu_active_cores: f64,
    phase_timings: PhaseTimingsV3,
    qemd_runtime: QemdRuntimeStatsV3,
    repair: RepairRunStatsV3,
    validation_error: Option<String>,
    reachability: Option<ReachabilityDiagnostics>,
    directed_edges: usize,
    state_sha256: String,
    process_before: ProcessSample,
    process_after: ProcessSample,
}

#[derive(Clone, Debug, Serialize)]
struct ClusterBenchmarkSummary {
    cluster_id: u32,
    full_posting_size: usize,
    builder_kind: &'static str,
    wave_size: u32,
    threads: usize,
    repetitions: u32,
    median_wall_micros: f64,
    sequential_median_wall_micros: f64,
    speedup_over_sequential: f64,
    repeated_state_hash_identical: bool,
    wave1_matches_sequential_state: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ClusterBenchmarkReport {
    report_version: u16,
    report_revision: &'static str,
    status: &'static str,
    semantics: &'static str,
    repair_policy: RepairPolicyV3,
    command: Vec<String>,
    builder_binary: FileEvidence,
    inputs: Vec<FileEvidence>,
    input_digest: String,
    dimension: u16,
    max_doc_tokens: u16,
    documents: usize,
    tokens: usize,
    coarse_clusters: usize,
    cluster_ids: Vec<u32>,
    wave_sizes: Vec<u32>,
    thread_counts: Vec<usize>,
    repetitions: u32,
    rows: Vec<ClusterBenchmarkRow>,
    summaries: Vec<ClusterBenchmarkSummary>,
}

fn median(values: &[u64]) -> f64 {
    let mut values = values.to_vec();
    values.sort_unstable();
    if values.len().is_multiple_of(2) {
        let right = values.len() / 2;
        (values[right - 1] as f64 + values[right] as f64) / 2.0
    } else {
        values[values.len() / 2] as f64
    }
}

fn isolated_cluster_fixture(
    compact_codes: &[Vec<u32>],
    posting: &[u32],
) -> Result<(Vec<Vec<u32>>, MembershipIndexV3)> {
    if posting.is_empty() {
        bail!("representative cluster posting is empty");
    }
    // Local IDs ascend with original posting reversed, so local ID descending
    // exactly reproduces the original document-descending posting order.
    let local_codes: Vec<Vec<u32>> = posting
        .iter()
        .rev()
        .map(|&doc_id| compact_codes[doc_id as usize].clone())
        .collect();
    let document_count = local_codes.len();
    let local_posting: Vec<u32> = (0..document_count)
        .rev()
        .map(u32::try_from)
        .collect::<std::result::Result<_, _>>()?;
    let membership = MembershipIndexV3 {
        fine_to_coarse: vec![0],
        memberships: vec![vec![0]; document_count],
        postings: vec![local_posting.clone()],
        cluster_entries: vec![local_posting.first().copied()],
    };
    membership.validate(document_count, 1)?;
    Ok((local_codes, membership))
}

#[allow(clippy::too_many_arguments)]
fn run_isolated_cluster(
    cluster_id: u32,
    full_posting_size: usize,
    local_codes: &[Vec<u32>],
    membership: &MembershipIndexV3,
    codebook: &QemdCodebookV3,
    builder_kind: GraphBuilderKindV3,
    repair_policy: RepairPolicyArg,
    wave_size: u32,
    threads: usize,
    repetition: u32,
) -> Result<ClusterBenchmarkRow> {
    let profile = semantic_profile(builder_kind, wave_size, repair_policy);
    let params = GraphBuildParamsV3 {
        m: 24,
        m0: 48,
        ef_construction: 80,
        qemd_max_iterations: 1_000,
        wave_size,
    };
    profile.validate()?;
    params.validate_repo_profile()?;
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(move |index| format!("gem-v3-cluster-{cluster_id}-{index}"))
        .build()?;
    let process_before = process_sample();
    let started = Instant::now();
    let mut phase_timings = PhaseTimingsV3::default();
    let mut qemd_runtime = QemdRuntimeStatsV3::default();
    let outcome = pool.install(|| {
        build_qemd_graph_v3_with_control(
            local_codes,
            membership,
            codebook,
            &profile,
            params,
            None,
            None,
            |_| Ok(()),
            |progress| {
                add_phase_totals(&mut phase_timings, &progress.phase_timings)
                    .map_err(|error| gem_core::GemError::Serialization(error.to_string()))?;
                qemd_runtime = progress.qemd_runtime;
                Ok(())
            },
            || false,
        )
    })?;
    let wall_micros = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let process_after = process_sample();
    let cpu_active_cores = if wall_micros == 0 {
        0.0
    } else {
        process_after
            .cpu_runtime_nanos
            .saturating_sub(process_before.cpu_runtime_nanos) as f64
            / (wall_micros as f64 * 1_000.0)
    };
    let (reachability, validation_error) =
        match directed_reachability_diagnostics(&outcome.state, membership) {
            Ok(summary) => (Some(summary), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
    let directed_edges = outcome.state.adjacency.iter().map(Vec::len).sum();
    let state_sha256 = hex::encode(hash_bytes(
        b"gem.repo.v3.isolated.cluster.state",
        &serde_json::to_vec(&outcome.state)?,
    ));
    Ok(ClusterBenchmarkRow {
        cluster_id,
        full_posting_size,
        builder_kind: builder_kind.id(),
        repair_policy: repair_policy.into(),
        wave_size,
        threads,
        repetition,
        wall_micros,
        cpu_active_cores,
        phase_timings,
        qemd_runtime,
        repair: outcome.repair,
        validation_error,
        reachability,
        directed_edges,
        state_sha256,
        process_before,
        process_after,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cluster_benchmark(
    fine_centroids_npy: &Path,
    coarse_centroids_npy: &Path,
    fine_to_coarse_npy: &Path,
    code_dir: &Path,
    doclens_dir: &Path,
    repair_policy: RepairPolicyArg,
    cluster_ids: Vec<u32>,
    wave_sizes: Vec<u32>,
    threads: Vec<usize>,
    repetitions: u32,
    progress_jsonl: &Path,
    output: &Path,
    dimension: u16,
    max_doc_tokens: u16,
) -> Result<()> {
    if output.exists()
        || progress_jsonl.exists()
        || cluster_ids.is_empty()
        || wave_sizes.is_empty()
        || threads.is_empty()
        || repetitions == 0
        || cluster_ids.iter().copied().collect::<BTreeSet<_>>().len() != cluster_ids.len()
        || wave_sizes.iter().copied().collect::<BTreeSet<_>>().len() != wave_sizes.len()
        || threads.iter().copied().collect::<BTreeSet<_>>().len() != threads.len()
        || wave_sizes.contains(&0)
        || threads.iter().any(|&value| value == 0 || value > 56)
    {
        bail!("invalid cluster benchmark configuration or existing output");
    }
    let binary = file_evidence(&std::env::current_exe()?)?;
    let inputs = input_files(
        fine_centroids_npy,
        coarse_centroids_npy,
        fine_to_coarse_npy,
        code_dir,
        doclens_dir,
    )?;
    let digest = input_digest(&inputs)?;
    let fine_centroids = import_fine_centroids(fine_centroids_npy, dimension)?;
    let coarse_centroids = import_coarse_centroids(coarse_centroids_npy, dimension)?;
    let fine_count = fine_centroids.len() / usize::from(dimension);
    let coarse_count = coarse_centroids.len() / usize::from(dimension);
    let (mapping_header, signed_mapping) = read_npy_i32(fine_to_coarse_npy)?;
    if mapping_header.shape != [fine_count as u64] {
        bail!("fine-to-coarse mapping shape mismatch");
    }
    let mapping: Vec<u32> = signed_mapping
        .into_iter()
        .map(|value| u32::try_from(value).context("negative coarse-cluster ID"))
        .collect::<Result<_>>()?;
    let compact_codes = import_compact_codes(code_dir, doclens_dir, fine_count, max_doc_tokens)?;
    let token_count = compact_codes.iter().map(Vec::len).sum();
    let membership = build_repo_memberships_v3(&compact_codes, mapping, coarse_count)?;
    if cluster_ids.iter().any(|&cluster| {
        cluster as usize >= coarse_count || membership.postings[cluster as usize].is_empty()
    }) {
        bail!("representative cluster ID is out of range or empty");
    }
    let codebook = QemdCodebookV3::from_centroids(&fine_centroids, usize::from(dimension))?;
    let mut progress = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(progress_jsonl)?;
    let mut rows = Vec::new();
    for &cluster_id in &cluster_ids {
        let posting = &membership.postings[cluster_id as usize];
        let (local_codes, local_membership) = isolated_cluster_fixture(&compact_codes, posting)?;
        for repetition in 0..repetitions {
            let row = run_isolated_cluster(
                cluster_id,
                posting.len(),
                &local_codes,
                &local_membership,
                &codebook,
                GraphBuilderKindV3::RepoSequentialOracle,
                repair_policy,
                1,
                1,
                repetition,
            )?;
            serde_json::to_writer(&mut progress, &row)?;
            writeln!(progress)?;
            progress.sync_data()?;
            println!(
                "gem_v3_cluster_benchmark cluster={} posting={} builder={} wave={} threads={} repetition={} wall_us={} active_cores={:.3}",
                row.cluster_id,
                row.full_posting_size,
                row.builder_kind,
                row.wave_size,
                row.threads,
                row.repetition,
                row.wall_micros,
                row.cpu_active_cores,
            );
            rows.push(row);
        }
        for &wave_size in &wave_sizes {
            for &thread_count in &threads {
                for repetition in 0..repetitions {
                    let row = run_isolated_cluster(
                        cluster_id,
                        posting.len(),
                        &local_codes,
                        &local_membership,
                        &codebook,
                        GraphBuilderKindV3::RepoDeterministicWavefront,
                        repair_policy,
                        wave_size,
                        thread_count,
                        repetition,
                    )?;
                    serde_json::to_writer(&mut progress, &row)?;
                    writeln!(progress)?;
                    progress.sync_data()?;
                    println!(
                        "gem_v3_cluster_benchmark cluster={} posting={} builder={} wave={} threads={} repetition={} wall_us={} active_cores={:.3}",
                        row.cluster_id,
                        row.full_posting_size,
                        row.builder_kind,
                        row.wave_size,
                        row.threads,
                        row.repetition,
                        row.wall_micros,
                        row.cpu_active_cores,
                    );
                    rows.push(row);
                }
            }
        }
    }

    let mut summaries = Vec::new();
    for &cluster_id in &cluster_ids {
        let baseline_rows: Vec<&ClusterBenchmarkRow> = rows
            .iter()
            .filter(|row| {
                row.cluster_id == cluster_id
                    && row.builder_kind == GraphBuilderKindV3::RepoSequentialOracle.id()
            })
            .collect();
        let baseline_times: Vec<u64> = baseline_rows.iter().map(|row| row.wall_micros).collect();
        let baseline_median = median(&baseline_times);
        let baseline_hash = &baseline_rows[0].state_sha256;
        for &wave_size in &wave_sizes {
            for &thread_count in &threads {
                let selected: Vec<&ClusterBenchmarkRow> = rows
                    .iter()
                    .filter(|row| {
                        row.cluster_id == cluster_id
                            && row.builder_kind
                                == GraphBuilderKindV3::RepoDeterministicWavefront.id()
                            && row.wave_size == wave_size
                            && row.threads == thread_count
                    })
                    .collect();
                let times: Vec<u64> = selected.iter().map(|row| row.wall_micros).collect();
                let candidate_median = median(&times);
                summaries.push(ClusterBenchmarkSummary {
                    cluster_id,
                    full_posting_size: selected[0].full_posting_size,
                    builder_kind: GraphBuilderKindV3::RepoDeterministicWavefront.id(),
                    wave_size,
                    threads: thread_count,
                    repetitions,
                    median_wall_micros: candidate_median,
                    sequential_median_wall_micros: baseline_median,
                    speedup_over_sequential: baseline_median / candidate_median,
                    repeated_state_hash_identical: selected
                        .iter()
                        .all(|row| row.state_sha256 == selected[0].state_sha256),
                    wave1_matches_sequential_state: (wave_size == 1).then(|| {
                        selected
                            .iter()
                            .all(|row| &row.state_sha256 == baseline_hash)
                    }),
                });
            }
        }
    }
    let status = if summaries
        .iter()
        .all(|row| row.repeated_state_hash_identical)
        && summaries
            .iter()
            .filter(|row| row.wave_size == 1)
            .all(|row| row.wave1_matches_sequential_state == Some(true))
        && rows.iter().all(|row| row.validation_error.is_none())
    {
        "pass"
    } else {
        "fail"
    };
    let report = ClusterBenchmarkReport {
        report_version: 3,
        report_revision: "v3r3",
        status,
        semantics: "isolated-original-full-corpus-posting-with-exact-qemd-v3r1",
        repair_policy: repair_policy.into(),
        command: std::env::args().collect(),
        builder_binary: binary,
        inputs,
        input_digest: hex::encode(digest),
        dimension,
        max_doc_tokens,
        documents: compact_codes.len(),
        tokens: token_count,
        coarse_clusters: coarse_count,
        cluster_ids,
        wave_sizes,
        thread_counts: threads,
        repetitions,
        rows,
        summaries,
    };
    atomic_write(output, &serde_json::to_vec_pretty(&report)?)?;
    if status != "pass" {
        bail!("cluster benchmark determinism or wave-size-1 oracle parity failed");
    }
    println!("gem_v3_cluster_benchmark=pass output={}", output.display());
    Ok(())
}
