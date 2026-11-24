//! Index construction, checkpointing, repair probing, and index validation.

use std::{
    collections::{BTreeSet, VecDeque},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use anyhow::{Context, Result, bail};
use gem_core::{
    GRAPH_CHECKPOINT_MAGIC_V3, GraphBuilderKindV3, INDEX_MAGIC_V3, RepairPolicyV3,
    SemanticProfileV3, decode_frame_v3, encode_frame_v3, hash_bytes, read_npy_i32,
};
use gem_search::{
    GraphBuildParamsV3, GraphBuildStateV3, GraphCheckpointV3, IndexValidationSummaryV3,
    MembershipIndexV3, PhaseTimingsV3, QEMD_IMPLEMENTATION_ID_V3, QemdCodebookV3,
    QemdRuntimeStatsV3, RepairRunStatsV3, SearchIndexV3, assemble_search_index_v3_unvalidated,
    build_qemd_graph_v3_with_control, build_repo_memberships_v3, import_coarse_centroids,
    import_compact_codes, import_fine_centroids, repair_graph_state_v3,
};
use rayon::ThreadPoolBuilder;
use serde::Serialize;

use super::{
    args::{BuilderKindArg, RepairPolicyArg, semantic_profile},
    evidence::{
        ContentEvidence, FileEvidence, ProcessSample, content_evidence, file_evidence,
        input_digest, input_files, is_lower_hex, process_sample,
    },
};
use crate::atomic_write;

const MAX_FRAME_BYTES: u64 = 64_u64 << 30;

#[derive(Debug, Serialize)]
struct BuildReport {
    report_version: u16,
    report_revision: &'static str,
    status: &'static str,
    semantic_profile: SemanticProfileV3,
    repair_policy: RepairPolicyV3,
    graph_params: GraphBuildParamsV3,
    execution_threads: usize,
    index_builder_commit: String,
    builder_binary: FileEvidence,
    command: Vec<String>,
    inputs: Vec<FileEvidence>,
    input_digest: String,
    documents: usize,
    tokens: usize,
    fine_clusters: usize,
    coarse_clusters: usize,
    memberships: usize,
    repair_edges: u64,
    repair_capacity_evictions: u64,
    repair: RepairRunStatsV3,
    resumed_from_cluster: u32,
    completed_clusters: u32,
    elapsed_seconds: f64,
    phase_totals: PhaseTimingsV3,
    qemd_runtime: QemdRuntimeStatsV3,
    process_final: ProcessSample,
    checkpoint: FileEvidence,
    output: Option<FileEvidence>,
    validation: Option<IndexValidationSummaryV3>,
    validation_error: Option<String>,
}

pub(super) fn add_phase_totals(total: &mut PhaseTimingsV3, row: &PhaseTimingsV3) -> Result<()> {
    total.phase_a_search_micros = total
        .phase_a_search_micros
        .checked_add(row.phase_a_search_micros)
        .context("phase A time overflow")?;
    total.phase_b_owner_micros = total
        .phase_b_owner_micros
        .checked_add(row.phase_b_owner_micros)
        .context("phase B time overflow")?;
    total.phase_c_intents_micros = total
        .phase_c_intents_micros
        .checked_add(row.phase_c_intents_micros)
        .context("phase C time overflow")?;
    total.phase_d_reduce_micros = total
        .phase_d_reduce_micros
        .checked_add(row.phase_d_reduce_micros)
        .context("phase D time overflow")?;
    total.publish_barrier_micros = total
        .publish_barrier_micros
        .checked_add(row.publish_barrier_micros)
        .context("barrier time overflow")?;
    total.graph_lock_wait_micros = total
        .graph_lock_wait_micros
        .checked_add(row.graph_lock_wait_micros)
        .context("lock-wait time overflow")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build(
    index_builder_commit: String,
    builder_kind: BuilderKindArg,
    repair_policy: RepairPolicyArg,
    fine_centroids_npy: PathBuf,
    coarse_centroids_npy: PathBuf,
    fine_to_coarse_npy: PathBuf,
    code_dir: PathBuf,
    doclens_dir: PathBuf,
    output: PathBuf,
    checkpoint_path: PathBuf,
    report_path: PathBuf,
    progress_jsonl: PathBuf,
    posting_sizes_json: PathBuf,
    dimension: u16,
    max_doc_tokens: u16,
    params: GraphBuildParamsV3,
    build_threads: usize,
    stop_after_cluster: Option<u32>,
    resume: bool,
) -> Result<()> {
    if !is_lower_hex(&index_builder_commit, 40) || build_threads == 0 || build_threads > 56 {
        bail!("builder commit or physical thread count is invalid");
    }
    if output.exists() || report_path.exists() {
        bail!("refusing to overwrite V3 output or report");
    }
    if !resume
        && (checkpoint_path.exists() || progress_jsonl.exists() || posting_sizes_json.exists())
    {
        bail!("V3 checkpoint/progress/posting artifact exists; pass --resume or choose new paths");
    }
    params.validate_repo_profile()?;
    let graph_builder: GraphBuilderKindV3 = builder_kind.into();
    let profile = semantic_profile(graph_builder, params.wave_size, repair_policy);
    profile.validate()?;
    let started = Instant::now();
    let binary_path = std::env::current_exe()?;
    let binary = file_evidence(&binary_path)?;
    let inputs = input_files(
        &fine_centroids_npy,
        &coarse_centroids_npy,
        &fine_to_coarse_npy,
        &code_dir,
        &doclens_dir,
    )?;
    let input_digest = input_digest(&inputs)?;
    let fine_centroids = import_fine_centroids(&fine_centroids_npy, dimension)?;
    let coarse_centroids = import_coarse_centroids(&coarse_centroids_npy, dimension)?;
    let fine_count = fine_centroids.len() / usize::from(dimension);
    let coarse_count = coarse_centroids.len() / usize::from(dimension);
    let (mapping_header, signed_mapping) = read_npy_i32(&fine_to_coarse_npy)?;
    if mapping_header.shape != [fine_count as u64] {
        bail!("fine-to-coarse mapping shape mismatch");
    }
    let fine_to_coarse: Vec<u32> = signed_mapping
        .into_iter()
        .map(|value| {
            let cluster = u32::try_from(value).context("negative coarse-cluster ID")?;
            if cluster as usize >= coarse_count {
                bail!("coarse-cluster ID out of range");
            }
            Ok(cluster)
        })
        .collect::<Result<_>>()?;
    let compact_codes = import_compact_codes(&code_dir, &doclens_dir, fine_count, max_doc_tokens)?;
    let token_count: usize = compact_codes.iter().map(Vec::len).sum();
    let membership = build_repo_memberships_v3(&compact_codes, fine_to_coarse, coarse_count)?;
    let membership_count: usize = membership.memberships.iter().map(Vec::len).sum();
    let posting_evidence = serde_json::json!({
        "posting_sizes_version": 3,
        "semantic_profile": profile,
        "input_digest": hex::encode(input_digest),
        "documents": compact_codes.len(),
        "coarse_clusters": coarse_count,
        "membership_count": membership_count,
        "posting_sizes": membership.postings.iter().map(Vec::len).collect::<Vec<_>>(),
    });
    if resume {
        let previous: serde_json::Value = serde_json::from_slice(&fs::read(&posting_sizes_json)?)?;
        if previous != posting_evidence {
            bail!("posting evidence differs from resume inputs");
        }
    } else {
        atomic_write(
            &posting_sizes_json,
            &serde_json::to_vec_pretty(&posting_evidence)?,
        )?;
    }
    let codebook = QemdCodebookV3::from_centroids(&fine_centroids, usize::from(dimension))?;
    let checkpoint = if resume {
        let checkpoint: GraphCheckpointV3 = decode_frame_v3(
            GRAPH_CHECKPOINT_MAGIC_V3,
            &fs::read(&checkpoint_path)?,
            MAX_FRAME_BYTES,
        )?;
        checkpoint.validate(
            input_digest,
            &profile,
            params,
            &index_builder_commit,
            &binary.sha256,
            coarse_count,
            compact_codes.len(),
        )?;
        Some(checkpoint)
    } else {
        None
    };
    let resumed_from_cluster = checkpoint
        .as_ref()
        .map(|value| value.state.next_cluster)
        .unwrap_or(0);
    if let Some(stop) = stop_after_cluster
        && (stop <= resumed_from_cluster || stop as usize > coarse_count)
    {
        bail!("stop-after-cluster must be after resume and within coarse count");
    }
    let termination = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&termination);
    ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))?;
    let mut progress_file = if resume {
        OpenOptions::new().append(true).open(&progress_jsonl)?
    } else {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&progress_jsonl)?
    };
    let mut last_system = process_sample();
    let mut phase_totals = PhaseTimingsV3::default();
    let mut last_qemd = QemdRuntimeStatsV3::default();
    let graph_started = Instant::now();
    let pool = ThreadPoolBuilder::new()
        .num_threads(build_threads)
        .thread_name(|index| format!("gem-v3-build-{index}"))
        .build()?;
    let outcome = pool.install(|| {
        build_qemd_graph_v3_with_control(
            &compact_codes,
            &membership,
            &codebook,
            &profile,
            params,
            checkpoint.map(|value| value.state),
            stop_after_cluster,
            |state| {
                write_checkpoint(
                    &checkpoint_path,
                    input_digest,
                    &profile,
                    params,
                    &index_builder_commit,
                    &binary.sha256,
                    coarse_count,
                    compact_codes.len(),
                    state,
                )
                .map_err(|error| gem_core::GemError::Io(error.to_string()))
            },
            |progress| {
                add_phase_totals(&mut phase_totals, &progress.phase_timings)
                    .map_err(|error| gem_core::GemError::Serialization(error.to_string()))?;
                last_qemd = progress.qemd_runtime.clone();
                let system = process_sample();
                let cpu_delta = system
                    .cpu_runtime_nanos
                    .saturating_sub(last_system.cpu_runtime_nanos);
                let active_cores = if progress.elapsed_micros < 10_000 {
                    None
                } else {
                    Some(
                        (cpu_delta as f64 / (progress.elapsed_micros as f64 * 1_000.0))
                            .min(build_threads as f64),
                    )
                };
                let record = serde_json::json!({
                    "progress_version": 3,
                    "semantic_profile": profile,
                    "execution_threads": build_threads,
                    "cluster_id": progress.cluster_id,
                    "next_cluster": progress.next_cluster,
                    "total_clusters": progress.total_clusters,
                    "posting_documents": progress.posting_documents,
                    "cluster_elapsed_micros": progress.elapsed_micros,
                    "total_elapsed_seconds": graph_started.elapsed().as_secs_f64(),
                    "phase_timings": progress.phase_timings,
                    "qemd_runtime": progress.qemd_runtime,
                    "rss_kib": system.rss_kib,
                    "swap_kib": system.swap_kib,
                    "voluntary_context_switches_delta": system.voluntary_context_switches.saturating_sub(last_system.voluntary_context_switches),
                    "nonvoluntary_context_switches_delta": system.nonvoluntary_context_switches.saturating_sub(last_system.nonvoluntary_context_switches),
                    "cpu_active_cores": active_cores,
                });
                serde_json::to_writer(&mut progress_file, &record)
                    .map_err(|error| gem_core::GemError::Serialization(error.to_string()))?;
                writeln!(progress_file)
                    .map_err(|error| gem_core::GemError::Io(error.to_string()))?;
                progress_file
                    .sync_data()
                    .map_err(|error| gem_core::GemError::Io(error.to_string()))?;
                last_system = system;
                println!(
                    "gem_v3_progress cluster={} next={} total={} posting={} elapsed_us={} active_cores={} rss_kib={} swap_kib={} solver_calls={} cache_hits={} duplicate_solves={}",
                    progress.cluster_id,
                    progress.next_cluster,
                    progress.total_clusters,
                    progress.posting_documents,
                    progress.elapsed_micros,
                    active_cores.map_or_else(|| "na".to_owned(), |value| format!("{value:.3}")),
                    system.rss_kib,
                    system.swap_kib,
                    progress.qemd_runtime.solver_calls,
                    progress.qemd_runtime.cache_hits,
                    progress.qemd_runtime.in_flight_duplicate_pair_solves,
                );
                Ok(())
            },
            || termination.load(Ordering::SeqCst),
        )
    })?;
    let state = outcome.state;
    let repair = outcome.repair;
    write_checkpoint(
        &checkpoint_path,
        input_digest,
        &profile,
        params,
        &index_builder_commit,
        &binary.sha256,
        coarse_count,
        compact_codes.len(),
        &state,
    )?;
    let documents = state.inserted.len();
    let repair_edges = state.repair_edges;
    let repair_capacity_evictions = state.repair_capacity_evictions;
    let completed_clusters = state.next_cluster;
    let (status, output_evidence, validation, validation_error) =
        if completed_clusters as usize == coarse_count {
            let index = assemble_search_index_v3_unvalidated(
                profile.clone(),
                params,
                dimension,
                max_doc_tokens,
                fine_centroids,
                coarse_centroids,
                compact_codes,
                membership,
                state.adjacency,
            )?;
            match index.validate_policy() {
                Ok(validation) => {
                    atomic_write(&output, &encode_frame_v3(INDEX_MAGIC_V3, &index)?)?;
                    (
                        "complete",
                        Some(file_evidence(&output)?),
                        Some(validation),
                        None,
                    )
                }
                Err(error) => ("validation-failed", None, None, Some(format!("{error:#}"))),
            }
        } else {
            ("partial-checkpoint", None, None, None)
        };
    let report = BuildReport {
        report_version: 3,
        report_revision: "v3r3",
        status,
        semantic_profile: profile,
        repair_policy: repair_policy.into(),
        graph_params: params,
        execution_threads: build_threads,
        index_builder_commit,
        builder_binary: binary,
        command: std::env::args().collect(),
        inputs,
        input_digest: hex::encode(input_digest),
        documents,
        tokens: token_count,
        fine_clusters: fine_count,
        coarse_clusters: coarse_count,
        memberships: membership_count,
        repair_edges,
        repair_capacity_evictions,
        repair,
        resumed_from_cluster,
        completed_clusters,
        elapsed_seconds: started.elapsed().as_secs_f64(),
        phase_totals,
        qemd_runtime: last_qemd,
        process_final: process_sample(),
        checkpoint: file_evidence(&checkpoint_path)?,
        output: output_evidence,
        validation,
        validation_error,
    };
    atomic_write(&report_path, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "gem_v3_build status={} completed_clusters={} total_clusters={} report={}",
        report.status,
        report.completed_clusters,
        report.coarse_clusters,
        report_path.display()
    );
    if let Some(error) = &report.validation_error {
        bail!("V3R3 index validation failed after retaining checkpoint/report: {error}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_checkpoint(
    path: &Path,
    input_digest: [u8; 32],
    profile: &SemanticProfileV3,
    params: GraphBuildParamsV3,
    index_builder_commit: &str,
    binary_sha256: &str,
    coarse_count: usize,
    document_count: usize,
    state: &GraphBuildStateV3,
) -> Result<()> {
    let checkpoint = GraphCheckpointV3 {
        input_digest,
        semantic_profile: profile.clone(),
        params,
        index_builder_commit: index_builder_commit.into(),
        builder_binary_sha256: binary_sha256.into(),
        qemd_implementation_id: QEMD_IMPLEMENTATION_ID_V3.into(),
        coarse_count: u32::try_from(coarse_count)?,
        document_count: u32::try_from(document_count)?,
        state: state.clone(),
    };
    atomic_write(
        path,
        &encode_frame_v3(GRAPH_CHECKPOINT_MAGIC_V3, &checkpoint)?,
    )
}

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct ReachabilityDiagnostics {
    reachable_memberships: u64,
    unreachable_memberships: u64,
    directed_reachability_passed: bool,
}

pub(super) fn directed_reachability_diagnostics(
    state: &GraphBuildStateV3,
    membership: &MembershipIndexV3,
) -> Result<ReachabilityDiagnostics> {
    let mut summary = ReachabilityDiagnostics::default();
    for posting in &membership.postings {
        let Some(&entry) = posting.first() else {
            continue;
        };
        let posting_set: BTreeSet<u32> = posting.iter().copied().collect();
        let mut reached = BTreeSet::from([entry]);
        let mut queue = VecDeque::from([entry]);
        while let Some(owner) = queue.pop_front() {
            let row = state
                .adjacency
                .get(owner as usize)
                .context("repair state adjacency owner is out of range")?;
            for &neighbor in row {
                if neighbor as usize >= state.adjacency.len() {
                    bail!("repair state adjacency neighbor is out of range");
                }
                if posting_set.contains(&neighbor) && reached.insert(neighbor) {
                    queue.push_back(neighbor);
                }
            }
        }
        summary.reachable_memberships += reached.len() as u64;
        summary.unreachable_memberships += (posting.len() - reached.len()) as u64;
    }
    summary.directed_reachability_passed = summary.unreachable_memberships == 0;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_and_benchmark_report_disconnection_without_rejecting_it() {
        let membership = MembershipIndexV3 {
            fine_to_coarse: vec![0],
            memberships: vec![vec![0]; 4],
            postings: vec![vec![3, 2, 1, 0], vec![]],
            cluster_entries: vec![Some(3), None],
        };
        let mut state = GraphBuildStateV3::empty(4);
        state.adjacency = vec![vec![], vec![0], vec![], vec![2]];
        let summary = directed_reachability_diagnostics(&state, &membership).unwrap();
        assert_eq!(summary.reachable_memberships, 2);
        assert_eq!(summary.unreachable_memberships, 2);
        assert!(!summary.directed_reachability_passed);
        state.adjacency[2].push(1);
        assert!(
            directed_reachability_diagnostics(&state, &membership)
                .unwrap()
                .directed_reachability_passed
        );
        state.adjacency[3].push(4);
        assert!(directed_reachability_diagnostics(&state, &membership).is_err());
    }
}

pub(super) fn load_index(path: &Path) -> Result<SearchIndexV3> {
    let index: SearchIndexV3 = decode_frame_v3(INDEX_MAGIC_V3, &fs::read(path)?, MAX_FRAME_BYTES)?;
    index.validate()?;
    Ok(index)
}

#[derive(Debug, Serialize)]
struct ValidationReport {
    report_version: u16,
    status: &'static str,
    index: ContentEvidence,
    semantic_profile: SemanticProfileV3,
    graph_params: GraphBuildParamsV3,
    validation: IndexValidationSummaryV3,
}

pub(super) fn validate(index_path: &Path, report_path: &Path) -> Result<()> {
    if report_path.exists() {
        bail!("refusing to overwrite validation report");
    }
    let index = load_index(index_path)?;
    let report = ValidationReport {
        report_version: 3,
        status: "pass",
        // Keep the validation artifact content-addressed. Absolute input paths
        // belong in stdout/run manifests, not in an output whose SHA-256 is a
        // determinism gate across otherwise equivalent build directories.
        index: content_evidence(index_path)?,
        semantic_profile: index.semantic_profile.clone(),
        graph_params: index.graph_params,
        validation: index.validate_policy()?,
    };
    atomic_write(report_path, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "gem_v3_validation=pass documents={} edges={} asymmetric_edges={} report={}",
        report.validation.document_count,
        report.validation.directed_edge_count,
        report.validation.asymmetric_edge_count,
        report_path.display()
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct RepairProbeReport {
    report_version: u16,
    report_revision: &'static str,
    status: &'static str,
    semantics: &'static str,
    checkpoint: FileEvidence,
    semantic_profile: SemanticProfileV3,
    repair_policy: RepairPolicyV3,
    graph_params: GraphBuildParamsV3,
    documents: usize,
    coarse_clusters: usize,
    repair_edges_before: u64,
    repair_edges_after: u64,
    repair_capacity_evictions_before: u64,
    repair_capacity_evictions_after: u64,
    repair: RepairRunStatsV3,
    repaired_state_sha256: String,
    reachability: Option<ReachabilityDiagnostics>,
    validation_error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn repair_probe(
    checkpoint_path: &Path,
    repair_policy: RepairPolicyArg,
    fine_centroids_npy: &Path,
    fine_to_coarse_npy: &Path,
    code_dir: &Path,
    doclens_dir: &Path,
    output: &Path,
    dimension: u16,
    max_doc_tokens: u16,
) -> Result<()> {
    if output.exists() {
        bail!("refusing to overwrite repair-probe report");
    }
    let checkpoint: GraphCheckpointV3 = decode_frame_v3(
        GRAPH_CHECKPOINT_MAGIC_V3,
        &fs::read(checkpoint_path)?,
        MAX_FRAME_BYTES,
    )?;
    checkpoint.semantic_profile.validate()?;
    if checkpoint.semantic_profile.repair_policy()? != repair_policy.into() {
        bail!("repair policy does not match the checkpoint semantic profile");
    }
    let fine_centroids = import_fine_centroids(fine_centroids_npy, dimension)?;
    let fine_count = fine_centroids.len() / usize::from(dimension);
    let (mapping_header, signed_mapping) = read_npy_i32(fine_to_coarse_npy)?;
    if mapping_header.shape != [fine_count as u64] {
        bail!("fine-to-coarse mapping shape mismatch");
    }
    let fine_to_coarse: Vec<u32> = signed_mapping
        .into_iter()
        .map(|value| u32::try_from(value).context("negative coarse-cluster ID"))
        .collect::<Result<_>>()?;
    if fine_to_coarse
        .iter()
        .any(|&cluster| cluster >= checkpoint.coarse_count)
    {
        bail!("coarse-cluster ID exceeds checkpoint shape");
    }
    let compact_codes = import_compact_codes(code_dir, doclens_dir, fine_count, max_doc_tokens)?;
    if compact_codes.len() != checkpoint.document_count as usize {
        bail!("checkpoint and compact corpus document counts differ");
    }
    let membership = build_repo_memberships_v3(
        &compact_codes,
        fine_to_coarse,
        checkpoint.coarse_count as usize,
    )?;
    let codebook = QemdCodebookV3::from_centroids(&fine_centroids, usize::from(dimension))?;
    let repair_edges_before = checkpoint.state.repair_edges;
    let repair_capacity_evictions_before = checkpoint.state.repair_capacity_evictions;
    let repaired = repair_graph_state_v3(
        &compact_codes,
        &membership,
        &codebook,
        &checkpoint.semantic_profile,
        checkpoint.params,
        checkpoint.state,
    )?;
    let (reachability, validation_error) =
        match directed_reachability_diagnostics(&repaired.state, &membership) {
            Ok(summary) => (Some(summary), None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
    let repaired_state_sha256 = hex::encode(hash_bytes(
        b"gem.repo.v3.repair.probe.state",
        &serde_json::to_vec(&repaired.state)?,
    ));
    let report = RepairProbeReport {
        report_version: 3,
        report_revision: "v3r3",
        status: if validation_error.is_none() {
            "pass"
        } else {
            "validation-failed"
        },
        semantics: "read-only-complete-construction-checkpoint-repair-probe-v3r1",
        checkpoint: file_evidence(checkpoint_path)?,
        semantic_profile: checkpoint.semantic_profile,
        repair_policy: repair_policy.into(),
        graph_params: checkpoint.params,
        documents: compact_codes.len(),
        coarse_clusters: membership.postings.len(),
        repair_edges_before,
        repair_edges_after: repaired.state.repair_edges,
        repair_capacity_evictions_before,
        repair_capacity_evictions_after: repaired.state.repair_capacity_evictions,
        repair: repaired.repair,
        repaired_state_sha256,
        reachability,
        validation_error,
    };
    atomic_write(output, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "gem_v3_repair_probe={} repair_edges={} capacity_evictions={} output={}",
        report.status,
        report.repair_edges_after,
        report.repair_capacity_evictions_after,
        output.display()
    );
    if let Some(error) = &report.validation_error {
        bail!("V3R3 repair validation failed after retaining report: {error}");
    }
    Ok(())
}
