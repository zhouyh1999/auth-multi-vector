//! Publish a completed graph without repeating construction or repair.
//!
//! Ordinary resume still requires the identical builder binary. Finalization
//! verifies the original report/checkpoint/input binding and records the original
//! builder separately from this executable; the checkpoint remains untouched.

use std::{fs, path::Path, time::Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use gem_core::{
    GRAPH_CHECKPOINT_MAGIC_V3, INDEX_MAGIC_V3, decode_frame_v3, encode_frame_v3, read_npy_i32,
};
use gem_search::{
    GraphCheckpointV3, assemble_search_index_v3_unvalidated, build_repo_memberships_v3,
    import_coarse_centroids, import_compact_codes, import_fine_centroids,
};
use serde::Deserialize;

use super::{
    args::{Cli, Command, semantic_profile},
    evidence::{FileEvidence, file_evidence, input_digest, input_files},
};
use crate::atomic_write;

#[derive(Deserialize)]
struct CompletedBuild {
    report_version: u16,
    report_revision: String,
    status: String,
    command: Vec<String>,
    completed_clusters: u32,
    checkpoint: FileEvidence,
    builder_binary: FileEvidence,
    inputs: Vec<FileEvidence>,
}

pub(super) fn finalize(build_report_path: &Path, output: &Path, report_path: &Path) -> Result<()> {
    if output.exists() || report_path.exists() || output == report_path {
        bail!("refusing to overwrite finalization output or report");
    }
    let started = Instant::now();
    let source: CompletedBuild = serde_json::from_slice(&fs::read(build_report_path)?)?;
    if source.report_version != 3
        || source.report_revision != "v3r3"
        || !matches!(source.status.as_str(), "complete" | "validation-failed")
    {
        bail!(
            "finalize requires a completed V3R3 build report, including retained validation failures"
        );
    }
    let Command::Build {
        index_builder_commit,
        builder_kind,
        repair_policy,
        fine_centroids_npy,
        coarse_centroids_npy,
        fine_to_coarse_npy,
        code_dir,
        doclens_dir,
        checkpoint: checkpoint_path,
        dimension,
        max_doc_tokens,
        m,
        m0,
        ef_construction,
        qemd_max_iterations,
        wave_size,
        ..
    } = Cli::try_parse_from(&source.command)?.command
    else {
        bail!("source report command must be build");
    };
    // A last-cluster checkpoint alone can predate repair. The completed build
    // report binds the final, post-repair checkpoint by its bytes and SHA-256.
    let checkpoint_evidence = file_evidence(&checkpoint_path)?;
    if checkpoint_evidence != source.checkpoint {
        bail!("checkpoint differs from the completed build report");
    }
    let checkpoint: GraphCheckpointV3 = decode_frame_v3(
        GRAPH_CHECKPOINT_MAGIC_V3,
        &fs::read(&checkpoint_path)?,
        64_u64 << 30,
    )?;
    if checkpoint.state.next_cluster != checkpoint.coarse_count
        || source.completed_clusters != checkpoint.coarse_count
        || checkpoint.state.inserted.iter().any(|inserted| !inserted)
    {
        bail!("finalize requires a fully completed graph; partial checkpoints must use resume");
    }
    let inputs = input_files(
        &fine_centroids_npy,
        &coarse_centroids_npy,
        &fine_to_coarse_npy,
        &code_dir,
        &doclens_dir,
    )?;
    if inputs != source.inputs {
        bail!("inputs differ from the completed build report");
    }
    let digest = input_digest(&inputs)?;
    let fine_centroids = import_fine_centroids(&fine_centroids_npy, dimension)?;
    let coarse_centroids = import_coarse_centroids(&coarse_centroids_npy, dimension)?;
    let fine_count = fine_centroids.len() / usize::from(dimension);
    let coarse_count = coarse_centroids.len() / usize::from(dimension);
    let (header, mapping) = read_npy_i32(&fine_to_coarse_npy)?;
    if header.shape != [fine_count as u64] {
        bail!("fine-to-coarse mapping shape mismatch");
    }
    let mapping = mapping
        .into_iter()
        .map(|value| u32::try_from(value).context("negative coarse-cluster ID"))
        .collect::<Result<Vec<_>>>()?;
    let codes = import_compact_codes(&code_dir, &doclens_dir, fine_count, max_doc_tokens)?;
    let membership = build_repo_memberships_v3(&codes, mapping, coarse_count)?;
    let profile = semantic_profile(builder_kind.into(), wave_size, repair_policy);
    let params = gem_search::GraphBuildParamsV3 {
        m,
        m0,
        ef_construction,
        qemd_max_iterations,
        wave_size,
    };
    params.validate_repo_profile()?;
    checkpoint.validate(
        digest,
        &profile,
        params,
        &index_builder_commit,
        &source.builder_binary.sha256,
        coarse_count,
        codes.len(),
    )?;
    let index = assemble_search_index_v3_unvalidated(
        profile,
        params,
        dimension,
        max_doc_tokens,
        fine_centroids,
        coarse_centroids,
        codes,
        membership,
        checkpoint.state.adjacency,
    )?;
    let validation = index.validate_policy()?;
    atomic_write(output, &encode_frame_v3(INDEX_MAGIC_V3, &index)?)?;
    let report = serde_json::json!({
        "report_version": 3,
        "report_revision": "v3r3",
        "status": "complete",
        "operation": "finalize-completed-build",
        "reachability_required": false,
        "source_build_report": file_evidence(build_report_path)?,
        "checkpoint": checkpoint_evidence,
        "index_builder_commit": index_builder_commit,
        "builder_binary": source.builder_binary,
        "finalizer_binary": file_evidence(&std::env::current_exe()?)?,
        "command": std::env::args().collect::<Vec<_>>(),
        "input_digest": hex::encode(digest),
        "semantic_profile": index.semantic_profile,
        "graph_params": index.graph_params,
        "repair_policy": repair_policy,
        "graph_unchanged": true,
        "repair_repeated": false,
        "validation": validation,
        "output": file_evidence(output)?,
        "elapsed_seconds": started.elapsed().as_secs_f64(),
    });
    atomic_write(report_path, &serde_json::to_vec_pretty(&report)?)?;
    println!(
        "gem_v3_finalize=complete documents={} unreachable_memberships={} report={}",
        validation.document_count,
        validation.unreachable_memberships,
        report_path.display()
    );
    Ok(())
}
