//! Command-line schema and semantic-profile selection for the V3 runner.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use gem_core::{GraphBuilderKindV3, RepairPolicyV3, SemanticProfileV3};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "gem-native-v3",
    version = "V3R3",
    about = "Repo-based deterministic GEM V3R3 Native builder, validator, and query runner"
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(super) enum BuilderKindArg {
    RepoSequentialOracle,
    RepoDeterministicWavefront,
}

impl From<BuilderKindArg> for GraphBuilderKindV3 {
    fn from(value: BuilderKindArg) -> Self {
        match value {
            BuilderKindArg::RepoSequentialOracle => Self::RepoSequentialOracle,
            BuilderKindArg::RepoDeterministicWavefront => Self::RepoDeterministicWavefront,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(super) enum RepairPolicyArg {
    RepoFaithful,
    ReachabilitySafeExtension,
}

impl From<RepairPolicyArg> for RepairPolicyV3 {
    fn from(value: RepairPolicyArg) -> Self {
        match value {
            RepairPolicyArg::RepoFaithful => Self::RepoFaithful,
            RepairPolicyArg::ReachabilitySafeExtension => Self::ReachabilitySafeExtension,
        }
    }
}

pub(super) fn semantic_profile(
    graph_builder: GraphBuilderKindV3,
    wave_size: u32,
    repair_policy: RepairPolicyArg,
) -> SemanticProfileV3 {
    match repair_policy {
        RepairPolicyArg::RepoFaithful => SemanticProfileV3::repo_faithful(graph_builder, wave_size),
        RepairPolicyArg::ReachabilitySafeExtension => {
            SemanticProfileV3::reachability_safe(graph_builder, wave_size)
        }
    }
}

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    Build {
        #[arg(long)]
        index_builder_commit: String,
        #[arg(long, value_enum)]
        builder_kind: BuilderKindArg,
        #[arg(long, value_enum, default_value = "repo-faithful")]
        repair_policy: RepairPolicyArg,
        #[arg(long)]
        fine_centroids_npy: PathBuf,
        #[arg(long)]
        coarse_centroids_npy: PathBuf,
        #[arg(long)]
        fine_to_coarse_npy: PathBuf,
        #[arg(long)]
        code_dir: PathBuf,
        #[arg(long)]
        doclens_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        progress_jsonl: PathBuf,
        #[arg(long)]
        posting_sizes_json: PathBuf,
        #[arg(long, default_value_t = 128)]
        dimension: u16,
        #[arg(long, default_value_t = 180)]
        max_doc_tokens: u16,
        #[arg(long, default_value_t = 24)]
        m: u16,
        #[arg(long, default_value_t = 48)]
        m0: u16,
        #[arg(long, default_value_t = 80)]
        ef_construction: u32,
        #[arg(long, default_value_t = 1_000)]
        qemd_max_iterations: u32,
        #[arg(long, default_value_t = 16)]
        wave_size: u32,
        #[arg(long, default_value_t = 28)]
        build_threads: usize,
        #[arg(long)]
        stop_after_cluster: Option<u32>,
        #[arg(long, default_value_t = false)]
        resume: bool,
    },
    /// Publish an already completed V3R3 graph using current validation policy.
    /// Reads the original build report and inputs; does not resume or repair.
    Finalize {
        #[arg(long)]
        build_report: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        report: PathBuf,
    },
    Validate {
        #[arg(long)]
        index: PathBuf,
        #[arg(long)]
        report: PathBuf,
    },
    /// Diagnose repair on a retained complete construction checkpoint without
    /// resuming it or publishing a replacement checkpoint/index.
    RepairProbe {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long, value_enum, default_value = "repo-faithful")]
        repair_policy: RepairPolicyArg,
        #[arg(long)]
        fine_centroids_npy: PathBuf,
        #[arg(long)]
        fine_to_coarse_npy: PathBuf,
        #[arg(long)]
        code_dir: PathBuf,
        #[arg(long)]
        doclens_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 128)]
        dimension: u16,
        #[arg(long, default_value_t = 180)]
        max_doc_tokens: u16,
    },
    Query {
        #[arg(long)]
        index: PathBuf,
        #[arg(long)]
        encoder_dir: PathBuf,
        #[arg(long)]
        code_dir: PathBuf,
        #[arg(long)]
        queries_npy: PathBuf,
        #[arg(long)]
        query_ids: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 32)]
        query_tokens: u16,
        #[arg(long, default_value_t = 100)]
        k: u32,
        #[arg(long, default_value_t = 1_024)]
        rerank_k: u32,
        #[arg(long, default_value_t = 4)]
        cluster_top_t: u32,
        #[arg(long, default_value_t = 1_024)]
        ef_search: u32,
        #[arg(long, default_value_t = 28)]
        threads: usize,
    },
    ExactOracle {
        #[arg(long)]
        index: PathBuf,
        #[arg(long)]
        encoder_dir: PathBuf,
        #[arg(long)]
        code_dir: PathBuf,
        #[arg(long)]
        queries_npy: PathBuf,
        #[arg(long)]
        query_ids: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 32)]
        query_tokens: u16,
        #[arg(long, default_value_t = 100)]
        k: u32,
        #[arg(long, default_value_t = 28)]
        threads: usize,
    },
    Determinism {
        #[arg(long)]
        index: PathBuf,
        #[arg(long)]
        encoder_dir: PathBuf,
        #[arg(long)]
        code_dir: PathBuf,
        #[arg(long)]
        queries_npy: PathBuf,
        #[arg(long)]
        query_ids: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 32)]
        query_tokens: u16,
        #[arg(long, default_value_t = 100)]
        k: u32,
        #[arg(long, default_value_t = 1_024)]
        rerank_k: u32,
        #[arg(long, default_value_t = 4)]
        cluster_top_t: u32,
        #[arg(long, default_value_t = 1_024)]
        ef_search: u32,
        #[arg(long, value_delimiter = ',', default_value = "1,28")]
        threads: Vec<usize>,
        #[arg(long, default_value_t = 2)]
        repetitions: u32,
    },
    ClusterBenchmark {
        #[arg(long, value_enum, default_value = "repo-faithful")]
        repair_policy: RepairPolicyArg,
        #[arg(long)]
        fine_centroids_npy: PathBuf,
        #[arg(long)]
        coarse_centroids_npy: PathBuf,
        #[arg(long)]
        fine_to_coarse_npy: PathBuf,
        #[arg(long)]
        code_dir: PathBuf,
        #[arg(long)]
        doclens_dir: PathBuf,
        #[arg(long, value_delimiter = ',')]
        cluster_ids: Vec<u32>,
        #[arg(long, value_delimiter = ',', default_value = "1,4,8,16,28,56")]
        wave_sizes: Vec<u32>,
        #[arg(long, value_delimiter = ',', default_value = "16,28,56")]
        threads: Vec<usize>,
        #[arg(long, default_value_t = 2)]
        repetitions: u32,
        #[arg(long)]
        progress_jsonl: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 128)]
        dimension: u16,
        #[arg(long, default_value_t = 180)]
        max_doc_tokens: u16,
    },
}
