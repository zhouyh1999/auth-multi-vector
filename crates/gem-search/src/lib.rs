#![forbid(unsafe_code)]
#![allow(
    clippy::duplicate_mod,
    reason = "The shared algorithm is instantiated for two distinct numeric types and schemas"
)]

//! The sole active GEM Native implementation.
//!
//! This crate contains the repository-based deterministic V3R3 semantic
//! family, its exact qEMD implementation, and the official-artifact readers
//! needed by the index builder and query runner. Historical V1/V2 search and
//! authentication code is retained outside the Cargo workspace under
//! `archive/legacy-v1-v2`.

mod artifact_v3;
mod qemd;
mod shards_v3;
mod v3;

pub use artifact_v3::{
    ImportedDocumentShardV3, OfficialShardSpecV3, import_coarse_centroids, import_compact_codes,
    import_fine_centroids, import_official_document_shard, import_queries,
};
pub use qemd::{QEMD_IMPLEMENTATION_ID_V3, QemdCodebookV3};
pub use shards_v3::discover_official_shard_ids_v3;
pub use v3::{
    ComponentUsageV3, QueryExecutionV3, QueryMetricTablesV3, QueryPublicV3, RawVectorSourceV3,
    SearchAccessV3, execute_search_v3, replay_search_v3, rerank_from_source_v3,
};
pub use v3::{
    ExactRerankResultV3, GraphBuildOutcomeV3, GraphBuildParamsV3, GraphBuildProgressV3,
    GraphBuildStateV3, GraphCheckpointV3, IndexValidationSummaryV3, MembershipIndexV3,
    NativeQueryResultV3, PhaseTimingsV3, QemdRuntimeStatsV3, RepairRunStatsV3,
    RepairUnbridgedComponentV3, SearchIndexV3, ShortcutEdgeV3, ShortcutInjectionReportV3,
    ShortcutInjectionV3, ShortcutTrainingPairV3, assemble_search_index_v3,
    assemble_search_index_v3_unvalidated, build_qemd_graph_v3, build_qemd_graph_v3_with_control,
    build_repo_memberships_v3, exact_maxsim_rerank_v3, inject_shortcuts_v3, native_query_v3,
    repair_graph_state_v3,
};

pub use v3::{
    ExecutionNodeV3, ExecutionStopV3, ExecutionTraceV3, FixedExecutionV3, FixedMetricTablesV3,
    FixedNodeDistanceV3, FixedSearchTraceV3, fixed_similarity_table_serial_v3,
    fixed_similarity_table_v3, maxsim_fixed_matrix_v3,
    replay_fixed_search_v3, rerank_fixed_matrices_v3, select_fixed_clusters_v3,
};

pub use v3::compact;
