//! Repository-based deterministic GEM V3R3 implementation.
//!
//! The public surface is kept here while each stage lives in a focused module:
//! membership preprocessing, qEMD graph construction and repair, online search
//! and exact reranking, plus the optional shortcut injector.

mod distance;
mod engine;
mod execution;
mod fixed;
pub use engine::{ExecutionNodeV3, ExecutionStopV3, ExecutionTraceV3};
pub use fixed::*;
mod graph;
mod membership;
mod qemd_runtime;
mod repair;
mod search;
mod shortcut;

pub use graph::{
    GraphBuildOutcomeV3, GraphBuildParamsV3, GraphBuildProgressV3, GraphBuildStateV3,
    GraphCheckpointV3, PhaseTimingsV3, QemdRuntimeStatsV3, RepairRunStatsV3,
    RepairUnbridgedComponentV3, build_qemd_graph_v3, build_qemd_graph_v3_with_control,
    repair_graph_state_v3,
};
pub use membership::{MembershipIndexV3, build_repo_memberships_v3};
pub use search::{
    ExactRerankResultV3, IndexValidationSummaryV3, NativeQueryResultV3, SearchIndexV3,
    assemble_search_index_v3, assemble_search_index_v3_unvalidated, exact_maxsim_rerank_v3,
    native_query_v3,
};
pub use shortcut::{
    ShortcutEdgeV3, ShortcutInjectionReportV3, ShortcutInjectionV3, ShortcutTrainingPairV3,
    inject_shortcuts_v3,
};

#[cfg(test)]
mod audit_tests;
#[cfg(test)]
mod tests;

pub use execution::{
    ComponentUsageV3, QueryExecutionV3, QueryMetricTablesV3, QueryPublicV3, RawVectorSourceV3,
    SearchAccessV3, execute_search_v3, replay_search_v3, rerank_from_source_v3,
};

mod fixed_numeric {
    pub type Coordinate = i32;
    pub type Similarity = i64;
    pub use gem_core::{FixedQueryV3, fixed_distance_v1, fixed_dot_v1};
    #[cfg(test)]
    pub const SCALE_SQUARED: i128 = gem_core::FIXED_SCALE_SQUARED_V1;
}
pub mod compact;
