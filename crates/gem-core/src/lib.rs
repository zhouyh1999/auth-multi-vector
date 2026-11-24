#![forbid(unsafe_code)]

//! Shared primitives for the sole active GEM Native V3R3 implementation.

mod compact;
mod error;
mod fixed;
mod hash;
mod npy;
mod numeric;
mod v3;
mod wire;

pub use compact::*;
pub use error::{GemError, Result};
pub use fixed::*;
pub use hash::{Hash, hash_bytes, hash_serialized, sha256_bytes, sha256_file};
pub use npy::{
    NpyHeaderV3, inspect_npy, read_npy_f16_bits, read_npy_f32, read_npy_i32, read_npy_i64,
};
pub use numeric::{decode_f16, strict_dot_f32, strict_maxsim_f32};
pub use v3::{
    EarlyStopEventV3, GRAPH_BUILDER_SEQUENTIAL_V3, GRAPH_BUILDER_WAVEFRONT_V3,
    GRAPH_CHECKPOINT_MAGIC_V3, GRAPH_SEMANTICS_ID_V3, GRAPH_SEMANTICS_REACHABILITY_SAFE_V3,
    GraphBuilderKindV3, INDEX_MAGIC_V3, MEMBERSHIP_SEMANTICS_ID_V3, NodeDistanceF32V3,
    PROTOCOL_VERSION_V3, QCH_SEMANTICS_ID_V3, QEMD_SEMANTICS_ID_V3, QUERY_MAGIC_V3, QueryV3,
    REFERENCE_COMMIT_V3, RERANK_SEMANTICS_ID_V3, RawDocumentF32V3, RawDocumentV3, RepairPolicyV3,
    SEARCH_SEMANTICS_ID_V3, SEMANTIC_PROFILE_REACHABILITY_SAFE_V3, SEMANTIC_PROFILE_REPO_V3,
    SHORTCUT_POLICY_DISABLED_V3, SearchDocumentV3, SearchParamsV3, SearchTraceV3,
    SemanticProfileV3,
};
pub use wire::{decode_frame_v3, encode_frame_v3};
