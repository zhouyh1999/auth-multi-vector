pub type Coordinate = i32;
pub type Similarity = i64;
pub use gem_core::{
    FixedNumericProfileV1 as NumericProfile, FixedQueryV3, fixed_coordinates_v1, fixed_fp16_v1,
};
pub use gem_matrix_proof::commit_i32_matrix_v1 as commit_matrix;
pub use gem_search::{
    FixedExecutionV3, FixedMetricTablesV3, FixedNodeDistanceV3, fixed_similarity_table_v3, fixed_similarity_table_serial_v3,
    maxsim_fixed_matrix_v3, replay_fixed_search_v3, rerank_fixed_matrices_v3,
    select_fixed_clusters_v3,
};
pub const PROFILE_ID: &str = gem_core::FIXED_PROFILE_ID_V1;
pub const IS_COMPACT: bool = false;
pub const SCALE_SQUARED: i128 = gem_core::FIXED_SCALE_SQUARED_V1;
pub const SNAPSHOT_MAGIC: &[u8; 8] = b"G3SCHSNP";
use curve25519_dalek::scalar::Scalar;
use gem_core::Result;
use gem_matrix_proof::{
    ProjectionArgumentV1, ProjectionContextV1, ProjectionTimingsV1, VerifiedProjectionV1,
};
use rand::{CryptoRng, RngCore};
pub fn scalar_coordinate(x: Coordinate) -> Scalar {
    gem_matrix_proof::scalar_i64_v1(i64::from(x))
}
pub fn scalar_similarity(x: Similarity) -> Scalar {
    gem_matrix_proof::scalar_i64_v1(x)
}
pub fn prove_projection_v1<R: RngCore + CryptoRng>(
    ctx: &ProjectionContextV1,
    a: &[Scalar],
    rng: &mut R,
) -> Result<(ProjectionArgumentV1, ProjectionTimingsV1)> {
    gem_matrix_proof::prove_projection_with_profile_v1(PROFILE_ID, ctx, a, rng)
}
pub fn verify_projection_v1(
    ctx: &ProjectionContextV1,
    p: &ProjectionArgumentV1,
) -> Result<(VerifiedProjectionV1, ProjectionTimingsV1)> {
    gem_matrix_proof::verify_projection_with_profile_v1(PROFILE_ID, ctx, p)
}
pub fn document_weights_v1(binding: gem_core::Hash, count: usize) -> Result<Vec<Scalar>> {
    gem_matrix_proof::document_weights_with_profile_v1(PROFILE_ID, binding, count)
}
pub const MANIFEST_DOMAIN: &[u8] = b"gem.auth.v3.manifest.8";
pub const REQUEST_DOMAIN: &[u8] = b"gem.auth.v3.request.8";
pub const COMPONENT_DOMAIN: &[u8] = b"gem.auth.v3.component.8";
pub const LEAF_DOMAIN: &[u8] = b"gem.auth.v3.leaf.8";
pub const ENTRIES_DOMAIN: &[u8] = b"gem.auth.v3.entries.8";
pub const DOCUMENTS_DOMAIN: &[u8] = b"gem.auth.v3.fixed-documents.8";
pub const METRIC_DOMAIN: &[u8] = b"gem.auth.v3.metric-statement.8";
pub const RERANKING_DOMAIN: &[u8] = b"gem.auth.v3.reranking-statement.8";
