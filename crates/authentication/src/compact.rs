//! First-contact authentication of a fixed-point GEM query.
use bincode::Options;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use gem_auth_scheme_v3::compact::{
    DocumentVectorOpeningV3, SchemeDocumentOpeningV3, SchemeRetrievalVoV3, TokenBoundaryV3,
    backend_component_hash_v3, backend_document_leaf_v3, scheme_entries_digest_v3,
    validate_scheme_request_v3,
};
pub use gem_auth_scheme_v3::compact::{
    PreparedSchemeSnapshotV3, SchemeBackendV3, SchemePublicPayloadV3, SchemeRequestV3,
    TrustedSchemeSnapshotV3, authenticate_scheme_public_data_v3, numeric,
    validate_trusted_scheme_snapshot_v3,
};
use gem_auth_v3::{ComponentOpening, MetadataV3, verify_document_multiproof_v3};
use gem_core::{GemError, Hash, Result, hash_serialized as hash};
use gem_matrix_proof::{
    PreparedProjectionWitnessV1, ProjectionContextV1, ProjectionStageV1, canonical_point_v1,
    prove_projection_with_prepared_witness_v1, verify_aggregated_freivalds_v1,
};
use gem_search::SearchAccessV3;
use numeric::*;
use rand::rngs::OsRng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
#[path = "full.rs"]
mod full;
use full::*;
#[path = "e2e.rs"]
mod e2e;
use e2e::*;
#[path = "fair_endpoints.rs"]
mod fair_endpoints;
use fair_endpoints::*;
#[path = "vida_baselines.rs"]
mod vida_baselines;
use vida_baselines::*;
#[path = "power_weights.rs"]
mod power_weights;
use power_weights::*;
#[path = "power_aggregation.rs"]
mod power_aggregation;
use power_aggregation::*;
#[path = "document_block_pilot.rs"]
mod document_block_pilot;
use document_block_pilot::*;
#[path = "compact_protocol.rs"]
mod compact_protocol;
use compact_protocol::*;
#[path = "population_owner.rs"]
mod population_owner;
use population_owner::*;
#[path = "population_serve.rs"]
mod population_serve;
use population_serve::*;
#[path = "first_visit.rs"]
mod first_visit;
use first_visit::*;
#[path = "measure_visit.rs"]
mod measure_visit;
#[path = "regression.rs"]
mod regression;
pub use first_visit::{VisitClient, publish_visit_bundles};
pub use population_owner::{PopulationShard, population_prepare_shard, population_sign_owner};
pub use population_serve::PopulationService;
pub use regression::check_full_fixture;
