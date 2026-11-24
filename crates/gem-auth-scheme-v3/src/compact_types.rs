use super::numeric::{Coordinate, NumericProfile as FixedNumericProfileV1, Similarity};
use super::numeric::{FixedExecutionV3, FixedNodeDistanceV3};
use gem_auth_v3::{
    ComponentOpening, DocumentTreeV3, MerkleProofV3, MetadataV3, PublicDataV3, PublicModeV3,
    RawOpeningV3, SignedManifestV3,
};
use gem_core::{Hash, QueryV3};
use gem_matrix_proof::ProjectionArgumentV1;
use gem_search::SearchIndexV3;
use serde::{Deserialize, Serialize};
pub const SCHEME_AUTH_SCHEMA_V3: u16 = 9;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum SchemeBackendV3 {
    FixedRawFp16 = 0,
    FixedRawFp32 = 1,
    MatrixScheme = 2,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeManifestV3 {
    pub authentication_schema: u16,
    pub source: SignedManifestV3,
    pub numeric_profile: FixedNumericProfileV1,
    /// Matrix-scheme root; fixed-raw uses source.manifest.document_root.
    pub document_root: Hash,
    pub fixed_documents_digest: Hash,
    pub generator_id: String,
    pub spring_source_hash: String,
    pub document_rows: u16,
    pub coarse_commitment: [u8; 32],
    pub fine_commitment: [u8; 32],
    pub entries_digest: Hash,
}
impl SchemeManifestV3 {
    pub fn source(&self) -> &gem_auth_v3::ManifestV3 {
        &self.source.manifest
    }
    pub fn document_root_for(&self, backend: SchemeBackendV3) -> Hash {
        match backend {
            SchemeBackendV3::MatrixScheme => self.document_root,
            SchemeBackendV3::FixedRawFp16 | SchemeBackendV3::FixedRawFp32 => {
                self.source().document_root
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSchemeManifestV3 {
    pub manifest: SchemeManifestV3,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedSchemeSnapshotV3 {
    pub owner_public_key: [u8; 32],
    pub expected_manifest_digest: Hash,
    pub signed: SignedSchemeManifestV3,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SchemeRequestV3 {
    pub manifest_digest: Hash,
    pub query: QueryV3,
    pub backend: SchemeBackendV3,
    pub public_mode: PublicModeV3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentMatrixCommitmentV3 {
    pub point: [u8; 32],
}
/// Exactly one fifth component: raw vectors for fixed-raw, commitment for scheme.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DocumentVectorOpeningV3 {
    Raw(ComponentOpening<RawOpeningV3>),
    Commitment(ComponentOpening<DocumentMatrixCommitmentV3>),
}
impl DocumentVectorOpeningV3 {
    pub fn is_revealed(&self) -> bool {
        match self {
            Self::Raw(o) => o.is_revealed(),
            Self::Commitment(o) => o.is_revealed(),
        }
    }
    pub fn commitment(&self) -> gem_core::Result<&DocumentMatrixCommitmentV3> {
        match self {
            Self::Commitment(o) => o.revealed(),
            Self::Raw(_) => Err(gem_core::GemError::InvalidManifest),
        }
    }
    pub fn matches_backend(&self, backend: SchemeBackendV3) -> bool {
        matches!(
            (self, backend),
            (Self::Commitment(_), SchemeBackendV3::MatrixScheme)
                | (
                    Self::Raw(_),
                    SchemeBackendV3::FixedRawFp16 | SchemeBackendV3::FixedRawFp32
                )
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeDocumentOpeningV3 {
    pub metadata: MetadataV3,
    pub membership: ComponentOpening<Vec<u32>>,
    pub codes: ComponentOpening<Vec<u32>>,
    pub adjacency: ComponentOpening<Vec<u32>>,
    pub vector: DocumentVectorOpeningV3,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemePublicPayloadV3 {
    pub entries: Vec<Option<u32>>,
    pub raw_centroids: Option<PublicDataV3>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricPayloadFixedV3 {
    pub coarse: Vec<Similarity>,
    pub fine: Vec<Similarity>,
    pub coarse_argument: ProjectionArgumentV1,
    pub fine_argument: Option<ProjectionArgumentV1>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBoundaryV3 {
    pub doc_id: u32,
    pub token_count: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RerankingPayloadFixedV3 {
    // Candidate IDs and token boundaries are derived from replay and authenticated metadata.
    /// Query-token-major, then ascending document ID, then original token order. No padding on wire.
    pub similarities: Vec<Similarity>,
    pub argument: ProjectionArgumentV1,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Query payload only; authenticated global configuration is supplied by the client.
pub struct SchemeRetrievalVoV3 {
    pub backend: SchemeBackendV3,
    pub public_mode: PublicModeV3,
    pub public: Option<SchemePublicPayloadV3>,
    pub documents: Vec<SchemeDocumentOpeningV3>,
    pub proof: MerkleProofV3,
    pub metrics: Option<MetricPayloadFixedV3>,
    pub reranking: Option<RerankingPayloadFixedV3>,
    pub results: Vec<FixedNodeDistanceV3>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedSchemeSnapshotV3 {
    pub trusted: TrustedSchemeSnapshotV3,
    pub public: PublicDataV3,
    pub index: SearchIndexV3,
    pub metadata: Vec<MetadataV3>,
    /// Offline source-ID mapping; not part of document openings.
    pub source_ids: Vec<u64>,
    pub raw_bits: Vec<Vec<u16>>,
    pub fixed_documents: Vec<Vec<Coordinate>>,
    pub coarse_fixed: Vec<Coordinate>,
    pub fine_fixed: Vec<Coordinate>,
    pub commitments: Vec<[u8; 32]>,
    pub component_hashes: Vec<[Hash; 5]>,
    pub tree: DocumentTreeV3,
    pub raw_component_hashes: Vec<[Hash; 5]>,
    pub raw_tree: DocumentTreeV3,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SchemeTimingsV3 {
    pub phases: std::collections::BTreeMap<String, f64>,
    pub total_ms: f64,
    pub overhead_ms: f64,
    /// Concurrent branch durations overlap; do not add them as wall time.
    #[serde(default)]
    pub parallel_overlap_ms: f64,
}
impl SchemeTimingsV3 {
    pub(crate) fn record(&mut self, name: &str, t: std::time::Instant) {
        *self.phases.entry(name.into()).or_default() += t.elapsed().as_secs_f64() * 1000.;
    }
    pub(crate) fn finish(&mut self, t: std::time::Instant) {
        self.total_ms = t.elapsed().as_secs_f64() * 1000.;
        self.overhead_ms =
            self.total_ms + self.parallel_overlap_ms - self.phases.values().sum::<f64>();
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SchemeVoBytesV3 {
    pub parts: std::collections::BTreeMap<String, usize>,
    pub total: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedFixedRetrievalV3 {
    pub execution: FixedExecutionV3,
    pub results: Vec<FixedNodeDistanceV3>,
    pub timings: SchemeTimingsV3,
}

impl SchemeManifestV3 {
    pub fn new(
        source: SignedManifestV3,
        root: Hash,
        fixed_documents_digest: Hash,
        document_rows: u16,
        commitments: [[u8; 32]; 2],
        entries_digest: Hash,
    ) -> Self {
        Self {
            authentication_schema: SCHEME_AUTH_SCHEMA_V3,
            source,
            numeric_profile: Default::default(),
            document_root: root,
            fixed_documents_digest,
            generator_id: gem_matrix_proof::GENERATOR_ID_V1.into(),
            spring_source_hash: gem_matrix_proof::SPRING_IMPLEMENTATION_HASH_V1.into(),
            document_rows,
            coarse_commitment: commitments[0],
            fine_commitment: commitments[1],
            entries_digest,
        }
    }
}
impl DocumentMatrixCommitmentV3 {
    pub fn new(point: [u8; 32]) -> Self {
        Self { point }
    }
}
impl PreparedSchemeSnapshotV3 {
    pub(crate) fn from_parts(
        trusted: TrustedSchemeSnapshotV3,
        raw: gem_auth_v3::PreparedRawSnapshotV3,
        fixed_documents: Vec<Vec<Coordinate>>,
        centroids: [Vec<Coordinate>; 2],
        commitments: Vec<[u8; 32]>,
        ads: (Vec<[Hash; 5]>, DocumentTreeV3),
    ) -> Self {
        let [coarse_fixed, fine_fixed] = centroids;
        Self {
            trusted,
            raw_component_hashes: raw.component_hashes,
            raw_tree: raw.tree,
            public: raw.public,
            index: raw.index,
            metadata: raw.metadata,
            source_ids: raw.source_ids,
            raw_bits: raw.raw_bits,
            fixed_documents,
            coarse_fixed,
            fine_fixed,
            commitments,
            component_hashes: ads.0,
            tree: ads.1,
        }
    }
}
