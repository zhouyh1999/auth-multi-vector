use gem_core::{Hash, NodeDistanceF32V3, QueryV3, SearchParamsV3, SemanticProfileV3};
use gem_search::{GraphBuildParamsV3, NativeQueryResultV3, QueryExecutionV3, SearchIndexV3};
use serde::{Deserialize, Serialize};

pub const AUTH_SCHEMA_V3: u16 = 2;
pub const MAX_VO_BYTES: usize = 1 << 30;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataV3 {
    pub doc_id: u32,
    pub token_count: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentOpening<T> {
    Revealed(T),
    Digest(Hash),
}
impl<T> ComponentOpening<T> {
    pub fn revealed(&self) -> gem_core::Result<&T> {
        match self {
            Self::Revealed(v) => Ok(v),
            Self::Digest(_) => Err(gem_core::GemError::InvalidManifest),
        }
    }
    pub fn is_revealed(&self) -> bool {
        matches!(self, Self::Revealed(_))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RawWireV3 {
    Fp16,
    Fp32,
}
/// Every VO carries its complete public payload; legacy cached mode is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicModeV3 {
    Cold,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RawOpeningV3 {
    Fp16(Vec<u16>),
    Fp32(Vec<u32>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentOpeningV3 {
    pub metadata: MetadataV3,
    pub membership: ComponentOpening<Vec<u32>>,
    pub codes: ComponentOpening<Vec<u32>>,
    pub adjacency: ComponentOpening<Vec<u32>>,
    pub raw: ComponentOpening<RawOpeningV3>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicDataV3 {
    pub fine_bits: Vec<u16>,
    pub coarse_bits: Vec<u32>,
    pub entries: Vec<Option<u32>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestV3 {
    pub authentication_schema: u16,
    pub semantic_profile: SemanticProfileV3,
    pub graph_params: GraphBuildParamsV3,
    pub snapshot_id: Hash,
    pub document_count: u32,
    pub token_count: u64,
    pub dimension: u16,
    pub max_doc_tokens: u16,
    pub query_tokens: u16,
    pub params: SearchParamsV3,
    pub fine_count: u32,
    pub coarse_count: u32,
    pub document_root: Hash,
    pub fine_digest: Hash,
    pub coarse_digest: Hash,
    pub entry_digest: Hash,
    pub index_digest: Hash,
    pub raw_digest: Hash,
    pub source_ids_digest: Hash,
    pub provenance_digest: Hash,
    pub canonical_raw: String,
    pub allowed_wire: Vec<RawWireV3>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifestV3 {
    pub manifest: ManifestV3,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedSnapshotV3 {
    pub owner_public_key: [u8; 32],
    pub expected_manifest_digest: Hash,
    pub signed: SignedManifestV3,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawRequestV3 {
    pub manifest_digest: Hash,
    pub query: QueryV3,
    pub raw_wire: RawWireV3,
    pub public_mode: PublicModeV3,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Query payload only; authenticated global configuration is supplied by the client.
pub struct RawRetrievalVoV3 {
    pub raw_wire: RawWireV3,
    pub public_mode: PublicModeV3,
    pub public: Option<PublicDataV3>,
    pub documents: Vec<DocumentOpeningV3>,
    pub proof: crate::MerkleProofV3,
    pub results: Vec<NodeDistanceF32V3>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedRawSnapshotV3 {
    pub trusted: TrustedSnapshotV3,
    pub public: PublicDataV3,
    pub index: SearchIndexV3,
    pub metadata: Vec<MetadataV3>,
    /// Offline source-ID mapping; never disclosed in per-document VOs.
    pub source_ids: Vec<u64>,
    pub raw_bits: Vec<Vec<u16>>,
    pub component_hashes: Vec<[Hash; 5]>,
    pub tree: crate::DocumentTreeV3,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerTimingsV3 {
    #[serde(default)]
    pub tables_ms: f64,
    pub search_ms: f64,
    pub rerank_ms: f64,
    pub opening_proof_ms: f64,
    pub encoding_ms: f64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientTimingsV3 {
    pub decoding_ms: f64,
    pub public_auth_ms: f64,
    pub component_hash_ms: f64,
    pub multiproof_ms: f64,
    pub lookup_ms: f64,
    pub replay_ms: f64,
    pub raw_maxsim_ms: f64,
    pub result_check_ms: f64,
}
impl ClientTimingsV3 {
    pub fn total_ms(&self) -> f64 {
        self.decoding_ms
            + self.public_auth_ms
            + self.component_hash_ms
            + self.multiproof_ms
            + self.lookup_ms
            + self.replay_ms
            + self.raw_maxsim_ms
            + self.result_check_ms
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedRetrievalV3 {
    pub execution: QueryExecutionV3,
    pub result: NativeQueryResultV3,
    pub timings: ClientTimingsV3,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VoBytesV3 {
    pub globals: usize,
    pub metadata: usize,
    pub membership: usize,
    pub codes: usize,
    pub adjacency: usize,
    pub raw: usize,
    pub hidden_digests: usize,
    pub merkle_siblings: usize,
    pub results: usize,
    pub framing: usize,
    pub total: usize,
}
