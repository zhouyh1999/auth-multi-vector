//! Versioned semantic profiles and serialized records for GEM Native V3R3.

use serde::{Deserialize, Serialize};

use crate::{GemError, Result};

pub const PROTOCOL_VERSION_V3: u16 = 3;
pub const INDEX_MAGIC_V3: [u8; 8] = *b"GEMIDXV3";
pub const GRAPH_CHECKPOINT_MAGIC_V3: [u8; 8] = *b"G3GRAPH!";
pub const QUERY_MAGIC_V3: [u8; 8] = *b"GEMQRYV3";

pub const REFERENCE_COMMIT_V3: &str = "1b559d0ccb2bea7a23ac9f2f8e84040924e3972f";
pub const SEMANTIC_PROFILE_REPO_V3: &str = "gem-repo-released-deterministic-v3r3";
pub const SEMANTIC_PROFILE_REACHABILITY_SAFE_V3: &str =
    "gem-repo-reachability-safe-deterministic-v3r3";
pub const MEMBERSHIP_SEMANTICS_ID_V3: &str =
    "repo-normalized-tf-ln-n-over-df-fixed-top20-doc-desc-v3";
pub const QEMD_SEMANTICS_ID_V3: &str = "repo-exact-lemon-uniform-histogram-fp32-one-minus-dot-v3";
pub const GRAPH_SEMANTICS_ID_V3: &str = "repo-owner-m24-recipient-m0-48-directed-stale-reciprocal-canonical-pair-score-threshold-repair-v3r3";
pub const GRAPH_SEMANTICS_REACHABILITY_SAFE_V3: &str = "repo-owner-m24-recipient-m0-48-directed-stale-reciprocal-canonical-pair-score-threshold-reachability-safe-v3r3";
pub const SEARCH_SEMANTICS_ID_V3: &str =
    "repo-round-robin-score-admission-all-initial-entries-empty-result-v3r2";
pub const QCH_SEMANTICS_ID_V3: &str =
    "repo-raw-query-centroid-average-per-token-one-minus-max-scalar-fp32-v3r3";
pub const RERANK_SEMANTICS_ID_V3: &str = "repo-exact-maxsim-one-minus-average-scalar-fp32-v3";
pub const SHORTCUT_POLICY_DISABLED_V3: &str = "repo-released-example-disabled-v3";
pub const GRAPH_BUILDER_SEQUENTIAL_V3: &str = "repo-sequential-oracle-v3";
pub const GRAPH_BUILDER_WAVEFRONT_V3: &str = "repo-deterministic-wavefront-v3";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepairPolicyV3 {
    RepoFaithful,
    ReachabilitySafeExtension,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GraphBuilderKindV3 {
    RepoSequentialOracle,
    RepoDeterministicWavefront,
    /// Provenance only: a fixed published graph, never a local construction.
    PublishedFixedGraph,
}

impl GraphBuilderKindV3 {
    pub const fn id(self) -> &'static str {
        match self {
            Self::RepoSequentialOracle => GRAPH_BUILDER_SEQUENTIAL_V3,
            Self::RepoDeterministicWavefront => GRAPH_BUILDER_WAVEFRONT_V3,
            Self::PublishedFixedGraph => "publisher-fixed-graph-v1",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticProfileV3 {
    pub protocol_version: u16,
    pub profile_id: String,
    pub reference_commit: String,
    pub membership_semantics_id: String,
    pub qemd_semantics_id: String,
    pub graph_semantics_id: String,
    pub qch_semantics_id: String,
    pub search_semantics_id: String,
    pub rerank_semantics_id: String,
    pub shortcut_policy_id: String,
    pub graph_builder: GraphBuilderKindV3,
    pub wave_size: u32,
}

impl SemanticProfileV3 {
    pub fn repo(graph_builder: GraphBuilderKindV3, wave_size: u32) -> Self {
        Self::repo_faithful(graph_builder, wave_size)
    }

    pub fn repo_faithful(graph_builder: GraphBuilderKindV3, wave_size: u32) -> Self {
        Self::with_repair_policy(graph_builder, wave_size, RepairPolicyV3::RepoFaithful)
    }

    pub fn reachability_safe(graph_builder: GraphBuilderKindV3, wave_size: u32) -> Self {
        Self::with_repair_policy(
            graph_builder,
            wave_size,
            RepairPolicyV3::ReachabilitySafeExtension,
        )
    }

    fn with_repair_policy(
        graph_builder: GraphBuilderKindV3,
        wave_size: u32,
        repair_policy: RepairPolicyV3,
    ) -> Self {
        let (profile_id, graph_semantics_id) = match repair_policy {
            RepairPolicyV3::RepoFaithful => (SEMANTIC_PROFILE_REPO_V3, GRAPH_SEMANTICS_ID_V3),
            RepairPolicyV3::ReachabilitySafeExtension => (
                SEMANTIC_PROFILE_REACHABILITY_SAFE_V3,
                GRAPH_SEMANTICS_REACHABILITY_SAFE_V3,
            ),
        };
        Self {
            protocol_version: PROTOCOL_VERSION_V3,
            profile_id: profile_id.into(),
            reference_commit: REFERENCE_COMMIT_V3.into(),
            membership_semantics_id: MEMBERSHIP_SEMANTICS_ID_V3.into(),
            qemd_semantics_id: QEMD_SEMANTICS_ID_V3.into(),
            graph_semantics_id: graph_semantics_id.into(),
            qch_semantics_id: QCH_SEMANTICS_ID_V3.into(),
            search_semantics_id: SEARCH_SEMANTICS_ID_V3.into(),
            rerank_semantics_id: RERANK_SEMANTICS_ID_V3.into(),
            shortcut_policy_id: SHORTCUT_POLICY_DISABLED_V3.into(),
            graph_builder,
            wave_size,
        }
    }

    /// Existing search semantics with truthful fixed-graph provenance. The enum
    /// variant is appended; old local profile and wire encodings are unchanged.
    pub fn published_fixed_graph() -> Self {
        let mut p = Self::repo_faithful(GraphBuilderKindV3::PublishedFixedGraph, 1);
        p.membership_semantics_id = "publisher-complete-memberships-v1".into();
        p.graph_semantics_id = "publisher-fixed-directed-ordered-adjacency-v1".into();
        p
    }

    pub fn is_published_fixed_graph(&self) -> bool {
        self.graph_builder == GraphBuilderKindV3::PublishedFixedGraph
    }

    pub fn repair_policy(&self) -> Result<RepairPolicyV3> {
        match (self.profile_id.as_str(), self.graph_semantics_id.as_str()) {
            (SEMANTIC_PROFILE_REPO_V3, GRAPH_SEMANTICS_ID_V3) => Ok(RepairPolicyV3::RepoFaithful),
            (SEMANTIC_PROFILE_REACHABILITY_SAFE_V3, GRAPH_SEMANTICS_REACHABILITY_SAFE_V3) => {
                Ok(RepairPolicyV3::ReachabilitySafeExtension)
            }
            _ => Err(GemError::InvalidManifest),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V3 {
            return Err(GemError::UnsupportedVersion(self.protocol_version));
        }
        let provenance_valid = if self.is_published_fixed_graph() {
            self.profile_id == SEMANTIC_PROFILE_REPO_V3
                && self.membership_semantics_id == "publisher-complete-memberships-v1"
                && self.graph_semantics_id == "publisher-fixed-directed-ordered-adjacency-v1"
                && self.wave_size == 1
        } else {
            self.repair_policy().is_ok()
                && self.membership_semantics_id == MEMBERSHIP_SEMANTICS_ID_V3
                && self.qemd_semantics_id == QEMD_SEMANTICS_ID_V3
        };
        if !provenance_valid
            || self.reference_commit != REFERENCE_COMMIT_V3
            || self.qch_semantics_id != QCH_SEMANTICS_ID_V3
            || self.search_semantics_id != SEARCH_SEMANTICS_ID_V3
            || self.rerank_semantics_id != RERANK_SEMANTICS_ID_V3
            || self.shortcut_policy_id != SHORTCUT_POLICY_DISABLED_V3
            || self.wave_size == 0
            || matches!(self.graph_builder, GraphBuilderKindV3::RepoSequentialOracle)
                && self.wave_size != 1
        {
            return Err(GemError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchParamsV3 {
    pub k: u32,
    pub rerank_k: u32,
    pub cluster_top_t: u32,
    pub ef_search: u32,
}

impl SearchParamsV3 {
    pub fn validate(&self) -> Result<()> {
        if self.k == 0
            || self.rerank_k < self.k
            || self.cluster_top_t == 0
            || self.ef_search < self.rerank_k
        {
            return Err(GemError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryV3 {
    pub query_id: u64,
    pub dimension: u16,
    pub token_count: u16,
    pub coordinates: Vec<f32>,
    pub params: SearchParamsV3,
}

/// Canonical FP16 corpus row consumed by the V3 Native index/query pipeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawDocumentV3 {
    pub doc_id: u32,
    pub token_count: u16,
    pub dimension: u16,
    pub coordinate_bits: Vec<u16>,
}

impl RawDocumentV3 {
    pub fn validate(&self, expected_dimension: u16, max_doc_tokens: u16) -> Result<()> {
        if self.dimension != expected_dimension || self.dimension == 0 {
            return Err(GemError::InvalidDimension {
                expected: usize::from(expected_dimension),
                actual: usize::from(self.dimension),
            });
        }
        if self.token_count == 0 || self.token_count > max_doc_tokens {
            return Err(GemError::InvalidTokenCount);
        }
        let expected = usize::from(self.token_count)
            .checked_mul(usize::from(self.dimension))
            .ok_or(GemError::NumericOverflow)?;
        if self.coordinate_bits.len() != expected {
            return Err(GemError::InvalidDimension {
                expected,
                actual: self.coordinate_bits.len(),
            });
        }
        Ok(())
    }
}

/// FP32 expansion of a canonical V3 FP16 corpus row for exact MaxSim reranking.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawDocumentF32V3 {
    pub doc_id: u32,
    pub token_count: u16,
    pub dimension: u16,
    pub coordinates: Vec<f32>,
}

impl RawDocumentF32V3 {
    pub fn validate(&self, expected_dimension: u16, max_doc_tokens: u16) -> Result<()> {
        if self.dimension != expected_dimension || self.dimension == 0 {
            return Err(GemError::InvalidDimension {
                expected: usize::from(expected_dimension),
                actual: usize::from(self.dimension),
            });
        }
        if self.token_count == 0 || self.token_count > max_doc_tokens {
            return Err(GemError::InvalidTokenCount);
        }
        let expected = usize::from(self.token_count)
            .checked_mul(usize::from(self.dimension))
            .ok_or(GemError::NumericOverflow)?;
        if self.coordinates.len() != expected {
            return Err(GemError::InvalidDimension {
                expected,
                actual: self.coordinates.len(),
            });
        }
        if self.coordinates.iter().any(|value| !value.is_finite()) {
            return Err(GemError::NonFinite);
        }
        Ok(())
    }
}

impl QueryV3 {
    pub fn validate(&self, expected_dimension: u16) -> Result<()> {
        if self.dimension != expected_dimension || self.dimension == 0 {
            return Err(GemError::InvalidDimension {
                expected: usize::from(expected_dimension),
                actual: usize::from(self.dimension),
            });
        }
        if self.token_count == 0 {
            return Err(GemError::InvalidTokenCount);
        }
        let expected = usize::from(self.dimension)
            .checked_mul(usize::from(self.token_count))
            .ok_or(GemError::NumericOverflow)?;
        if self.coordinates.len() != expected {
            return Err(GemError::InvalidDimension {
                expected,
                actual: self.coordinates.len(),
            });
        }
        if self.coordinates.iter().any(|value| !value.is_finite()) {
            return Err(GemError::NonFinite);
        }
        self.params.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchDocumentV3 {
    pub doc_id: u32,
    pub token_count: u16,
    pub compact_codes: Vec<u32>,
    pub cluster_ids: Vec<u32>,
    pub adjacency: Vec<u32>,
}

impl SearchDocumentV3 {
    pub fn validate(&self, max_doc_tokens: u16) -> Result<()> {
        if self.token_count == 0
            || self.token_count > max_doc_tokens
            || self.compact_codes.len() != usize::from(self.token_count)
            || self.cluster_ids.is_empty()
        {
            return Err(GemError::InvalidTokenCount);
        }
        if self.cluster_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || self.adjacency.contains(&self.doc_id)
        {
            return Err(GemError::NonCanonicalOrder);
        }
        Ok(())
    }

    pub fn intersects_sorted_clusters(&self, selected: &[u32]) -> bool {
        let (mut left, mut right) = (0usize, 0usize);
        while left < self.cluster_ids.len() && right < selected.len() {
            match self.cluster_ids[left].cmp(&selected[right]) {
                std::cmp::Ordering::Less => left += 1,
                std::cmp::Ordering::Greater => right += 1,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDistanceF32V3 {
    pub doc_id: u32,
    pub distance_bits: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EarlyStopEventV3 {
    pub pass: u32,
    pub cluster_id: u32,
    pub entry_doc_id: u32,
    pub doc_id: u32,
    pub distance_bits: u32,
    pub lower_bound_bits: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchTraceV3 {
    pub selected_clusters: Vec<u32>,
    pub queue_entries: Vec<(u32, u32)>,
    pub compared: Vec<NodeDistanceF32V3>,
    pub expanded: Vec<u32>,
    pub membership_examined: Vec<u32>,
    pub cluster_pruned: Vec<u32>,
    pub retained: Vec<NodeDistanceF32V3>,
    pub candidates: Vec<NodeDistanceF32V3>,
    pub early_stops: Vec<EarlyStopEventV3>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_dimension_query_and_raw_rows_are_rejected() {
        let query = QueryV3 {
            query_id: 0,
            dimension: 0,
            token_count: 1,
            coordinates: vec![],
            params: SearchParamsV3 {
                k: 1,
                rerank_k: 1,
                cluster_top_t: 1,
                ef_search: 1,
            },
        };
        assert!(query.validate(0).is_err());
        assert!(
            RawDocumentV3 {
                doc_id: 0,
                token_count: 1,
                dimension: 0,
                coordinate_bits: vec![]
            }
            .validate(0, 1)
            .is_err()
        );
        assert!(
            RawDocumentF32V3 {
                doc_id: 0,
                token_count: 1,
                dimension: 0,
                coordinates: vec![]
            }
            .validate(0, 1)
            .is_err()
        );
    }

    #[test]
    fn v3_profile_rejects_cross_family_and_invalid_wave() {
        let mut profile =
            SemanticProfileV3::repo(GraphBuilderKindV3::RepoDeterministicWavefront, 28);
        profile.validate().unwrap();
        assert_eq!(
            profile.repair_policy().unwrap(),
            RepairPolicyV3::RepoFaithful
        );
        let safe = SemanticProfileV3::reachability_safe(
            GraphBuilderKindV3::RepoDeterministicWavefront,
            28,
        );
        safe.validate().unwrap();
        assert_eq!(
            safe.repair_policy().unwrap(),
            RepairPolicyV3::ReachabilitySafeExtension
        );
        profile.protocol_version = 2;
        assert!(profile.validate().is_err());
        let oracle = SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 2);
        assert!(oracle.validate().is_err());

        let mut superseded =
            SemanticProfileV3::repo(GraphBuilderKindV3::RepoDeterministicWavefront, 28);
        superseded.profile_id = "gem-repo-released-deterministic-v3".into();
        superseded.graph_semantics_id =
            "repo-owner-m24-recipient-m0-48-directed-stale-reciprocal-repair-v3".into();
        assert!(superseded.validate().is_err());
    }

    #[test]
    fn v3r1_profiles_cannot_claim_the_fixed_cache_and_search_semantics() {
        for (profile_id, graph_id) in [
            (
                "gem-repo-released-deterministic-v3r1",
                "repo-owner-m24-recipient-m0-48-directed-stale-reciprocal-repair-v3r1",
            ),
            (
                "gem-repo-reachability-safe-deterministic-v3r1",
                "repo-owner-m24-recipient-m0-48-directed-stale-reciprocal-reachability-safe-v3r1",
            ),
        ] {
            let mut old = SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1);
            old.profile_id = profile_id.into();
            old.graph_semantics_id = graph_id.into();
            old.search_semantics_id = "repo-corrected-round-robin-immediate-lower-bound-v3".into();
            assert!(old.validate().is_err());
        }
    }

    #[test]
    fn v3r2_profiles_and_individual_old_semantics_are_rejected() {
        for repair in [
            RepairPolicyV3::RepoFaithful,
            RepairPolicyV3::ReachabilitySafeExtension,
        ] {
            let current = SemanticProfileV3::with_repair_policy(
                GraphBuilderKindV3::RepoSequentialOracle,
                1,
                repair,
            );
            let mut old = current.clone();
            old.profile_id = old.profile_id.replace("v3r3", "v3r2");
            assert!(old.validate().is_err());
            let mut old = current.clone();
            old.graph_semantics_id = old
                .graph_semantics_id
                .replace("score-threshold-", "")
                .replace("v3r3", "v3r2");
            assert!(old.validate().is_err());
            let mut old = current;
            old.qch_semantics_id =
                "repo-raw-query-centroid-one-minus-average-scalar-fp32-v3".into();
            assert!(old.validate().is_err());
        }
    }
}
