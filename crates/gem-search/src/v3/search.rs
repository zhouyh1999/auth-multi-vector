//! V3 index validation, deterministic qCH traversal, and exact FP32 reranking.

use std::collections::{BTreeSet, VecDeque};

use gem_core::{
    GemError, NodeDistanceF32V3, QueryV3, RawDocumentF32V3, Result, SearchDocumentV3,
    SearchTraceV3, SemanticProfileV3,
};
use serde::{Deserialize, Serialize};

use super::{graph::GraphBuildParamsV3, membership::MembershipIndexV3};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchIndexV3 {
    pub semantic_profile: SemanticProfileV3,
    pub graph_params: GraphBuildParamsV3,
    pub dimension: u16,
    pub max_doc_tokens: u16,
    pub fine_centroids: Vec<f32>,
    pub coarse_centroids: Vec<f32>,
    pub fine_to_coarse: Vec<u32>,
    pub cluster_entries: Vec<Option<u32>>,
    pub documents: Vec<SearchDocumentV3>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexValidationSummaryV3 {
    pub document_count: u32,
    pub token_count: u64,
    pub fine_cluster_count: u32,
    pub coarse_cluster_count: u32,
    pub membership_count: u64,
    pub directed_edge_count: u64,
    pub asymmetric_edge_count: u64,
    pub maximum_degree: u32,
    pub nonempty_clusters: u32,
    pub non_singleton_clusters: u32,
    pub reachable_memberships: u64,
    pub unreachable_memberships: u64,
    /// Diagnostic only: false does not make a structurally valid index invalid.
    pub directed_reachability_passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactRerankResultV3 {
    pub results: Vec<NodeDistanceF32V3>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeQueryResultV3 {
    pub trace: SearchTraceV3,
    pub exact: ExactRerankResultV3,
}

impl SearchIndexV3 {
    pub fn validate(&self) -> Result<()> {
        self.semantic_profile.validate()?;
        self.graph_params.validate_repo_profile()?;
        if self.semantic_profile.wave_size != self.graph_params.wave_size {
            return Err(GemError::InvalidManifest);
        }
        let dimension = usize::from(self.dimension);
        if dimension == 0
            || self.max_doc_tokens == 0
            || self.documents.is_empty()
            || self.fine_centroids.is_empty()
            || !self.fine_centroids.len().is_multiple_of(dimension)
            || self.coarse_centroids.is_empty()
            || !self.coarse_centroids.len().is_multiple_of(dimension)
        {
            return Err(GemError::InvalidManifest);
        }
        let fine_count = self.fine_centroids.len() / dimension;
        let coarse_count = self.coarse_centroids.len() / dimension;
        // Empty means absent for fixed published graphs; builders still require
        // the real training map. No fabricated labels enter the signed index.
        if (!self.semantic_profile.is_published_fixed_graph() || !self.fine_to_coarse.is_empty())
            && self.fine_to_coarse.len() != fine_count
            || self.cluster_entries.len() != coarse_count
            || self
                .fine_to_coarse
                .iter()
                .any(|&cluster| cluster as usize >= coarse_count)
            || self
                .fine_centroids
                .iter()
                .chain(&self.coarse_centroids)
                .any(|value| !value.is_finite())
        {
            return Err(GemError::InvalidManifest);
        }
        for (doc_id, document) in self.documents.iter().enumerate() {
            if document.doc_id as usize != doc_id
                || document
                    .compact_codes
                    .iter()
                    .any(|&code| code as usize >= fine_count)
                || document
                    .cluster_ids
                    .iter()
                    .any(|&cluster| cluster as usize >= coarse_count)
                || document
                    .adjacency
                    .iter()
                    .any(|&neighbor| neighbor as usize >= self.documents.len())
                || document.adjacency.len() > usize::from(self.graph_params.m0)
            {
                return Err(GemError::InvalidManifest);
            }
            document.validate(self.max_doc_tokens)?;
            // Local construction metadata still promises its canonical rows.
            // Published provenance authenticates the actual original order,
            // including repeated valid edges, rather than rewriting the graph.
            if !self.semantic_profile.is_published_fixed_graph()
                && document.adjacency.windows(2).any(|p| p[0] >= p[1])
            {
                return Err(GemError::NonCanonicalOrder);
            }
        }
        for (cluster, entry) in self.cluster_entries.iter().enumerate() {
            if let Some(entry) = entry {
                let document = self
                    .documents
                    .get(*entry as usize)
                    .ok_or(GemError::InvalidManifest)?;
                if document
                    .cluster_ids
                    .binary_search(&(cluster as u32))
                    .is_err()
                {
                    return Err(GemError::InvalidManifest);
                }
            }
        }
        Ok(())
    }

    /// Validate structure and fixed entries, and report directed reachability.
    /// The released repair can leave disconnected components when rows are full;
    /// full reachability is therefore not an index acceptance requirement.
    pub fn validate_policy(&self) -> Result<IndexValidationSummaryV3> {
        self.validate()?;
        let coarse_count = self.cluster_entries.len();
        let mut postings = vec![Vec::new(); coarse_count];
        let mut token_count = 0u64;
        let mut membership_count = 0u64;
        let mut directed_edge_count = 0u64;
        let mut asymmetric_edge_count = 0u64;
        let mut maximum_degree = 0usize;
        for document in &self.documents {
            token_count = token_count
                .checked_add(u64::from(document.token_count))
                .ok_or(GemError::NumericOverflow)?;
            membership_count = membership_count
                .checked_add(document.cluster_ids.len() as u64)
                .ok_or(GemError::NumericOverflow)?;
            directed_edge_count = directed_edge_count
                .checked_add(document.adjacency.len() as u64)
                .ok_or(GemError::NumericOverflow)?;
            maximum_degree = maximum_degree.max(document.adjacency.len());
            for &neighbor in &document.adjacency {
                if self.documents[neighbor as usize]
                    .adjacency
                    .contains(&document.doc_id)
                    == false
                {
                    asymmetric_edge_count = asymmetric_edge_count
                        .checked_add(1)
                        .ok_or(GemError::NumericOverflow)?;
                }
            }
            for &cluster in &document.cluster_ids {
                postings[cluster as usize].push(document.doc_id);
            }
        }

        let mut nonempty_clusters = 0u32;
        let mut non_singleton_clusters = 0u32;
        let mut reachable_memberships = 0u64;
        let mut unreachable_memberships = 0u64;
        for (cluster, posting) in postings.iter().enumerate() {
            let expected_entry = if self.semantic_profile.is_published_fixed_graph() {
                let entry = self.cluster_entries[cluster];
                if posting.is_empty() != entry.is_none()
                    || entry.is_some_and(|id| !posting.contains(&id))
                {
                    return Err(GemError::InvalidManifest);
                }
                entry
            } else {
                posting.iter().copied().max()
            };
            if self.cluster_entries[cluster] != expected_entry {
                return Err(GemError::InvalidManifest);
            }
            let Some(entry) = expected_entry else {
                continue;
            };
            nonempty_clusters = nonempty_clusters
                .checked_add(1)
                .ok_or(GemError::NumericOverflow)?;
            if posting.len() > 1 {
                non_singleton_clusters = non_singleton_clusters
                    .checked_add(1)
                    .ok_or(GemError::NumericOverflow)?;
            }
            let posting_set: BTreeSet<u32> = posting.iter().copied().collect();
            let mut reached = BTreeSet::new();
            let mut queue = VecDeque::from([entry]);
            reached.insert(entry);
            while let Some(owner) = queue.pop_front() {
                for &neighbor in &self.documents[owner as usize].adjacency {
                    if posting_set.contains(&neighbor) && reached.insert(neighbor) {
                        queue.push_back(neighbor);
                    }
                }
            }
            reachable_memberships = reachable_memberships
                .checked_add(reached.len() as u64)
                .ok_or(GemError::NumericOverflow)?;
            unreachable_memberships = unreachable_memberships
                .checked_add((posting.len() - reached.len()) as u64)
                .ok_or(GemError::NumericOverflow)?;
        }
        Ok(IndexValidationSummaryV3 {
            document_count: u32::try_from(self.documents.len())
                .map_err(|_| GemError::NumericOverflow)?,
            token_count,
            fine_cluster_count: u32::try_from(
                self.fine_centroids.len() / usize::from(self.dimension),
            )
            .map_err(|_| GemError::NumericOverflow)?,
            coarse_cluster_count: u32::try_from(coarse_count)
                .map_err(|_| GemError::NumericOverflow)?,
            membership_count,
            directed_edge_count,
            asymmetric_edge_count,
            maximum_degree: u32::try_from(maximum_degree).map_err(|_| GemError::NumericOverflow)?,
            nonempty_clusters,
            non_singleton_clusters,
            reachable_memberships,
            unreachable_memberships,
            directed_reachability_passed: unreachable_memberships == 0,
        })
    }

    pub fn qch_distance(&self, query: &QueryV3, doc_id: u32) -> Result<f32> {
        query.validate(self.dimension)?;
        if query.params.cluster_top_t as usize > self.cluster_entries.len() {
            return Err(GemError::InvalidManifest);
        }
        let tables = super::QueryMetricTablesV3::from_fine_centroids(&self.fine_centroids, query)?;
        tables.qch(
            &self
                .documents
                .get(doc_id as usize)
                .ok_or(GemError::InvalidManifest)?
                .compact_codes,
            query.token_count,
        )
    }
    pub fn search(&self, query: &QueryV3) -> Result<SearchTraceV3> {
        self.validate()?;
        Ok(super::execute_search_v3(self, self.into(), query)?.trace)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_search_index_v3_unvalidated(
    semantic_profile: SemanticProfileV3,
    graph_params: GraphBuildParamsV3,
    dimension: u16,
    max_doc_tokens: u16,
    fine_centroids: Vec<f32>,
    coarse_centroids: Vec<f32>,
    compact_codes: Vec<Vec<u32>>,
    membership: MembershipIndexV3,
    adjacency: Vec<Vec<u32>>,
) -> Result<SearchIndexV3> {
    if compact_codes.len() != membership.memberships.len() || adjacency.len() != compact_codes.len()
    {
        return Err(GemError::InvalidManifest);
    }
    let documents = compact_codes
        .into_iter()
        .zip(adjacency)
        .enumerate()
        .map(|(doc_id, (compact_codes, adjacency))| {
            let document = SearchDocumentV3 {
                doc_id: u32::try_from(doc_id).map_err(|_| GemError::NumericOverflow)?,
                token_count: u16::try_from(compact_codes.len())
                    .map_err(|_| GemError::InvalidTokenCount)?,
                compact_codes,
                cluster_ids: membership.memberships[doc_id].clone(),
                adjacency,
            };
            document.validate(max_doc_tokens)?;
            Ok(document)
        })
        .collect::<Result<Vec<_>>>()?;
    let index = SearchIndexV3 {
        semantic_profile,
        graph_params,
        dimension,
        max_doc_tokens,
        fine_centroids,
        coarse_centroids,
        fine_to_coarse: membership.fine_to_coarse,
        cluster_entries: membership.cluster_entries,
        documents,
    };
    Ok(index)
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_search_index_v3(
    semantic_profile: SemanticProfileV3,
    graph_params: GraphBuildParamsV3,
    dimension: u16,
    max_doc_tokens: u16,
    fine_centroids: Vec<f32>,
    coarse_centroids: Vec<f32>,
    compact_codes: Vec<Vec<u32>>,
    membership: MembershipIndexV3,
    adjacency: Vec<Vec<u32>>,
) -> Result<SearchIndexV3> {
    let index = assemble_search_index_v3_unvalidated(
        semantic_profile,
        graph_params,
        dimension,
        max_doc_tokens,
        fine_centroids,
        coarse_centroids,
        compact_codes,
        membership,
        adjacency,
    )?;
    index.validate()?;
    Ok(index)
}

pub fn exact_maxsim_rerank_v3(
    query: &QueryV3,
    raw_documents: &[RawDocumentF32V3],
    candidate_ids: &[u32],
) -> Result<ExactRerankResultV3> {
    query.validate(query.dimension)?;
    if raw_documents
        .iter()
        .enumerate()
        .any(|(doc_id, document)| document.doc_id as usize != doc_id)
    {
        return Err(GemError::NonCanonicalOrder);
    }
    super::rerank_from_source_v3(query, raw_documents, candidate_ids)
}

pub fn native_query_v3(
    index: &SearchIndexV3,
    raw_documents: &[RawDocumentF32V3],
    query: &QueryV3,
) -> Result<NativeQueryResultV3> {
    let trace = index.search(query)?;
    let candidate_ids: Vec<u32> = trace.candidates.iter().map(|row| row.doc_id).collect();
    let exact = exact_maxsim_rerank_v3(query, raw_documents, &candidate_ids)?;
    Ok(NativeQueryResultV3 { trace, exact })
}
