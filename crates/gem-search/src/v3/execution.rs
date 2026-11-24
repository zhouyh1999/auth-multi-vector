//! Shared deterministic V3R3 state machine with demand-driven component access.
use super::engine::{ExecutionMetricV3, ExecutionScoreV3, replay_engine_v3};
use super::{ExactRerankResultV3, SearchIndexV3, distance::DistanceDocV3};
use gem_core::{
    EarlyStopEventV3, GemError, NodeDistanceF32V3, QueryV3, RawDocumentF32V3, Result,
    SearchTraceV3, strict_dot_f32, strict_maxsim_f32,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeSet};

pub trait SearchAccessV3 {
    fn metadata(&self, id: u32) -> Result<u16>;
    fn membership(&self, id: u32) -> Result<&[u32]>;
    fn codes(&self, id: u32) -> Result<&[u32]>;
    fn adjacency(&self, id: u32) -> Result<&[u32]>;
}
impl SearchAccessV3 for SearchIndexV3 {
    fn metadata(&self, id: u32) -> Result<u16> {
        Ok(self
            .documents
            .get(id as usize)
            .ok_or(GemError::InvalidManifest)?
            .token_count)
    }
    fn membership(&self, id: u32) -> Result<&[u32]> {
        Ok(&self
            .documents
            .get(id as usize)
            .ok_or(GemError::InvalidManifest)?
            .cluster_ids)
    }
    fn codes(&self, id: u32) -> Result<&[u32]> {
        Ok(&self
            .documents
            .get(id as usize)
            .ok_or(GemError::InvalidManifest)?
            .compact_codes)
    }
    fn adjacency(&self, id: u32) -> Result<&[u32]> {
        Ok(&self
            .documents
            .get(id as usize)
            .ok_or(GemError::InvalidManifest)?
            .adjacency)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentUsageV3 {
    pub membership: BTreeSet<u32>,
    pub codes: BTreeSet<u32>,
    pub adjacency: BTreeSet<u32>,
    pub raw: BTreeSet<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryExecutionV3 {
    pub trace: SearchTraceV3,
    pub component_usage: ComponentUsageV3,
}
#[derive(Clone, Copy)]
pub struct QueryPublicV3<'a> {
    pub dimension: u16,
    pub fine_centroids: &'a [f32],
    pub coarse_centroids: &'a [f32],
    pub cluster_entries: &'a [Option<u32>],
}
impl<'a> From<&'a SearchIndexV3> for QueryPublicV3<'a> {
    fn from(i: &'a SearchIndexV3) -> Self {
        Self {
            dimension: i.dimension,
            fine_centroids: &i.fine_centroids,
            coarse_centroids: &i.coarse_centroids,
            cluster_entries: &i.cluster_entries,
        }
    }
}
#[derive(Clone, Debug)]
pub struct QueryMetricTablesV3 {
    pub selected_clusters: Vec<u32>,
    fine_count: usize,
    scores: Vec<f32>,
}
impl QueryMetricTablesV3 {
    pub fn from_fine_centroids(fine: &[f32], query: &QueryV3) -> Result<Self> {
        query.validate(query.dimension)?;
        let d = usize::from(query.dimension);
        if fine.is_empty() || !fine.len().is_multiple_of(d) {
            return Err(GemError::InvalidManifest);
        }
        let rows: Vec<Result<Vec<f32>>> = query
            .coordinates
            .par_chunks_exact(d)
            .map(|q| fine.chunks_exact(d).map(|c| strict_dot_f32(q, c)).collect())
            .collect();
        let mut scores = Vec::new();
        for row in rows {
            scores.extend(row?);
        }
        Ok(Self {
            selected_clusters: Vec::new(),
            fine_count: fine.len() / d,
            scores,
        })
    }
    pub fn compute(public: QueryPublicV3<'_>, query: &QueryV3) -> Result<Self> {
        query.validate(public.dimension)?;
        let d = usize::from(public.dimension);
        if public.fine_centroids.is_empty()
            || !public.fine_centroids.len().is_multiple_of(d)
            || public.coarse_centroids.len() != public.cluster_entries.len() * d
            || query.params.cluster_top_t as usize > public.cluster_entries.len()
        {
            return Err(GemError::InvalidManifest);
        }
        let mut selected = BTreeSet::new();
        for vector in query.coordinates.chunks_exact(d) {
            let rows: Vec<Result<DistanceDocV3>> = public
                .coarse_centroids
                .par_chunks_exact(d)
                .enumerate()
                .map(|(id, c)| DistanceDocV3::new(id as u32, -strict_dot_f32(vector, c)?))
                .collect();
            let mut rows = rows.into_iter().collect::<Result<Vec<_>>>()?;
            rows.sort();
            rows.truncate(query.params.cluster_top_t as usize);
            selected.extend(rows.into_iter().map(|r| r.doc_id));
        }
        let selected_clusters: Vec<u32> = selected.into_iter().collect();
        let fine_count = public.fine_centroids.len() / d;
        let mut scores = Vec::new();
        if selected_clusters
            .iter()
            .any(|&c| public.cluster_entries[c as usize].is_some())
        {
            let rows: Vec<Result<Vec<f32>>> = query
                .coordinates
                .par_chunks_exact(d)
                .map(|q| {
                    public
                        .fine_centroids
                        .chunks_exact(d)
                        .map(|c| strict_dot_f32(q, c))
                        .collect()
                })
                .collect();
            for row in rows {
                scores.extend(row?);
            }
        }
        Ok(Self {
            selected_clusters,
            fine_count,
            scores,
        })
    }
    pub fn qch(&self, codes: &[u32], query_tokens: u16) -> Result<f32> {
        if codes.is_empty() || self.scores.len() != self.fine_count * usize::from(query_tokens) {
            return Err(GemError::InvalidTokenCount);
        }
        let mut sum = 0f32;
        for row in self.scores.chunks_exact(self.fine_count) {
            let mut maximum: Option<f32> = None;
            for &code in codes {
                let value = *row.get(code as usize).ok_or(GemError::InvalidManifest)?;
                maximum = Some(match maximum {
                    Some(current) if current >= value => current,
                    _ => value,
                });
            }
            sum += 1f32 - maximum.ok_or(GemError::InvalidTokenCount)?;
            if !sum.is_finite() {
                return Err(GemError::NonFinite);
            }
        }
        let distance = sum / f32::from(query_tokens);
        if !distance.is_finite() {
            return Err(GemError::NonFinite);
        }
        Ok(distance)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FloatScoreV3(u32);
impl Ord for FloatScoreV3 {
    fn cmp(&self, other: &Self) -> Ordering {
        f32::from_bits(self.0).total_cmp(&f32::from_bits(other.0))
    }
}
impl PartialOrd for FloatScoreV3 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl ExecutionScoreV3 for FloatScoreV3 {
    fn strictly_less(self, other: Self) -> bool {
        f32::from_bits(self.0) < f32::from_bits(other.0)
    }
    fn strictly_greater(self, other: Self) -> bool {
        f32::from_bits(self.0) > f32::from_bits(other.0)
    }
}
impl ExecutionMetricV3 for QueryMetricTablesV3 {
    type Score = FloatScoreV3;
    fn score(&self, codes: &[u32], tokens: u16) -> Result<FloatScoreV3> {
        Ok(FloatScoreV3(self.qch(codes, tokens)?.to_bits()))
    }
}
/// FP32 compatibility wrapper over the shared state machine.
pub fn replay_search_v3<A: SearchAccessV3 + ?Sized>(
    access: &A,
    public: QueryPublicV3<'_>,
    query: &QueryV3,
    tables: &QueryMetricTablesV3,
) -> Result<QueryExecutionV3> {
    query.validate(public.dimension)?;
    let (trace, component_usage) = replay_engine_v3(
        access,
        public.cluster_entries,
        &tables.selected_clusters,
        &query.params,
        query.token_count,
        tables,
    )?;
    let nodes = |xs: Vec<super::engine::ExecutionNodeV3<FloatScoreV3>>| {
        xs.into_iter()
            .map(|x| NodeDistanceF32V3 {
                doc_id: x.doc_id,
                distance_bits: x.distance.0,
            })
            .collect()
    };
    Ok(QueryExecutionV3 {
        component_usage,
        trace: SearchTraceV3 {
            selected_clusters: trace.selected_clusters,
            queue_entries: trace.queue_entries,
            compared: nodes(trace.compared),
            expanded: trace.expanded,
            membership_examined: trace.membership_examined,
            cluster_pruned: trace.cluster_pruned,
            retained: nodes(trace.retained),
            candidates: nodes(trace.candidates),
            early_stops: trace
                .early_stops
                .into_iter()
                .map(|x| EarlyStopEventV3 {
                    pass: x.pass,
                    cluster_id: x.cluster_id,
                    entry_doc_id: x.entry_doc_id,
                    doc_id: x.doc_id,
                    distance_bits: x.distance.0,
                    lower_bound_bits: x.lower_bound.0,
                })
                .collect(),
        },
    })
}
pub fn execute_search_v3<A: SearchAccessV3 + ?Sized>(
    access: &A,
    public: QueryPublicV3<'_>,
    query: &QueryV3,
) -> Result<QueryExecutionV3> {
    let tables = QueryMetricTablesV3::compute(public, query)?;
    replay_search_v3(access, public, query, &tables)
}
pub trait RawVectorSourceV3: Sync {
    fn raw(&self, id: u32) -> Result<&RawDocumentF32V3>;
}
impl RawVectorSourceV3 for [RawDocumentF32V3] {
    fn raw(&self, id: u32) -> Result<&RawDocumentF32V3> {
        let d = self.get(id as usize).ok_or(GemError::InvalidManifest)?;
        if d.doc_id != id {
            return Err(GemError::NonCanonicalOrder);
        }
        Ok(d)
    }
}
pub fn rerank_from_source_v3<S: RawVectorSourceV3 + ?Sized>(
    query: &QueryV3,
    source: &S,
    candidate_ids: &[u32],
) -> Result<ExactRerankResultV3> {
    query.validate(query.dimension)?;
    let mut ids = candidate_ids.to_vec();
    ids.sort_unstable();
    if ids.windows(2).any(|p| p[0] == p[1]) {
        return Err(GemError::DuplicateId);
    }
    let rows: Vec<Result<DistanceDocV3>> = ids
        .par_iter()
        .map(|&id| {
            let doc = source.raw(id)?;
            doc.validate(query.dimension, u16::MAX)?;
            let sum = strict_maxsim_f32(
                &query.coordinates,
                usize::from(query.token_count),
                &doc.coordinates,
                usize::from(doc.token_count),
                usize::from(query.dimension),
            )?;
            DistanceDocV3::new(id, 1f32 - sum / f32::from(query.token_count))
        })
        .collect();
    let mut rows = rows.into_iter().collect::<Result<Vec<_>>>()?;
    rows.sort();
    rows.truncate(query.params.k as usize);
    Ok(ExactRerankResultV3 {
        results: rows.into_iter().map(DistanceDocV3::public).collect(),
    })
}

#[cfg(test)]
mod metric_order_tests {
    use super::*;
    #[test]
    fn signed_zero_total_order_does_not_change_admission_or_stop() {
        let negative = FloatScoreV3((-0.0f32).to_bits());
        let positive = FloatScoreV3(0.0f32.to_bits());
        assert!(negative < positive);
        assert!(!negative.strictly_less(positive));
        assert!(!positive.strictly_greater(negative));
    }
}
