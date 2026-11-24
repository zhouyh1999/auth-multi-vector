//! Integer metric adapter, tables and exact reranking for the shared engine.
use super::fixed_numeric::*;
use super::{
    ComponentUsageV3, ExecutionNodeV3, ExecutionTraceV3, SearchAccessV3,
    engine::{ExecutionMetricV3, replay_engine_v3},
};
use gem_core::{FixedDistanceV3, GemError, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub type FixedNodeDistanceV3 = ExecutionNodeV3<FixedDistanceV3>;
pub type FixedSearchTraceV3 = ExecutionTraceV3<FixedDistanceV3>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedExecutionV3 {
    pub trace: FixedSearchTraceV3,
    pub component_usage: ComponentUsageV3,
}
#[derive(Clone, Debug)]
pub struct FixedMetricTablesV3 {
    selected: Vec<u32>,
    fine_count: usize,
    scores: Vec<Similarity>,
}
impl FixedMetricTablesV3 {
    pub fn from_tables(
        coarse: &[Similarity],
        fine: Vec<Similarity>,
        fine_count: usize,
        query: &FixedQueryV3,
        entries: &[Option<u32>],
    ) -> Result<Self> {
        query.validate()?;
        let selected = select_fixed_clusters_v3(coarse, query, entries.len())?;
        let needed = selected.iter().any(|&c| entries[c as usize].is_some());
        if fine_count == 0
            || (needed && fine.len() != fine_count * usize::from(query.source.token_count))
            || (!needed && !fine.is_empty())
        {
            return Err(GemError::InvalidManifest);
        }
        Ok(Self {
            selected,
            fine_count,
            scores: fine,
        })
    }
    pub fn selected_clusters(&self) -> &[u32] {
        &self.selected
    }
    pub fn fine_scores(&self) -> &[Similarity] {
        &self.scores
    }
    pub fn qch(&self, codes: &[u32], tokens: u16) -> Result<FixedDistanceV3> {
        self.score(codes, tokens)
    }
}
impl ExecutionMetricV3 for FixedMetricTablesV3 {
    type Score = FixedDistanceV3;
    fn score(&self, codes: &[u32], tokens: u16) -> Result<FixedDistanceV3> {
        if codes.is_empty() || self.scores.len() != self.fine_count * usize::from(tokens) {
            return Err(GemError::InvalidTokenCount);
        }
        let maxima = self
            .scores
            .chunks_exact(self.fine_count)
            .map(|row| {
                // Scan the lookup values directly: one temporary array per query
                // token would allocate in the graph search's innermost loop.
                let mut maximum: Option<Similarity> = None;
                for &code in codes {
                    let value = *row.get(code as usize).ok_or(GemError::InvalidManifest)?;
                    maximum = Some(maximum.map_or(value, |current| current.max(value)));
                }
                maximum.ok_or(GemError::InvalidTokenCount)
            })
            .collect::<Result<Vec<_>>>()?;
        fixed_distance_v1(maxima, usize::from(tokens))
    }
}
pub fn fixed_similarity_table_v3(
    query: &FixedQueryV3,
    matrix: &[Coordinate],
) -> Result<Vec<Similarity>> {
    query.validate()?;
    let d = usize::from(query.source.dimension);
    if matrix.is_empty() || !matrix.len().is_multiple_of(d) {
        return Err(GemError::InvalidManifest);
    }
    let rows = query
        .coordinates
        .par_chunks_exact(d)
        .map(|q| {
            matrix
                .chunks_exact(d)
                .map(|a| fixed_dot_v1(q, a))
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(usize::from(query.source.token_count) * (matrix.len() / d));
    for r in rows {
        out.extend(r?);
    }
    Ok(out)
}
/// Compute a candidate document's matrix inside an already parallel document loop.
/// Keep the same validation, checked dot product, and query-major output order as
/// `fixed_similarity_table_v3`, without nested tasks or per-query-row allocations.
pub fn fixed_similarity_table_serial_v3(
    query: &FixedQueryV3,
    matrix: &[Coordinate],
) -> Result<Vec<Similarity>> {
    query.validate()?;
    let d = usize::from(query.source.dimension);
    if matrix.is_empty() || !matrix.len().is_multiple_of(d) {
        return Err(GemError::InvalidManifest);
    }
    let mut out = Vec::with_capacity(usize::from(query.source.token_count) * (matrix.len() / d));
    for q in query.coordinates.chunks_exact(d) {
        for row in matrix.chunks_exact(d) {
            out.push(fixed_dot_v1(q, row)?);
        }
    }
    Ok(out)
}
pub fn select_fixed_clusters_v3(
    coarse: &[Similarity],
    query: &FixedQueryV3,
    count: usize,
) -> Result<Vec<u32>> {
    if count == 0
        || count > u32::MAX as usize
        || coarse.len() != count * usize::from(query.source.token_count)
        || query.source.params.cluster_top_t as usize > count
    {
        return Err(GemError::InvalidManifest);
    }
    let mut selected = BTreeSet::new();
    for row in coarse.chunks_exact(count) {
        let mut ids: Vec<u32> = (0..count as u32).collect();
        ids.sort_unstable_by(|&a, &b| row[b as usize].cmp(&row[a as usize]).then(a.cmp(&b)));
        selected.extend(
            ids.into_iter()
                .take(query.source.params.cluster_top_t as usize),
        );
    }
    Ok(selected.into_iter().collect())
}
pub fn replay_fixed_search_v3<A: SearchAccessV3 + ?Sized>(
    access: &A,
    entries: &[Option<u32>],
    query: &FixedQueryV3,
    tables: &FixedMetricTablesV3,
) -> Result<FixedExecutionV3> {
    query.validate()?;
    let (trace, component_usage) = replay_engine_v3(
        access,
        entries,
        &tables.selected,
        &query.source.params,
        query.source.token_count,
        tables,
    )?;
    Ok(FixedExecutionV3 {
        trace,
        component_usage,
    })
}
pub fn maxsim_fixed_matrix_v3(
    query_tokens: usize,
    token_count: usize,
    y: &[Similarity],
) -> Result<FixedDistanceV3> {
    if token_count == 0 || y.len() != query_tokens * token_count {
        return Err(GemError::InvalidTokenCount);
    }
    fixed_distance_v1(
        y.chunks_exact(token_count)
            .map(|r| r.iter().copied().max().ok_or(GemError::InvalidTokenCount))
            .collect::<Result<Vec<_>>>()?,
        query_tokens,
    )
}
pub fn rerank_fixed_matrices_v3(
    query: &FixedQueryV3,
    matrices: &[(u32, usize, Vec<Similarity>)],
) -> Result<Vec<FixedNodeDistanceV3>> {
    if matrices.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(GemError::NonCanonicalOrder);
    }
    let mut out = matrices
        .par_iter()
        .map(|(id, n, y)| {
            Ok(ExecutionNodeV3 {
                doc_id: *id,
                distance: maxsim_fixed_matrix_v3(usize::from(query.source.token_count), *n, y)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    out.sort();
    out.truncate(query.source.params.k as usize);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_scores_preserve_negative_values_duplicates_and_bounds() {
        let tables = FixedMetricTablesV3 {
            selected: vec![],
            fine_count: 4,
            scores: vec![-9, -8, -8, -20, -5, -3, -10, -30],
        };
        let expected = fixed_distance_v1([-8, -3], 2).unwrap();
        assert_eq!(tables.qch(&[0, 1, 1, 2], 2).unwrap(), expected);
        assert!(tables.qch(&[], 2).is_err());
        assert!(tables.qch(&[4], 2).is_err());
        assert!(tables.qch(&[0], 1).is_err());
        // Compare to a materialized reference over multiple lengths and orders.
        for len in 1..180 {
            let codes: Vec<u32> = (0..len).map(|i| ((i * 13 + len) % 4) as u32).collect();
            let maxima: Vec<Similarity> = tables
                .scores
                .chunks_exact(4)
                .map(|row| codes.iter().map(|&c| row[c as usize]).max().unwrap())
                .collect();
            assert_eq!(
                tables.qch(&codes, 2).unwrap(),
                fixed_distance_v1(maxima, 2).unwrap()
            );
        }
    }
    #[test]
    fn serial_document_tables_preserve_values_order_and_rejection() {
        let query = FixedQueryV3::new(gem_core::QueryV3 {
            query_id: 7,
            dimension: 4,
            token_count: 2,
            coordinates: vec![0.25, -0.5, 0.75, 0.0, -0.25, 0.5, 0.0, 1.0],
            params: gem_core::SearchParamsV3 {
                k: 1,
                rerank_k: 1,
                cluster_top_t: 1,
                ef_search: 1,
            },
        })
        .unwrap();
        for n in [1, 2, 17, 180, 257] {
            let matrix: Vec<Coordinate> = (0..n * 4)
                .map(|i| ((i * 17 % 61) as i32 - 30) as Coordinate)
                .collect();
            let serial = fixed_similarity_table_serial_v3(&query, &matrix).unwrap();
            assert_eq!(serial, fixed_similarity_table_v3(&query, &matrix).unwrap());
            assert_eq!(serial.len(), 2 * n);
            for qi in 0..2 {
                for row in 0..n {
                    assert_eq!(
                        serial[qi * n + row],
                        fixed_dot_v1(
                            &query.coordinates[qi * 4..qi * 4 + 4],
                            &matrix[row * 4..row * 4 + 4]
                        )
                        .unwrap()
                    );
                }
            }
        }
        for matrix in [vec![], vec![1; 3]] {
            assert!(fixed_similarity_table_serial_v3(&query, &matrix).is_err());
            assert!(fixed_similarity_table_v3(&query, &matrix).is_err());
        }
        let mut bad_query = query.clone();
        bad_query.coordinates[0] += 1;
        assert!(fixed_similarity_table_serial_v3(&bad_query, &[1; 4]).is_err());
        assert!(fixed_similarity_table_v3(&bad_query, &[1; 4]).is_err());
    }
    #[test]
    fn negative_maxsim_and_integer_ties() {
        let distance = maxsim_fixed_matrix_v3(2, 2, &[-9, -8, -5, -3]).unwrap();
        assert_eq!(distance.0, 2 * SCALE_SQUARED + 11);
        assert!(maxsim_fixed_matrix_v3(2, 0, &[]).is_err());
        let mut nodes = [
            ExecutionNodeV3 {
                doc_id: 9,
                distance,
            },
            ExecutionNodeV3 {
                doc_id: 1,
                distance,
            },
        ];
        nodes.sort();
        assert_eq!(nodes[0].doc_id, 1);
    }
}
