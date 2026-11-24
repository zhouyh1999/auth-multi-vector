//! Optional shortcut-edge injection kept separate from the repo-default profile.

use std::collections::BTreeMap;

use gem_core::{GemError, QueryV3, Result};
use serde::{Deserialize, Serialize};

use super::search::SearchIndexV3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutTrainingPairV3 {
    pub query_id: u64,
    pub positive_doc_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutEdgeV3 {
    pub query_id: u64,
    pub positive_doc_id: u32,
    pub approximate_top1_doc_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutInjectionReportV3 {
    pub query_count: u32,
    pub positive_pair_count: u32,
    pub injected_undirected_edges: u32,
    pub positive_already_in_candidates: u32,
    pub existing_edges: u32,
    pub degree_capacity_rejections: u32,
    pub injected_edges: Vec<ShortcutEdgeV3>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutInjectionV3 {
    pub adjacency: Vec<Vec<u32>>,
    pub report: ShortcutInjectionReportV3,
}

/// Retains the released repository's shortcut construction as an explicit,
/// callable layer without enabling it in the default V3 semantic profile.
/// The returned adjacency is deliberately not relabeled as a repo-default
/// `SearchIndexV3`; a future shortcut profile must bind its training source.
pub fn inject_shortcuts_v3(
    index: &SearchIndexV3,
    queries: &[QueryV3],
    pairs: &[ShortcutTrainingPairV3],
    degree_capacity: u16,
) -> Result<ShortcutInjectionV3> {
    index.validate_policy()?;
    if queries.is_empty()
        || degree_capacity == 0
        || degree_capacity > index.graph_params.m0
        || queries
            .windows(2)
            .any(|window| window[0].query_id >= window[1].query_id)
        || pairs.windows(2).any(|window| {
            (window[0].query_id, window[0].positive_doc_id)
                >= (window[1].query_id, window[1].positive_doc_id)
        })
    {
        return Err(GemError::NonCanonicalOrder);
    }
    let query_positions: BTreeMap<u64, usize> = queries
        .iter()
        .enumerate()
        .map(|(position, query)| (query.query_id, position))
        .collect();
    if query_positions.len() != queries.len() {
        return Err(GemError::DuplicateId);
    }
    let mut searches = Vec::with_capacity(queries.len());
    for query in queries {
        let trace = index.search(query)?;
        let candidates: Vec<u32> = trace.candidates.iter().map(|row| row.doc_id).collect();
        let top1 = *candidates.first().ok_or(GemError::InvalidManifest)?;
        searches.push((top1, candidates));
    }

    let mut adjacency: Vec<Vec<u32>> = index
        .documents
        .iter()
        .map(|document| document.adjacency.clone())
        .collect();
    let mut report = ShortcutInjectionReportV3 {
        query_count: u32::try_from(queries.len()).map_err(|_| GemError::NumericOverflow)?,
        positive_pair_count: u32::try_from(pairs.len()).map_err(|_| GemError::NumericOverflow)?,
        injected_undirected_edges: 0,
        positive_already_in_candidates: 0,
        existing_edges: 0,
        degree_capacity_rejections: 0,
        injected_edges: Vec::new(),
    };
    for pair in pairs {
        let position = *query_positions
            .get(&pair.query_id)
            .ok_or(GemError::InvalidManifest)?;
        if pair.positive_doc_id as usize >= adjacency.len() {
            return Err(GemError::InvalidManifest);
        }
        let (top1, candidates) = &searches[position];
        if candidates.binary_search(&pair.positive_doc_id).is_ok()
            || candidates.contains(&pair.positive_doc_id)
        {
            report.positive_already_in_candidates = report
                .positive_already_in_candidates
                .checked_add(1)
                .ok_or(GemError::NumericOverflow)?;
            continue;
        }
        if *top1 == pair.positive_doc_id {
            report.positive_already_in_candidates = report
                .positive_already_in_candidates
                .checked_add(1)
                .ok_or(GemError::NumericOverflow)?;
            continue;
        }
        if adjacency[*top1 as usize]
            .binary_search(&pair.positive_doc_id)
            .is_ok()
            || adjacency[pair.positive_doc_id as usize]
                .binary_search(top1)
                .is_ok()
        {
            report.existing_edges = report
                .existing_edges
                .checked_add(1)
                .ok_or(GemError::NumericOverflow)?;
            continue;
        }
        if adjacency[*top1 as usize].len() >= usize::from(degree_capacity)
            || adjacency[pair.positive_doc_id as usize].len() >= usize::from(degree_capacity)
        {
            report.degree_capacity_rejections = report
                .degree_capacity_rejections
                .checked_add(1)
                .ok_or(GemError::NumericOverflow)?;
            continue;
        }
        let position = adjacency[*top1 as usize]
            .binary_search(&pair.positive_doc_id)
            .unwrap_err();
        adjacency[*top1 as usize].insert(position, pair.positive_doc_id);
        let position = adjacency[pair.positive_doc_id as usize]
            .binary_search(top1)
            .unwrap_err();
        adjacency[pair.positive_doc_id as usize].insert(position, *top1);
        report.injected_undirected_edges = report
            .injected_undirected_edges
            .checked_add(1)
            .ok_or(GemError::NumericOverflow)?;
        report.injected_edges.push(ShortcutEdgeV3 {
            query_id: pair.query_id,
            positive_doc_id: pair.positive_doc_id,
            approximate_top1_doc_id: *top1,
        });
    }
    Ok(ShortcutInjectionV3 { adjacency, report })
}
