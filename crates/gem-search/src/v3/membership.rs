//! Deterministic repository-profile membership preprocessing and validation.

use std::collections::BTreeMap;

use gem_core::{GemError, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipIndexV3 {
    pub fine_to_coarse: Vec<u32>,
    pub memberships: Vec<Vec<u32>>,
    pub postings: Vec<Vec<u32>>,
    pub cluster_entries: Vec<Option<u32>>,
}

impl MembershipIndexV3 {
    pub fn validate(&self, document_count: usize, coarse_count: usize) -> Result<()> {
        if self.fine_to_coarse.is_empty()
            || self.memberships.len() != document_count
            || self.postings.len() != coarse_count
            || self.cluster_entries.len() != coarse_count
            || self
                .fine_to_coarse
                .iter()
                .any(|&cluster| cluster as usize >= coarse_count)
        {
            return Err(GemError::InvalidManifest);
        }
        for membership in &self.memberships {
            if membership.is_empty()
                || membership.windows(2).any(|pair| pair[0] >= pair[1])
                || membership
                    .iter()
                    .any(|&cluster| cluster as usize >= coarse_count)
            {
                return Err(GemError::NonCanonicalOrder);
            }
        }
        let mut reciprocal = vec![Vec::new(); document_count];
        for (cluster_id, posting) in self.postings.iter().enumerate() {
            if posting.windows(2).any(|pair| pair[0] <= pair[1])
                || posting
                    .iter()
                    .any(|&doc_id| doc_id as usize >= document_count)
                || self.cluster_entries[cluster_id] != posting.first().copied()
            {
                return Err(GemError::NonCanonicalOrder);
            }
            for &doc_id in posting {
                reciprocal[doc_id as usize].push(cluster_id as u32);
            }
        }
        if reciprocal != self.memberships {
            return Err(GemError::InvalidManifest);
        }
        Ok(())
    }
}

/// Reproduces the active `preprocess/tfidf_cluster.py` path: normalized TF,
/// `ln(N/df)`, fixed top-20 distinct memberships, explicit score/cluster ties,
/// and document-descending postings.
pub fn build_repo_memberships_v3(
    compact_codes: &[Vec<u32>],
    fine_to_coarse: Vec<u32>,
    coarse_count: usize,
) -> Result<MembershipIndexV3> {
    if compact_codes.is_empty() || fine_to_coarse.is_empty() || coarse_count == 0 {
        return Err(GemError::InvalidManifest);
    }
    if fine_to_coarse
        .iter()
        .any(|&cluster| cluster as usize >= coarse_count)
    {
        return Err(GemError::InvalidManifest);
    }

    let mut document_frequency = vec![0u64; coarse_count];
    let mut counts_by_document = Vec::with_capacity(compact_codes.len());
    for codes in compact_codes {
        if codes.is_empty() {
            return Err(GemError::InvalidTokenCount);
        }
        let mut counts = BTreeMap::<u32, u32>::new();
        for &code in codes {
            let cluster = *fine_to_coarse
                .get(code as usize)
                .ok_or(GemError::InvalidManifest)?;
            let count = counts.entry(cluster).or_default();
            *count = count.checked_add(1).ok_or(GemError::NumericOverflow)?;
        }
        for &cluster in counts.keys() {
            document_frequency[cluster as usize] = document_frequency[cluster as usize]
                .checked_add(1)
                .ok_or(GemError::NumericOverflow)?;
        }
        counts_by_document.push(counts);
    }

    let document_count = compact_codes.len() as f64;
    let mut memberships = Vec::with_capacity(compact_codes.len());
    let mut postings = vec![Vec::new(); coarse_count];
    for (doc_id, (codes, counts)) in compact_codes.iter().zip(counts_by_document).enumerate() {
        let denominator = codes.len() as f64;
        let mut scored: Vec<(u32, f64)> = counts
            .into_iter()
            .map(|(cluster, count)| {
                let frequency = document_frequency[cluster as usize] as f64;
                (
                    cluster,
                    (f64::from(count) / denominator) * (document_count / frequency).ln(),
                )
            })
            .collect();
        if scored.iter().any(|row| !row.1.is_finite()) {
            return Err(GemError::NonFinite);
        }
        scored.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        scored.truncate(20);
        let mut selected: Vec<u32> = scored.into_iter().map(|row| row.0).collect();
        selected.sort_unstable();
        let doc_id = u32::try_from(doc_id).map_err(|_| GemError::NumericOverflow)?;
        for &cluster in &selected {
            postings[cluster as usize].push(doc_id);
        }
        memberships.push(selected);
    }
    for posting in &mut postings {
        posting.reverse();
    }
    let cluster_entries = postings
        .iter()
        .map(|posting| posting.first().copied())
        .collect();
    let output = MembershipIndexV3 {
        fine_to_coarse,
        memberships,
        postings,
        cluster_entries,
    };
    output.validate(compact_codes.len(), coarse_count)?;
    Ok(output)
}
