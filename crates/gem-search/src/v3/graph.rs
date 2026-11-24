//! Exact-qEMD graph construction, deterministic wavefront reduction, and repair.

use std::{
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet},
    sync::Mutex,
    time::Instant,
};

use gem_core::{GemError, GraphBuilderKindV3, Hash, RepairPolicyV3, Result, SemanticProfileV3};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use super::{
    distance::{ClosestFirstV3, DistanceDocV3},
    membership::MembershipIndexV3,
};
use crate::qemd::{QEMD_IMPLEMENTATION_ID_V3, QemdCodebookV3, histogram};

pub use super::qemd_runtime::QemdRuntimeStatsV3;
pub(super) use super::qemd_runtime::{CACHE_SHARDS, QemdEngineV3, RuntimeCountersV3};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphBuildParamsV3 {
    pub m: u16,
    pub m0: u16,
    pub ef_construction: u32,
    pub qemd_max_iterations: u32,
    pub wave_size: u32,
}

impl GraphBuildParamsV3 {
    pub fn validate(&self) -> Result<()> {
        if self.m == 0
            || self.m0 < self.m
            || self.ef_construction < u32::from(self.m)
            || self.qemd_max_iterations == 0
            || self.wave_size == 0
        {
            return Err(GemError::InvalidManifest);
        }
        Ok(())
    }

    pub fn validate_repo_profile(&self) -> Result<()> {
        self.validate()?;
        if self.m != 24
            || self.m0 != 48
            || self.ef_construction != 80
            || self.qemd_max_iterations != 1_000
        {
            return Err(GemError::InvalidManifest);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphBuildStateV3 {
    pub next_cluster: u32,
    pub inserted: Vec<bool>,
    pub adjacency: Vec<Vec<u32>>,
    pub owner_replacement_events: u64,
    pub maximum_owner_replacement_degree: u16,
    pub reciprocal_intents: u64,
    pub repair_edges: u64,
    pub repair_capacity_evictions: u64,
}

impl GraphBuildStateV3 {
    pub fn empty(document_count: usize) -> Self {
        Self {
            next_cluster: 0,
            inserted: vec![false; document_count],
            adjacency: vec![Vec::new(); document_count],
            owner_replacement_events: 0,
            maximum_owner_replacement_degree: 0,
            reciprocal_intents: 0,
            repair_edges: 0,
            repair_capacity_evictions: 0,
        }
    }

    fn validate(&self, document_count: usize, m0: u16) -> Result<()> {
        if self.inserted.len() != document_count
            || self.adjacency.len() != document_count
            || self.maximum_owner_replacement_degree > 24
        {
            return Err(GemError::InvalidManifest);
        }
        for (owner, row) in self.adjacency.iter().enumerate() {
            if row.len() > usize::from(m0)
                || row.windows(2).any(|pair| pair[0] >= pair[1])
                || row.iter().any(|&neighbor| {
                    neighbor as usize >= document_count
                        || neighbor as usize == owner
                        || !self.inserted[owner]
                        || !self.inserted[neighbor as usize]
                })
            {
                return Err(GemError::InvalidManifest);
            }
        }
        Ok(())
    }

    /// A resumable state is published only after a complete cluster. Documents
    /// marked inserted must be exactly the union of completed cluster postings.
    fn validate_boundary(&self, membership: &MembershipIndexV3) -> Result<()> {
        let completed =
            usize::try_from(self.next_cluster).map_err(|_| GemError::NumericOverflow)?;
        if completed > membership.postings.len() {
            return Err(GemError::InvalidManifest);
        }
        let mut expected = vec![false; membership.memberships.len()];
        for posting in &membership.postings[..completed] {
            for &id in posting {
                expected[id as usize] = true;
            }
        }
        if self.inserted != expected {
            return Err(GemError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphCheckpointV3 {
    pub input_digest: Hash,
    pub semantic_profile: SemanticProfileV3,
    pub params: GraphBuildParamsV3,
    pub index_builder_commit: String,
    pub builder_binary_sha256: String,
    pub qemd_implementation_id: String,
    pub coarse_count: u32,
    pub document_count: u32,
    pub state: GraphBuildStateV3,
}

impl GraphCheckpointV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &self,
        input_digest: Hash,
        semantic_profile: &SemanticProfileV3,
        params: GraphBuildParamsV3,
        index_builder_commit: &str,
        builder_binary_sha256: &str,
        coarse_count: usize,
        document_count: usize,
    ) -> Result<()> {
        semantic_profile.validate()?;
        params.validate_repo_profile()?;
        if self.input_digest != input_digest
            || &self.semantic_profile != semantic_profile
            || self.params != params
            || self.index_builder_commit != index_builder_commit
            || self.builder_binary_sha256 != builder_binary_sha256
            || self.qemd_implementation_id != QEMD_IMPLEMENTATION_ID_V3
            || self.coarse_count as usize != coarse_count
            || self.document_count as usize != document_count
            || self.state.next_cluster as usize > coarse_count
        {
            return Err(GemError::InvalidManifest);
        }
        self.state.validate(document_count, params.m0)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTimingsV3 {
    pub phase_a_search_micros: u64,
    pub phase_b_owner_micros: u64,
    pub phase_c_intents_micros: u64,
    pub phase_d_reduce_micros: u64,
    pub publish_barrier_micros: u64,
    pub graph_lock_wait_micros: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphBuildProgressV3 {
    pub cluster_id: u32,
    pub next_cluster: u32,
    pub total_clusters: u32,
    pub posting_documents: u32,
    pub elapsed_micros: u64,
    pub phase_timings: PhaseTimingsV3,
    pub qemd_runtime: QemdRuntimeStatsV3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairUnbridgedComponentV3 {
    pub cluster_id: u32,
    pub component_entry: u32,
    pub entry_reached_documents: u32,
    pub component_documents: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRunStatsV3 {
    pub capacity_exhaustions: u64,
    pub capacity_evictions: u64,
    pub unbridged_components: Vec<RepairUnbridgedComponentV3>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphBuildOutcomeV3 {
    pub state: GraphBuildStateV3,
    pub repair: RepairRunStatsV3,
}

pub(super) struct RepoGraphBuilderV3<'a> {
    pub(super) compact_codes: &'a [Vec<u32>],
    pub(super) membership: &'a MembershipIndexV3,
    pub(super) params: GraphBuildParamsV3,
    pub(super) repair_policy: RepairPolicyV3,
    pub(super) repair_stats: RepairRunStatsV3,
    pub(super) state: GraphBuildStateV3,
    pub(super) qemd: QemdEngineV3<'a>,
}

impl RepoGraphBuilderV3<'_> {
    pub(super) fn local_search(
        &self,
        snapshot: &[Vec<u32>],
        active: &[bool],
        query: u32,
        entry: u32,
    ) -> Result<Vec<DistanceDocV3>> {
        if query == entry {
            return Ok(Vec::new());
        }
        let entry_distance = DistanceDocV3::new(entry, self.qemd.distance(query, entry)?)?;
        let mut visited = HashSet::new();
        visited.insert(entry);
        let mut frontier = BinaryHeap::new();
        frontier.push(ClosestFirstV3(entry_distance));
        let mut result = BinaryHeap::new();
        result.push(entry_distance);
        let capacity = self.params.ef_construction as usize;
        while let Some(ClosestFirstV3(current)) = frontier.peek().copied() {
            // Repo construction thresholds compare scores only. Document IDs
            // still order the heaps, but must not admit an equal-score node.
            if result.len() >= capacity
                && result
                    .peek()
                    .is_some_and(|worst| current.distance() > worst.distance())
            {
                break;
            }
            frontier.pop();
            let eligible: Vec<u32> = snapshot[current.doc_id as usize]
                .iter()
                .copied()
                .filter(|&neighbor| {
                    (active.get(neighbor as usize).copied().unwrap_or(false) || neighbor == query)
                        && visited.insert(neighbor)
                })
                .collect();
            let mut scored = self.qemd.ranked_distances(query, &eligible)?;
            scored.sort();
            for candidate in scored {
                if result.len() < capacity
                    || result
                        .peek()
                        .is_some_and(|worst| candidate.distance() < worst.distance())
                {
                    frontier.push(ClosestFirstV3(candidate));
                    result.push(candidate);
                    if result.len() > capacity {
                        result.pop();
                    }
                }
            }
        }
        let mut output = result.into_vec();
        output.sort();
        Ok(output)
    }

    pub(super) fn owner_replacement(
        &self,
        snapshot: &[Vec<u32>],
        owner: u32,
        candidates: &[DistanceDocV3],
    ) -> Result<Vec<u32>> {
        let complete_new = candidates.iter().map(|candidate| candidate.doc_id);
        if self.state.inserted[owner as usize] {
            self.qemd.heuristic_neighbors(
                owner,
                snapshot[owner as usize].iter().copied().chain(complete_new),
                usize::from(self.params.m),
            )
        } else {
            self.qemd
                .heuristic_neighbors(owner, complete_new, usize::from(self.params.m))
        }
    }

    pub(super) fn reduce_recipient(
        &self,
        snapshot: &[Vec<u32>],
        owner_replacements: &BTreeMap<u32, Vec<u32>>,
        recipient: u32,
        inbound: &[(usize, u32)],
    ) -> Result<Vec<u32>> {
        let mut row = owner_replacements
            .get(&recipient)
            .cloned()
            .unwrap_or_else(|| snapshot[recipient as usize].clone());
        for &(_, inbound_owner) in inbound {
            if inbound_owner == recipient {
                return Err(GemError::InvalidManifest);
            }
            if let Err(position) = row.binary_search(&inbound_owner) {
                row.insert(position, inbound_owner);
            }
            if row.len() > usize::from(self.params.m0) {
                row = self
                    .qemd
                    .heuristic_neighbors(recipient, row, usize::from(self.params.m0))?;
            }
        }
        Ok(row)
    }

    fn apply_sequential_document(
        &mut self,
        cluster: u32,
        posting_position: usize,
        owner: u32,
        entry: u32,
        active: &mut [bool],
    ) -> Result<()> {
        active[owner as usize] = true;
        let candidates = self.local_search(&self.state.adjacency, active, owner, entry)?;
        let replacement = self.owner_replacement(&self.state.adjacency, owner, &candidates)?;
        if replacement.len() > usize::from(self.params.m) {
            return Err(GemError::InvalidManifest);
        }
        self.state.inserted[owner as usize] = true;
        self.state.owner_replacement_events = self
            .state
            .owner_replacement_events
            .checked_add(1)
            .ok_or(GemError::NumericOverflow)?;
        self.state.maximum_owner_replacement_degree = self
            .state
            .maximum_owner_replacement_degree
            .max(u16::try_from(replacement.len()).map_err(|_| GemError::NumericOverflow)?);
        self.state.adjacency[owner as usize] = replacement.clone();
        for recipient in replacement {
            self.state.reciprocal_intents = self
                .state
                .reciprocal_intents
                .checked_add(1)
                .ok_or(GemError::NumericOverflow)?;
            let inbound = [(posting_position, owner)];
            let reduced = self.reduce_recipient(
                &self.state.adjacency,
                &BTreeMap::new(),
                recipient,
                &inbound,
            )?;
            self.state.adjacency[recipient as usize] = reduced;
        }
        let _ = cluster;
        Ok(())
    }

    fn build_cluster_sequential(&mut self, cluster: u32) -> Result<PhaseTimingsV3> {
        let posting = &self.membership.postings[cluster as usize];
        let Some(&entry) = posting.first() else {
            return Ok(PhaseTimingsV3::default());
        };
        self.state.inserted[entry as usize] = true;
        let mut active = vec![false; self.compact_codes.len()];
        active[entry as usize] = true;
        let started = Instant::now();
        for (position, &owner) in posting.iter().enumerate().skip(1) {
            self.apply_sequential_document(cluster, position, owner, entry, &mut active)?;
        }
        Ok(PhaseTimingsV3 {
            phase_a_search_micros: elapsed_micros(started),
            ..PhaseTimingsV3::default()
        })
    }

    fn build_cluster_wavefront(&mut self, cluster: u32) -> Result<PhaseTimingsV3> {
        let posting = &self.membership.postings[cluster as usize];
        let Some(&entry) = posting.first() else {
            return Ok(PhaseTimingsV3::default());
        };
        self.state.inserted[entry as usize] = true;
        let mut active = vec![false; self.compact_codes.len()];
        active[entry as usize] = true;
        let mut totals = PhaseTimingsV3::default();
        let wave_size = self.params.wave_size as usize;
        for (wave_index, wave) in posting[1..].chunks(wave_size).enumerate() {
            let base_position = 1 + wave_index * wave_size;
            let snapshot = &self.state.adjacency;

            let phase_started = Instant::now();
            let searches: Vec<Result<Vec<DistanceDocV3>>> = wave
                .par_iter()
                .map(|&owner| self.local_search(snapshot, &active, owner, entry))
                .collect();
            let searches = searches.into_iter().collect::<Result<Vec<_>>>()?;
            totals.phase_a_search_micros = totals
                .phase_a_search_micros
                .checked_add(elapsed_micros(phase_started))
                .ok_or(GemError::NumericOverflow)?;

            let phase_started = Instant::now();
            let replacements: Vec<Result<(u32, Vec<u32>)>> = wave
                .par_iter()
                .copied()
                .zip(searches.par_iter())
                .map(|(owner, candidates)| {
                    Ok((owner, self.owner_replacement(snapshot, owner, candidates)?))
                })
                .collect();
            let replacements = replacements.into_iter().collect::<Result<Vec<_>>>()?;
            let owner_replacements: BTreeMap<u32, Vec<u32>> = replacements.into_iter().collect();
            if owner_replacements
                .values()
                .any(|row| row.len() > usize::from(self.params.m))
            {
                return Err(GemError::InvalidManifest);
            }
            totals.phase_b_owner_micros = totals
                .phase_b_owner_micros
                .checked_add(elapsed_micros(phase_started))
                .ok_or(GemError::NumericOverflow)?;

            let phase_started = Instant::now();
            let mut inbound = BTreeMap::<u32, Vec<(usize, u32)>>::new();
            for (offset, &owner) in wave.iter().enumerate() {
                let position = base_position + offset;
                for &recipient in &owner_replacements[&owner] {
                    inbound
                        .entry(recipient)
                        .or_default()
                        .push((position, owner));
                }
            }
            for values in inbound.values_mut() {
                values.sort_unstable_by_key(|&(position, owner)| (position, owner));
            }
            let affected: BTreeSet<u32> = owner_replacements
                .keys()
                .copied()
                .chain(inbound.keys().copied())
                .collect();
            totals.phase_c_intents_micros = totals
                .phase_c_intents_micros
                .checked_add(elapsed_micros(phase_started))
                .ok_or(GemError::NumericOverflow)?;

            let phase_started = Instant::now();
            let affected: Vec<u32> = affected.into_iter().collect();
            let rows: Vec<Result<(u32, Vec<u32>)>> = affected
                .par_iter()
                .map(|&node| {
                    let intents = inbound.get(&node).map(Vec::as_slice).unwrap_or(&[]);
                    Ok((
                        node,
                        self.reduce_recipient(snapshot, &owner_replacements, node, intents)?,
                    ))
                })
                .collect();
            let rows = rows.into_iter().collect::<Result<Vec<_>>>()?;
            totals.phase_d_reduce_micros = totals
                .phase_d_reduce_micros
                .checked_add(elapsed_micros(phase_started))
                .ok_or(GemError::NumericOverflow)?;

            let publish_started = Instant::now();
            for (node, row) in rows {
                self.state.adjacency[node as usize] = row;
            }
            for &owner in wave {
                self.state.inserted[owner as usize] = true;
                active[owner as usize] = true;
                self.state.owner_replacement_events = self
                    .state
                    .owner_replacement_events
                    .checked_add(1)
                    .ok_or(GemError::NumericOverflow)?;
                self.state.maximum_owner_replacement_degree =
                    self.state.maximum_owner_replacement_degree.max(
                        u16::try_from(owner_replacements[&owner].len())
                            .map_err(|_| GemError::NumericOverflow)?,
                    );
            }
            self.state.reciprocal_intents = self
                .state
                .reciprocal_intents
                .checked_add(
                    inbound
                        .values()
                        .map(Vec::len)
                        .sum::<usize>()
                        .try_into()
                        .map_err(|_| GemError::NumericOverflow)?,
                )
                .ok_or(GemError::NumericOverflow)?;
            totals.publish_barrier_micros = totals
                .publish_barrier_micros
                .checked_add(elapsed_micros(publish_started))
                .ok_or(GemError::NumericOverflow)?;
        }
        Ok(totals)
    }
}

fn elapsed_micros(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

#[allow(clippy::too_many_arguments)]
pub fn build_qemd_graph_v3_with_control<F, P, S>(
    compact_codes: &[Vec<u32>],
    membership: &MembershipIndexV3,
    codebook: &QemdCodebookV3,
    semantic_profile: &SemanticProfileV3,
    params: GraphBuildParamsV3,
    state: Option<GraphBuildStateV3>,
    stop_after_cluster: Option<u32>,
    mut checkpoint: F,
    mut progress: P,
    mut stop_requested: S,
) -> Result<GraphBuildOutcomeV3>
where
    F: FnMut(&GraphBuildStateV3) -> Result<()>,
    P: FnMut(GraphBuildProgressV3) -> Result<()>,
    S: FnMut() -> bool,
{
    semantic_profile.validate()?;
    let repair_policy = semantic_profile.repair_policy()?;
    params.validate_repo_profile()?;
    if semantic_profile.wave_size != params.wave_size
        || matches!(
            semantic_profile.graph_builder,
            GraphBuilderKindV3::RepoSequentialOracle
        ) && params.wave_size != 1
    {
        return Err(GemError::InvalidManifest);
    }
    codebook.validate()?;
    membership.validate(compact_codes.len(), membership.postings.len())?;
    let state = state.unwrap_or_else(|| GraphBuildStateV3::empty(compact_codes.len()));
    state.validate(compact_codes.len(), params.m0)?;
    state.validate_boundary(membership)?;
    let histograms = compact_codes
        .par_iter()
        .map(|codes| histogram(codes, codebook.fine_count))
        .collect::<Result<Vec<_>>>()?;
    let qemd = QemdEngineV3 {
        compact_codes,
        histograms,
        codebook,
        max_iterations: params.qemd_max_iterations as usize,
        cache: (0..CACHE_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect(),
        in_flight: (0..CACHE_SHARDS)
            .map(|_| Mutex::new(HashSet::new()))
            .collect(),
        counters: RuntimeCountersV3::new(),
    };
    let mut builder = RepoGraphBuilderV3 {
        compact_codes,
        membership,
        params,
        state,
        qemd,
        repair_policy,
        repair_stats: RepairRunStatsV3::default(),
    };
    let total_clusters = membership.postings.len() as u32;
    let end = stop_after_cluster
        .unwrap_or(total_clusters)
        .min(total_clusters);
    while builder.state.next_cluster < end {
        let cluster = builder.state.next_cluster;
        let started = Instant::now();
        let phase_timings = match semantic_profile.graph_builder {
            GraphBuilderKindV3::PublishedFixedGraph => return Err(GemError::InvalidManifest),
            GraphBuilderKindV3::RepoSequentialOracle => {
                builder.build_cluster_sequential(cluster)?
            }
            GraphBuilderKindV3::RepoDeterministicWavefront => {
                builder.build_cluster_wavefront(cluster)?
            }
        };
        builder.state.next_cluster = builder
            .state
            .next_cluster
            .checked_add(1)
            .ok_or(GemError::NumericOverflow)?;
        progress(GraphBuildProgressV3 {
            cluster_id: cluster,
            next_cluster: builder.state.next_cluster,
            total_clusters,
            posting_documents: u32::try_from(membership.postings[cluster as usize].len())
                .map_err(|_| GemError::NumericOverflow)?,
            elapsed_micros: elapsed_micros(started),
            phase_timings,
            qemd_runtime: builder.qemd.counters.snapshot(),
        })?;
        if builder.state.next_cluster < end && stop_requested() {
            checkpoint(&builder.state)?;
            break;
        }
    }
    if builder.state.next_cluster == total_clusters {
        // Persist the fully constructed, pre-repair graph at a valid cluster
        // boundary. If deterministic repair rejects an undefined repository
        // case, resume can retry repair without repeating all qEMD work.
        checkpoint(&builder.state)?;
        for cluster in 0..total_clusters {
            builder.repair_cluster_repo(cluster)?;
        }
    }
    builder.state.validate(compact_codes.len(), params.m0)?;
    Ok(GraphBuildOutcomeV3 {
        state: builder.state,
        repair: builder.repair_stats,
    })
}

pub fn build_qemd_graph_v3(
    compact_codes: &[Vec<u32>],
    membership: &MembershipIndexV3,
    codebook: &QemdCodebookV3,
    semantic_profile: &SemanticProfileV3,
    params: GraphBuildParamsV3,
) -> Result<GraphBuildOutcomeV3> {
    build_qemd_graph_v3_with_control(
        compact_codes,
        membership,
        codebook,
        semantic_profile,
        params,
        None,
        None,
        |_| Ok(()),
        |_| Ok(()),
        || false,
    )
}

/// Replays only the deterministic repository repair phase over a complete
/// construction-boundary state. This is intentionally separate from resume:
/// callers can diagnose a retained failed checkpoint without publishing an
/// index or weakening checkpoint provenance validation.
pub fn repair_graph_state_v3(
    compact_codes: &[Vec<u32>],
    membership: &MembershipIndexV3,
    codebook: &QemdCodebookV3,
    semantic_profile: &SemanticProfileV3,
    params: GraphBuildParamsV3,
    state: GraphBuildStateV3,
) -> Result<GraphBuildOutcomeV3> {
    semantic_profile.validate()?;
    let repair_policy = semantic_profile.repair_policy()?;
    params.validate_repo_profile()?;
    if semantic_profile.wave_size != params.wave_size
        || matches!(
            semantic_profile.graph_builder,
            GraphBuilderKindV3::RepoSequentialOracle
        ) && params.wave_size != 1
    {
        return Err(GemError::InvalidManifest);
    }
    codebook.validate()?;
    membership.validate(compact_codes.len(), membership.postings.len())?;
    state.validate(compact_codes.len(), params.m0)?;
    state.validate_boundary(membership)?;
    if state.next_cluster as usize != membership.postings.len() {
        return Err(GemError::InvalidManifest);
    }
    let histograms = compact_codes
        .par_iter()
        .map(|codes| histogram(codes, codebook.fine_count))
        .collect::<Result<Vec<_>>>()?;
    let qemd = QemdEngineV3 {
        compact_codes,
        histograms,
        codebook,
        max_iterations: params.qemd_max_iterations as usize,
        cache: (0..CACHE_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect(),
        in_flight: (0..CACHE_SHARDS)
            .map(|_| Mutex::new(HashSet::new()))
            .collect(),
        counters: RuntimeCountersV3::new(),
    };
    let mut builder = RepoGraphBuilderV3 {
        compact_codes,
        membership,
        params,
        state,
        qemd,
        repair_policy,
        repair_stats: RepairRunStatsV3::default(),
    };
    for cluster in 0..membership.postings.len() as u32 {
        builder.repair_cluster_repo(cluster)?;
    }
    builder.state.validate(compact_codes.len(), params.m0)?;
    Ok(GraphBuildOutcomeV3 {
        state: builder.state,
        repair: builder.repair_stats,
    })
}
