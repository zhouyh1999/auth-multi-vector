//! Canonical qEMD pair cache, solver telemetry, and repository diversity selection.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering as AtomicOrdering},
    },
    time::Instant,
};

use gem_core::{GemError, Result};
use serde::{Deserialize, Serialize};

use super::distance::DistanceDocV3;
use crate::qemd::QemdCodebookV3;

pub(super) const CACHE_SHARDS: usize = 256;
const CACHE_SHARD_LIMIT: usize = 2_097_152;
const MAX_SOLVER_CONCURRENCY_BUCKETS: usize = 129;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QemdRuntimeStatsV3 {
    pub distance_requests: u64,
    pub cache_hits: u64,
    pub cache_evictions: u64,
    pub solver_calls: u64,
    pub transport_cells: u64,
    pub in_flight_duplicate_pair_solves: u64,
    pub maximum_solver_concurrency: u64,
    pub solver_concurrency_histogram: Vec<u64>,
    pub cache_lock_wait_nanos: u64,
}

pub(super) struct RuntimeCountersV3 {
    distance_requests: AtomicU64,
    cache_hits: AtomicU64,
    cache_evictions: AtomicU64,
    solver_calls: AtomicU64,
    transport_cells: AtomicU64,
    in_flight_duplicate_pair_solves: AtomicU64,
    active_solvers: AtomicU64,
    maximum_solver_concurrency: AtomicU64,
    solver_concurrency_histogram: Vec<AtomicU64>,
    cache_lock_wait_nanos: AtomicU64,
}

impl RuntimeCountersV3 {
    pub(super) fn new() -> Self {
        Self {
            distance_requests: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_evictions: AtomicU64::new(0),
            solver_calls: AtomicU64::new(0),
            transport_cells: AtomicU64::new(0),
            in_flight_duplicate_pair_solves: AtomicU64::new(0),
            active_solvers: AtomicU64::new(0),
            maximum_solver_concurrency: AtomicU64::new(0),
            solver_concurrency_histogram: (0..MAX_SOLVER_CONCURRENCY_BUCKETS)
                .map(|_| AtomicU64::new(0))
                .collect(),
            cache_lock_wait_nanos: AtomicU64::new(0),
        }
    }

    pub(super) fn snapshot(&self) -> QemdRuntimeStatsV3 {
        QemdRuntimeStatsV3 {
            distance_requests: self.distance_requests.load(AtomicOrdering::Relaxed),
            cache_hits: self.cache_hits.load(AtomicOrdering::Relaxed),
            cache_evictions: self.cache_evictions.load(AtomicOrdering::Relaxed),
            solver_calls: self.solver_calls.load(AtomicOrdering::Relaxed),
            transport_cells: self.transport_cells.load(AtomicOrdering::Relaxed),
            in_flight_duplicate_pair_solves: self
                .in_flight_duplicate_pair_solves
                .load(AtomicOrdering::Relaxed),
            maximum_solver_concurrency: self
                .maximum_solver_concurrency
                .load(AtomicOrdering::Relaxed),
            solver_concurrency_histogram: self
                .solver_concurrency_histogram
                .iter()
                .map(|value| value.load(AtomicOrdering::Relaxed))
                .collect(),
            cache_lock_wait_nanos: self.cache_lock_wait_nanos.load(AtomicOrdering::Relaxed),
        }
    }
}

pub(super) struct QemdEngineV3<'a> {
    pub(super) compact_codes: &'a [Vec<u32>],
    pub(super) histograms: Vec<Vec<(u32, i64)>>,
    pub(super) codebook: &'a QemdCodebookV3,
    pub(super) max_iterations: usize,
    pub(super) cache: Vec<Mutex<HashMap<(u32, u32), f32>>>,
    pub(super) in_flight: Vec<Mutex<HashSet<(u32, u32)>>>,
    pub(super) counters: RuntimeCountersV3,
}

impl QemdEngineV3<'_> {
    pub(super) fn distance(&self, left: u32, right: u32) -> Result<f32> {
        self.counters
            .distance_requests
            .fetch_add(1, AtomicOrdering::Relaxed);
        let key = if left <= right {
            (left, right)
        } else {
            (right, left)
        };
        // Floating-point transport is not bitwise invariant under transposing
        // its inputs. Solve in the same canonical direction as the cache key,
        // including cold misses, concurrent duplicate solves and resume.
        // This retains one cache entry per pair and the existing hit rate.
        let (left, right) = key;
        let shard = ((key.0 as usize).wrapping_mul(65_537) ^ key.1 as usize) % CACHE_SHARDS;
        let lock_started = Instant::now();
        let cached = self.cache[shard]
            .lock()
            .map_err(|_| GemError::Serialization("V3 qEMD cache mutex poisoned".into()))?
            .get(&key)
            .copied();
        self.counters.cache_lock_wait_nanos.fetch_add(
            lock_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
            AtomicOrdering::Relaxed,
        );
        if let Some(distance) = cached {
            self.counters
                .cache_hits
                .fetch_add(1, AtomicOrdering::Relaxed);
            return Ok(distance);
        }

        let duplicate = {
            let mut in_flight = self.in_flight[shard]
                .lock()
                .map_err(|_| GemError::Serialization("V3 qEMD in-flight mutex poisoned".into()))?;
            !in_flight.insert(key)
        };
        if duplicate {
            self.counters
                .in_flight_duplicate_pair_solves
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        let active = self
            .counters
            .active_solvers
            .fetch_add(1, AtomicOrdering::Relaxed)
            + 1;
        self.counters
            .maximum_solver_concurrency
            .fetch_max(active, AtomicOrdering::Relaxed);
        let bucket = usize::try_from(active)
            .unwrap_or(usize::MAX)
            .min(MAX_SOLVER_CONCURRENCY_BUCKETS - 1);
        self.counters.solver_concurrency_histogram[bucket].fetch_add(1, AtomicOrdering::Relaxed);
        self.counters
            .solver_calls
            .fetch_add(1, AtomicOrdering::Relaxed);
        let cells = self.histograms[left as usize]
            .len()
            .checked_mul(self.histograms[right as usize].len())
            .ok_or(GemError::NumericOverflow)?;
        self.counters
            .transport_cells
            .fetch_add(cells as u64, AtomicOrdering::Relaxed);
        let distance = self.codebook.distance_histograms_with_limit(
            &self.histograms[left as usize],
            self.compact_codes[left as usize].len(),
            &self.histograms[right as usize],
            self.compact_codes[right as usize].len(),
            self.max_iterations,
        );
        self.counters
            .active_solvers
            .fetch_sub(1, AtomicOrdering::Relaxed);
        self.in_flight[shard]
            .lock()
            .map_err(|_| GemError::Serialization("V3 qEMD in-flight mutex poisoned".into()))?
            .remove(&key);
        let distance = distance?;

        let lock_started = Instant::now();
        let mut cache = self.cache[shard]
            .lock()
            .map_err(|_| GemError::Serialization("V3 qEMD cache mutex poisoned".into()))?;
        self.counters.cache_lock_wait_nanos.fetch_add(
            lock_started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
            AtomicOrdering::Relaxed,
        );
        if cache.len() >= CACHE_SHARD_LIMIT && !cache.contains_key(&key) {
            cache.clear();
            self.counters
                .cache_evictions
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
        cache.entry(key).or_insert(distance);
        Ok(distance)
    }

    pub(super) fn ranked_distances(
        &self,
        owner: u32,
        candidates: &[u32],
    ) -> Result<Vec<DistanceDocV3>> {
        candidates
            .iter()
            .map(|&candidate| DistanceDocV3::new(candidate, self.distance(owner, candidate)?))
            .collect()
    }

    pub(super) fn heuristic_neighbors(
        &self,
        owner: u32,
        candidates: impl IntoIterator<Item = u32>,
        limit: usize,
    ) -> Result<Vec<u32>> {
        let unique: BTreeSet<u32> = candidates
            .into_iter()
            .filter(|&candidate| candidate != owner)
            .collect();
        let ids: Vec<u32> = unique.into_iter().collect();
        if ids.len() < limit {
            return Ok(ids);
        }
        let mut ranked = self.ranked_distances(owner, &ids)?;
        ranked.sort();
        let mut selected = Vec::new();
        for candidate in ranked {
            if selected.len() >= limit {
                break;
            }
            let mut accepted = true;
            for &previous in &selected {
                if self.distance(previous, candidate.doc_id)? < candidate.distance() {
                    accepted = false;
                    break;
                }
            }
            if accepted {
                selected.push(candidate.doc_id);
            }
        }
        selected.sort_unstable();
        Ok(selected)
    }
}
