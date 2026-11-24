//! One execution state machine. Heap ordering and admission comparisons are separate.
use super::{ComponentUsageV3, SearchAccessV3};
use gem_core::{GemError, Result, SearchParamsV3};
use serde::{Deserialize, Serialize};
use std::{
    cmp::{Ordering, Reverse},
    collections::{BTreeMap, BTreeSet, BinaryHeap},
};

pub(crate) trait ExecutionScoreV3: Copy + Ord {
    fn strictly_less(self, other: Self) -> bool;
    fn strictly_greater(self, other: Self) -> bool;
}
pub(crate) trait ExecutionMetricV3 {
    type Score: ExecutionScoreV3;
    fn score(&self, codes: &[u32], tokens: u16) -> Result<Self::Score>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionNodeV3<S> {
    pub doc_id: u32,
    pub distance: S,
}
impl<S: Ord> Ord for ExecutionNodeV3<S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.distance
            .cmp(&other.distance)
            .then_with(|| self.doc_id.cmp(&other.doc_id))
    }
}
impl<S: Ord> PartialOrd for ExecutionNodeV3<S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStopV3<S> {
    pub pass: u32,
    pub cluster_id: u32,
    pub entry_doc_id: u32,
    pub doc_id: u32,
    pub distance: S,
    pub lower_bound: S,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTraceV3<S> {
    pub selected_clusters: Vec<u32>,
    pub queue_entries: Vec<(u32, u32)>,
    pub compared: Vec<ExecutionNodeV3<S>>,
    pub expanded: Vec<u32>,
    pub membership_examined: Vec<u32>,
    pub cluster_pruned: Vec<u32>,
    pub retained: Vec<ExecutionNodeV3<S>>,
    pub candidates: Vec<ExecutionNodeV3<S>>,
    pub early_stops: Vec<ExecutionStopV3<S>>,
}
struct Queue<S: Ord> {
    cluster: u32,
    entry: u32,
    stopped: bool,
    frontier: BinaryHeap<Reverse<ExecutionNodeV3<S>>>,
}
pub(crate) fn replay_engine_v3<A: SearchAccessV3 + ?Sized, M: ExecutionMetricV3>(
    access: &A,
    entries: &[Option<u32>],
    selected: &[u32],
    params: &SearchParamsV3,
    tokens: u16,
    metric: &M,
) -> Result<(ExecutionTraceV3<M::Score>, ComponentUsageV3)> {
    params.validate()?;
    if selected.windows(2).any(|w| w[0] >= w[1])
        || selected.iter().any(|&c| c as usize >= entries.len())
        || tokens == 0
    {
        return Err(GemError::InvalidManifest);
    }
    let mut usage = ComponentUsageV3::default();
    let mut owners = BTreeMap::new();
    for &cluster in selected {
        if let Some(entry) = entries[cluster as usize] {
            owners.entry(entry).or_insert(cluster);
        }
    }
    let mut queue_entries: Vec<_> = owners.into_iter().map(|(entry, c)| (c, entry)).collect();
    queue_entries.sort_unstable();
    let mut trace = ExecutionTraceV3 {
        selected_clusters: selected.to_vec(),
        queue_entries,
        compared: vec![],
        expanded: vec![],
        membership_examined: vec![],
        cluster_pruned: vec![],
        retained: vec![],
        candidates: vec![],
        early_stops: vec![],
    };
    if trace.queue_entries.is_empty() {
        return Ok((trace, usage));
    }
    let mut visited = BTreeSet::new();
    let mut results = BinaryHeap::new();
    let mut queues = vec![];
    let mut initial: Option<ExecutionNodeV3<M::Score>> = None;
    for &(cluster, entry) in &trace.queue_entries {
        access.metadata(entry)?;
        usage.membership.insert(entry);
        if access.membership(entry)?.binary_search(&cluster).is_err() {
            return Err(GemError::InvalidManifest);
        }
        usage.codes.insert(entry);
        let node = ExecutionNodeV3 {
            doc_id: entry,
            distance: metric.score(access.codes(entry)?, tokens)?,
        };
        initial = Some(initial.map_or(node, |current| current.max(node)));
        if visited.insert(entry) {
            trace.compared.push(node);
            results.push(node);
        }
        let mut frontier = BinaryHeap::new();
        frontier.push(Reverse(node));
        queues.push(Queue {
            cluster,
            entry,
            stopped: false,
            frontier,
        });
    }
    // All initial entries survive even if their count exceeds ef; first admission tightens.
    let mut lower = initial.ok_or(GemError::InvalidManifest)?;
    let mut pass = 0u32;
    loop {
        let mut popped = false;
        for queue in &mut queues {
            if queue.stopped {
                continue;
            }
            let Some(Reverse(head)) = queue.frontier.peek().copied() else {
                queue.stopped = true;
                continue;
            };
            if head.distance.strictly_greater(lower.distance) {
                queue.stopped = true;
                trace.early_stops.push(ExecutionStopV3 {
                    pass,
                    cluster_id: queue.cluster,
                    entry_doc_id: queue.entry,
                    doc_id: head.doc_id,
                    distance: head.distance,
                    lower_bound: lower.distance,
                });
                continue;
            }
            let current = queue.frontier.pop().ok_or(GemError::InvalidManifest)?.0;
            popped = true;
            trace.expanded.push(current.doc_id);
            usage.adjacency.insert(current.doc_id);
            for &neighbor in access.adjacency(current.doc_id)? {
                trace.membership_examined.push(neighbor);
                access.metadata(neighbor)?;
                usage.membership.insert(neighbor);
                if !access
                    .membership(neighbor)?
                    .iter()
                    .any(|c| selected.binary_search(c).is_ok())
                {
                    trace.cluster_pruned.push(neighbor);
                    continue;
                }
                if !visited.insert(neighbor) {
                    continue;
                }
                usage.codes.insert(neighbor);
                let node = ExecutionNodeV3 {
                    doc_id: neighbor,
                    distance: metric.score(access.codes(neighbor)?, tokens)?,
                };
                trace.compared.push(node);
                if results.len() < params.ef_search as usize
                    || node.distance.strictly_less(lower.distance)
                {
                    queue.frontier.push(Reverse(node));
                    results.push(node);
                    while results.len() > params.ef_search as usize {
                        results.pop();
                    }
                    lower = results.peek().copied().ok_or(GemError::InvalidManifest)?;
                }
            }
        }
        if !popped {
            break;
        }
        pass = pass.checked_add(1).ok_or(GemError::NumericOverflow)?;
    }
    trace.retained = results.into_iter().collect();
    trace.retained.sort();
    trace.candidates = trace
        .retained
        .iter()
        .take(params.rerank_k as usize)
        .copied()
        .collect();
    usage.raw.extend(trace.candidates.iter().map(|x| x.doc_id));
    Ok((trace, usage))
}

impl ExecutionScoreV3 for gem_core::FixedDistanceV3 {
    fn strictly_less(self, other: Self) -> bool {
        self < other
    }
    fn strictly_greater(self, other: Self) -> bool {
        self > other
    }
}
