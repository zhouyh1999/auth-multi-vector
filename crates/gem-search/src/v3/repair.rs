//! Directed connectivity repair with separate strict and reachability-safe policies.

use std::{
    cmp::Ordering,
    collections::{BTreeSet, VecDeque},
};

use gem_core::{GemError, RepairPolicyV3, Result};

use super::graph::{RepairUnbridgedComponentV3, RepoGraphBuilderV3};

impl RepoGraphBuilderV3<'_> {
    pub(super) fn bfs_component(
        &self,
        cluster: u32,
        start: u32,
        marked: &mut BTreeSet<u32>,
    ) -> Vec<u32> {
        let mut queue = VecDeque::new();
        let mut order = Vec::new();
        if marked.insert(start) {
            queue.push_back(start);
        }
        while let Some(owner) = queue.pop_front() {
            order.push(owner);
            for &neighbor in &self.state.adjacency[owner as usize] {
                if self.membership.memberships[neighbor as usize]
                    .binary_search(&cluster)
                    .is_ok()
                    && marked.insert(neighbor)
                {
                    queue.push_back(neighbor);
                }
            }
        }
        order
    }

    pub(super) fn reachable_set_skipping(
        &self,
        cluster: u32,
        entry: u32,
        skipped_edge: Option<(u32, u32)>,
    ) -> BTreeSet<u32> {
        let mut reached = BTreeSet::from([entry]);
        let mut queue = VecDeque::from([entry]);
        while let Some(owner) = queue.pop_front() {
            for &neighbor in &self.state.adjacency[owner as usize] {
                if skipped_edge == Some((owner, neighbor)) {
                    continue;
                }
                if self.membership.memberships[neighbor as usize]
                    .binary_search(&cluster)
                    .is_ok()
                    && reached.insert(neighbor)
                {
                    queue.push_back(neighbor);
                }
            }
        }
        reached
    }

    fn repair_eviction_preserves_reachability(&self, owner: u32, neighbor: u32) -> bool {
        let owner_memberships = &self.membership.memberships[owner as usize];
        let neighbor_memberships = &self.membership.memberships[neighbor as usize];
        let mut owner_cursor = 0usize;
        let mut neighbor_cursor = 0usize;
        while owner_cursor < owner_memberships.len() && neighbor_cursor < neighbor_memberships.len()
        {
            match owner_memberships[owner_cursor].cmp(&neighbor_memberships[neighbor_cursor]) {
                Ordering::Less => owner_cursor += 1,
                Ordering::Greater => neighbor_cursor += 1,
                Ordering::Equal => {
                    let cluster = owner_memberships[owner_cursor];
                    let Some(entry) = self.membership.cluster_entries[cluster as usize] else {
                        return false;
                    };
                    let before = self.reachable_set_skipping(cluster, entry, None);
                    if before.contains(&owner)
                        && before
                            != self.reachable_set_skipping(cluster, entry, Some((owner, neighbor)))
                    {
                        return false;
                    }
                    owner_cursor += 1;
                    neighbor_cursor += 1;
                }
            }
        }
        true
    }

    pub(super) fn repair_cluster_repo(&mut self, cluster: u32) -> Result<()> {
        let posting = &self.membership.postings[cluster as usize];
        let Some(&entry) = posting.first() else {
            return Ok(());
        };
        if posting.len() <= 1 {
            return Ok(());
        }
        let mut marked = BTreeSet::new();
        let mut reached_order = self.bfs_component(cluster, entry, &mut marked);
        let mut left_cursor = 0usize;
        for &right in posting.iter().skip(1) {
            if marked.contains(&right) {
                continue;
            }
            while left_cursor < reached_order.len()
                && self.state.adjacency[reached_order[left_cursor] as usize].len()
                    >= usize::from(self.params.m0)
            {
                left_cursor += 1;
            }
            let reached_before_component = marked.len();
            let left = if let Some(&left) = reached_order.get(left_cursor) {
                Some(left)
            } else {
                self.repair_stats.capacity_exhaustions = self
                    .repair_stats
                    .capacity_exhaustions
                    .checked_add(1)
                    .ok_or(GemError::NumericOverflow)?;
                match self.repair_policy {
                    RepairPolicyV3::RepoFaithful => None,
                    RepairPolicyV3::ReachabilitySafeExtension => {
                        let mut replacement = None;
                        for &candidate in &reached_order {
                            for &neighbor in &self.state.adjacency[candidate as usize] {
                                if self.repair_eviction_preserves_reachability(candidate, neighbor)
                                {
                                    replacement = Some((candidate, neighbor));
                                    break;
                                }
                            }
                            if replacement.is_some() {
                                break;
                            }
                        }
                        let (candidate, evicted) = replacement.ok_or_else(|| {
                            GemError::Serialization(format!(
                                "reachability-safe repair has no safe capacity cluster={cluster} reached={} posting={}",
                                marked.len(),
                                posting.len()
                            ))
                        })?;
                        let row = &mut self.state.adjacency[candidate as usize];
                        let position = row
                            .binary_search(&evicted)
                            .map_err(|_| GemError::InvalidManifest)?;
                        row.remove(position);
                        self.state.repair_capacity_evictions = self
                            .state
                            .repair_capacity_evictions
                            .checked_add(1)
                            .ok_or(GemError::NumericOverflow)?;
                        self.repair_stats.capacity_evictions = self
                            .repair_stats
                            .capacity_evictions
                            .checked_add(1)
                            .ok_or(GemError::NumericOverflow)?;
                        Some(candidate)
                    }
                }
            };
            if let Some(left) = left {
                let left_row = &mut self.state.adjacency[left as usize];
                if let Err(position) = left_row.binary_search(&right) {
                    left_row.insert(position, right);
                }
                let right_row = &mut self.state.adjacency[right as usize];
                if right_row.len() < usize::from(self.params.m0)
                    && let Err(position) = right_row.binary_search(&left)
                {
                    right_row.insert(position, left);
                }
                self.state.repair_edges = self
                    .state
                    .repair_edges
                    .checked_add(1)
                    .ok_or(GemError::NumericOverflow)?;
            }
            let component = self.bfs_component(cluster, right, &mut marked);
            if left.is_none() {
                self.repair_stats
                    .unbridged_components
                    .push(RepairUnbridgedComponentV3 {
                        cluster_id: cluster,
                        component_entry: right,
                        entry_reached_documents: u32::try_from(reached_before_component)
                            .map_err(|_| GemError::NumericOverflow)?,
                        component_documents: u32::try_from(component.len())
                            .map_err(|_| GemError::NumericOverflow)?,
                    });
            }
            reached_order.extend(component);
        }
        if marked.len() != posting.len() {
            return Err(GemError::Serialization(format!(
                "repo directed repair failed cluster={cluster} reached={} posting={}",
                marked.len(),
                posting.len()
            )));
        }
        Ok(())
    }
}
