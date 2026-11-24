//! Exact qEMD distance computation and its independent Rust parity oracle.

use std::cell::RefCell;

#[cfg(not(feature = "lemon-qemd"))]
use std::collections::VecDeque;

use gem_core::{GemError, Result, strict_dot_f32};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "lemon-qemd")]
pub const QEMD_IMPLEMENTATION_ID_V3: &str = "gem-lemon-network-simplex-direct-codebook-v3";
#[cfg(not(feature = "lemon-qemd"))]
pub const QEMD_IMPLEMENTATION_ID_V3: &str = "rust-deterministic-network-simplex-oracle-v3";

/// Exact qEMD codebook shared by the V3 sequential oracle and deterministic
/// wavefront builder.
///
/// With the default feature this dispatches to the checked LEMON
/// `NetworkSimplex` adapter. The no-default build retains the independent,
/// deterministic Rust network-simplex oracle used by parity tests.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QemdCodebookV3 {
    pub fine_count: u32,
    pub costs: Vec<f32>,
}

impl QemdCodebookV3 {
    pub fn from_centroids(fine_centroids: &[f32], dimension: usize) -> Result<Self> {
        if dimension == 0
            || fine_centroids.is_empty()
            || !fine_centroids.len().is_multiple_of(dimension)
        {
            return Err(GemError::InvalidDimension {
                expected: dimension,
                actual: fine_centroids.len(),
            });
        }
        let fine_count = fine_centroids.len() / dimension;
        let rows: Vec<Result<Vec<f32>>> = fine_centroids
            .par_chunks_exact(dimension)
            .map(|left| {
                fine_centroids
                    .chunks_exact(dimension)
                    .map(|right| {
                        let cost = 1.0f32 - strict_dot_f32(left, right)?;
                        if !cost.is_finite() {
                            return Err(GemError::NonFinite);
                        }
                        Ok(cost)
                    })
                    .collect()
            })
            .collect();
        let mut costs = Vec::with_capacity(
            fine_count
                .checked_mul(fine_count)
                .ok_or(GemError::NumericOverflow)?,
        );
        for row in rows {
            costs.extend(row?);
        }
        Ok(Self {
            fine_count: u32::try_from(fine_count).map_err(|_| GemError::NumericOverflow)?,
            costs,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let count = self.fine_count as usize;
        if count == 0
            || self.costs.len() != count.checked_mul(count).ok_or(GemError::NumericOverflow)?
            || self.costs.iter().any(|value| !value.is_finite())
        {
            return Err(GemError::InvalidManifest);
        }
        Ok(())
    }

    pub fn ground_cost(&self, left: u32, right: u32) -> Result<f32> {
        let count = self.fine_count as usize;
        let position = (left as usize)
            .checked_mul(count)
            .and_then(|start| start.checked_add(right as usize))
            .ok_or(GemError::NumericOverflow)?;
        self.costs
            .get(position)
            .copied()
            .ok_or(GemError::InvalidManifest)
    }

    pub fn distance(&self, left: &[u32], right: &[u32]) -> Result<f32> {
        self.distance_with_limit(left, right, 1_000)
    }

    pub fn distance_with_limit(
        &self,
        left: &[u32],
        right: &[u32],
        max_iterations: usize,
    ) -> Result<f32> {
        if left.is_empty() || right.is_empty() || max_iterations == 0 {
            return Err(GemError::InvalidTokenCount);
        }
        let left_histogram = histogram(left, self.fine_count)?;
        let right_histogram = histogram(right, self.fine_count)?;
        self.distance_histograms_with_limit(
            &left_histogram,
            left.len(),
            &right_histogram,
            right.len(),
            max_iterations,
        )
    }

    pub(crate) fn distance_histograms_with_limit(
        &self,
        left_histogram: &[(u32, i64)],
        left_len: usize,
        right_histogram: &[(u32, i64)],
        right_len: usize,
        max_iterations: usize,
    ) -> Result<f32> {
        if left_len == 0 || right_len == 0 || max_iterations == 0 {
            return Err(GemError::InvalidTokenCount);
        }
        #[cfg(feature = "lemon-qemd")]
        {
            self.distance_histograms_lemon_with_limit(
                left_histogram,
                left_len,
                right_histogram,
                right_len,
                max_iterations,
            )
        }
        #[cfg(not(feature = "lemon-qemd"))]
        {
            self.distance_histograms_rust_with_limit(
                left_histogram,
                left_len,
                right_histogram,
                right_len,
                max_iterations,
            )
        }
    }

    #[cfg(not(feature = "lemon-qemd"))]
    fn distance_histograms_rust_with_limit(
        &self,
        left_histogram: &[(u32, i64)],
        left_len: usize,
        right_histogram: &[(u32, i64)],
        right_len: usize,
        max_iterations: usize,
    ) -> Result<f32> {
        let common_mass = lcm_i64(left_len as i64, right_len as i64)?;
        // Move the scratch buffer out of thread-local storage while solving.
        // A nested Rayon join may execute another qEMD task on this worker;
        // keeping a RefCell borrow live across that join would reject a valid
        // re-entrant call. A small per-thread stack preserves reuse and gives
        // nested work an independent buffer.
        let mut workspace = TRANSPORT_WORKSPACES
            .with(|workspaces| workspaces.borrow_mut().pop().unwrap_or_default());
        let total = workspace.solve(
            self,
            left_histogram,
            left_len,
            right_histogram,
            right_len,
            common_mass,
            max_iterations,
        );
        TRANSPORT_WORKSPACES.with(|workspaces| workspaces.borrow_mut().push(workspace));
        let total = total?;
        let result = (total / common_mass as f64) as f32;
        if !result.is_finite() {
            return Err(GemError::NonFinite);
        }
        Ok(result)
    }

    #[cfg(feature = "lemon-qemd")]
    fn distance_histograms_lemon_with_limit(
        &self,
        left_histogram: &[(u32, i64)],
        left_len: usize,
        right_histogram: &[(u32, i64)],
        right_len: usize,
        max_iterations: usize,
    ) -> Result<f32> {
        let mut workspace = LEMON_TRANSPORT_WORKSPACES
            .with(|workspaces| workspaces.borrow_mut().pop().unwrap_or_default());
        workspace.left_codes.clear();
        workspace
            .left_codes
            .extend(left_histogram.iter().map(|row| row.0));
        workspace.supplies.clear();
        workspace.supplies.extend(
            left_histogram
                .iter()
                .map(|row| row.1 as f64 / left_len as f64),
        );
        workspace.demands.clear();
        workspace.demands.extend(
            right_histogram
                .iter()
                .map(|row| row.1 as f64 / right_len as f64),
        );
        workspace.right_codes.clear();
        workspace
            .right_codes
            .extend(right_histogram.iter().map(|row| row.0));
        let result = gem_qemd_lemon::solve_codebook(
            left_histogram.len(),
            right_histogram.len(),
            &workspace.supplies,
            &workspace.demands,
            &workspace.left_codes,
            &workspace.right_codes,
            self.fine_count as usize,
            &self.costs,
            max_iterations,
        );
        LEMON_TRANSPORT_WORKSPACES.with(|workspaces| workspaces.borrow_mut().push(workspace));
        match result {
            Ok(output) => Ok(output),
            Err(gem_qemd_lemon::LemonQemdError::IterationLimit) => {
                Err(GemError::QemdNonConvergence(max_iterations))
            }
            Err(gem_qemd_lemon::LemonQemdError::NonFiniteOutput) => Err(GemError::NonFinite),
            Err(_) => Err(GemError::InvalidManifest),
        }
    }
}

pub(crate) fn histogram(codes: &[u32], fine_count: u32) -> Result<Vec<(u32, i64)>> {
    let mut values = codes.to_vec();
    if values.iter().any(|&code| code >= fine_count) {
        return Err(GemError::InvalidManifest);
    }
    values.sort_unstable();
    let mut output = Vec::new();
    for code in values {
        match output.last_mut() {
            Some((previous, count)) if *previous == code => *count += 1,
            _ => output.push((code, 1)),
        }
    }
    Ok(output)
}

#[cfg(not(feature = "lemon-qemd"))]
fn gcd_i64(mut left: i64, mut right: i64) -> i64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.abs()
}

#[cfg(not(feature = "lemon-qemd"))]
fn lcm_i64(left: i64, right: i64) -> Result<i64> {
    left.checked_div(gcd_i64(left, right))
        .and_then(|value| value.checked_mul(right))
        .ok_or(GemError::NumericOverflow)
}

#[cfg(not(feature = "lemon-qemd"))]
#[derive(Debug, Default)]
struct TransportWorkspace {
    supplies: Vec<i64>,
    demands: Vec<i64>,
    remaining_supply: Vec<i64>,
    remaining_demand: Vec<i64>,
    costs: Vec<f32>,
    cell_rows: Vec<u16>,
    cell_columns: Vec<u16>,
    cell_order: Vec<usize>,
    cell_order_scratch: Vec<usize>,
    flow: Vec<i64>,
    basis: Vec<u8>,
    parent: Vec<usize>,
    rank: Vec<u8>,
    adjacency: Vec<Vec<usize>>,
    potential: Vec<f64>,
    tree_parent_node: Vec<usize>,
    tree_parent_cell: Vec<usize>,
    queue: VecDeque<usize>,
    path: Vec<usize>,
}

#[cfg(feature = "lemon-qemd")]
#[derive(Debug, Default)]
struct LemonTransportWorkspace {
    left_codes: Vec<u32>,
    right_codes: Vec<u32>,
    supplies: Vec<f64>,
    demands: Vec<f64>,
}

thread_local! {
    #[cfg(not(feature = "lemon-qemd"))]
    static TRANSPORT_WORKSPACES: RefCell<Vec<TransportWorkspace>> = const { RefCell::new(Vec::new()) };
    #[cfg(feature = "lemon-qemd")]
    static LEMON_TRANSPORT_WORKSPACES: RefCell<Vec<LemonTransportWorkspace>> = const { RefCell::new(Vec::new()) };
}

#[cfg(not(feature = "lemon-qemd"))]
fn entering_better(left: (f64, usize), right: (f64, usize)) -> bool {
    left.0.total_cmp(&right.0).is_lt()
        || (left.0.to_bits() == right.0.to_bits() && left.1 < right.1)
}

#[cfg(not(feature = "lemon-qemd"))]
const NETWORK_SIMPLEX_REDUCED_COST_EPSILON: f64 = 2.220_446_049_250_313e-15;
#[cfg(any(not(feature = "lemon-qemd"), test))]
fn finite_f32_total_order_key(value: f32) -> u32 {
    let bits = value.to_bits();
    if bits & 0x8000_0000 == 0 {
        bits ^ 0x8000_0000
    } else {
        !bits
    }
}

#[cfg(not(feature = "lemon-qemd"))]
impl TransportWorkspace {
    fn reset_disjoint_set(&mut self, size: usize) {
        self.parent.clear();
        self.parent.extend(0..size);
        self.rank.clear();
        self.rank.resize(size, 0);
    }

    fn find(&mut self, mut value: usize) -> usize {
        let mut root = value;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        while self.parent[value] != value {
            let next = self.parent[value];
            self.parent[value] = root;
            value = next;
        }
        root
    }

    fn union(&mut self, left: usize, right: usize) -> bool {
        let mut left = self.find(left);
        let mut right = self.find(right);
        if left == right {
            return false;
        }
        if self.rank[left] < self.rank[right] {
            std::mem::swap(&mut left, &mut right);
        }
        self.parent[right] = left;
        if self.rank[left] == self.rank[right] {
            self.rank[left] += 1;
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn solve(
        &mut self,
        codebook: &QemdCodebookV3,
        left_histogram: &[(u32, i64)],
        left_len: usize,
        right_histogram: &[(u32, i64)],
        right_len: usize,
        common_mass: i64,
        max_iterations: usize,
    ) -> Result<f64> {
        let row_count = left_histogram.len();
        let column_count = right_histogram.len();
        let node_count = row_count + column_count;
        let cell_count = row_count
            .checked_mul(column_count)
            .ok_or(GemError::NumericOverflow)?;
        if row_count == 0 || column_count == 0 {
            return Err(GemError::InvalidManifest);
        }
        if row_count > u16::MAX as usize || column_count > u16::MAX as usize {
            return Err(GemError::NumericOverflow);
        }

        self.supplies.clear();
        self.supplies.extend(
            left_histogram
                .iter()
                .map(|row| common_mass / left_len as i64 * row.1),
        );
        self.demands.clear();
        self.demands.extend(
            right_histogram
                .iter()
                .map(|row| common_mass / right_len as i64 * row.1),
        );
        if self.supplies.iter().any(|&value| value <= 0)
            || self.demands.iter().any(|&value| value <= 0)
            || self.supplies.iter().sum::<i64>() != self.demands.iter().sum::<i64>()
        {
            return Err(GemError::InvalidManifest);
        }
        self.costs.clear();
        self.cell_rows.clear();
        self.cell_columns.clear();
        self.costs
            .reserve(cell_count.saturating_sub(self.costs.capacity()));
        self.cell_rows
            .reserve(cell_count.saturating_sub(self.cell_rows.capacity()));
        self.cell_columns
            .reserve(cell_count.saturating_sub(self.cell_columns.capacity()));
        for (row, left) in left_histogram.iter().enumerate() {
            for (column, right) in right_histogram.iter().enumerate() {
                self.costs.push(codebook.ground_cost(left.0, right.0)?);
                self.cell_rows.push(row as u16);
                self.cell_columns.push(column as u16);
            }
        }

        self.remaining_supply.clone_from(&self.supplies);
        self.remaining_demand.clone_from(&self.demands);
        self.flow.clear();
        self.flow.resize(cell_count, 0);
        self.basis.clear();
        self.basis.resize(cell_count, 0);

        // The deterministic least-cost initialization mirrors the reference
        // solver's initial-pivot heuristic much more closely than a northwest
        // corner basis. Each allocation exhausts a row or column, so positive
        // support remains a forest. Equal costs use canonical cell order.
        self.cell_order.clear();
        self.cell_order.extend(0..cell_count);
        self.cell_order_scratch.resize(cell_count, 0);
        // A stable LSD radix pass over the finite FP32 cost bits is exactly
        // equivalent to `(cost.total_cmp(), cell_id)`: the initial order is
        // canonical cell ID, so stability supplies the secondary key without
        // the O(cells log cells) comparison sort paid by every qEMD call.
        for shift in [0, 8, 16, 24] {
            let mut counts = [0usize; 256];
            for &cell in &self.cell_order {
                let key = finite_f32_total_order_key(self.costs[cell]);
                counts[((key >> shift) & 0xff) as usize] += 1;
            }
            let mut offset = 0usize;
            for count in &mut counts {
                let current = *count;
                *count = offset;
                offset += current;
            }
            for &cell in &self.cell_order {
                let key = finite_f32_total_order_key(self.costs[cell]);
                let bucket = ((key >> shift) & 0xff) as usize;
                self.cell_order_scratch[counts[bucket]] = cell;
                counts[bucket] += 1;
            }
            std::mem::swap(&mut self.cell_order, &mut self.cell_order_scratch);
        }
        for &cell in &self.cell_order {
            let row = usize::from(self.cell_rows[cell]);
            let column = usize::from(self.cell_columns[cell]);
            if self.remaining_supply[row] == 0 || self.remaining_demand[column] == 0 {
                continue;
            }
            let amount = self.remaining_supply[row].min(self.remaining_demand[column]);
            self.flow[cell] = amount;
            self.basis[cell] = 1;
            self.remaining_supply[row] -= amount;
            self.remaining_demand[column] -= amount;
            if self.remaining_supply.iter().all(|&value| value == 0) {
                break;
            }
        }
        if self.remaining_supply.iter().any(|&value| value != 0)
            || self.remaining_demand.iter().any(|&value| value != 0)
        {
            return Err(GemError::InvalidManifest);
        }

        // Simultaneous row/column exhaustion leaves a degenerate forest. Complete
        // it to one canonical spanning-tree basis with lexicographic zero cells.
        self.reset_disjoint_set(node_count);
        let mut basis_edges = 0usize;
        for cell in 0..cell_count {
            if self.basis[cell] != 0 {
                let row = usize::from(self.cell_rows[cell]);
                let column = usize::from(self.cell_columns[cell]);
                if !self.union(row, row_count + column) {
                    return Err(GemError::InvalidManifest);
                }
                basis_edges += 1;
            }
        }
        for cell in 0..cell_count {
            if basis_edges == node_count - 1 {
                break;
            }
            let row = usize::from(self.cell_rows[cell]);
            let column = usize::from(self.cell_columns[cell]);
            if self.basis[cell] == 0 && self.union(row, row_count + column) {
                self.basis[cell] = 1;
                basis_edges += 1;
            }
        }
        if basis_edges != node_count - 1 {
            return Err(GemError::InvalidManifest);
        }

        self.adjacency.resize_with(node_count, Vec::new);
        for edges in &mut self.adjacency {
            edges.clear();
        }
        for cell in 0..cell_count {
            if self.basis[cell] != 0 {
                let row = usize::from(self.cell_rows[cell]);
                let column = usize::from(self.cell_columns[cell]);
                self.adjacency[row].push(cell);
                self.adjacency[row_count + column].push(cell);
            }
        }
        self.potential.resize(node_count, f64::NAN);
        self.tree_parent_node.resize(node_count, usize::MAX);
        self.tree_parent_cell.resize(node_count, usize::MAX);
        let block_size = ((cell_count as f64).sqrt() as usize)
            .max(cell_count.div_ceil(16))
            .max(10)
            .min(cell_count);
        let mut next_cell = 0usize;

        for iteration in 0..=max_iterations {
            self.potential.fill(f64::NAN);
            self.potential[0] = 0.0;
            self.queue.clear();
            self.queue.push_back(0);
            while let Some(node) = self.queue.pop_front() {
                for &cell in &self.adjacency[node] {
                    let row = usize::from(self.cell_rows[cell]);
                    let column_node = row_count + usize::from(self.cell_columns[cell]);
                    let neighbor = if node == row { column_node } else { row };
                    if self.potential[neighbor].is_finite() {
                        continue;
                    }
                    self.potential[neighbor] = f64::from(self.costs[cell]) - self.potential[node];
                    self.queue.push_back(neighbor);
                }
            }
            if self.potential.iter().any(|value| !value.is_finite()) {
                return Err(GemError::InvalidManifest);
            }

            // Match the reference LEMON network-simplex pivot family: scan
            // deterministic row-major blocks, take the most negative eligible
            // reduced cost in the first qualifying block, and break exact ties
            // by `(row_id, column_id)`.
            let mut entering = None::<(f64, usize)>;
            let mut scanned = 0usize;
            while scanned < cell_count {
                let block_end = (scanned + block_size).min(cell_count);
                while scanned < block_end {
                    let cell = next_cell;
                    next_cell += 1;
                    if next_cell == cell_count {
                        next_cell = 0;
                    }
                    scanned += 1;
                    if self.basis[cell] == 0 {
                        let row = usize::from(self.cell_rows[cell]);
                        let column = usize::from(self.cell_columns[cell]);
                        let cost = f64::from(self.costs[cell]);
                        let reduced =
                            cost - self.potential[row] - self.potential[row_count + column];
                        let scale = self.potential[row]
                            .abs()
                            .max(self.potential[row_count + column].abs())
                            .max(cost.abs());
                        let candidate = (reduced, cell);
                        if reduced < -NETWORK_SIMPLEX_REDUCED_COST_EPSILON * scale
                            && entering.is_none_or(|current| entering_better(candidate, current))
                        {
                            entering = Some(candidate);
                        }
                    }
                }
                if entering.is_some() {
                    break;
                }
            }
            let Some((_, entering_cell)) = entering else {
                let mut total = 0.0f64;
                for cell in 0..cell_count {
                    total += self.flow[cell] as f64 * f64::from(self.costs[cell]);
                    if !total.is_finite() {
                        return Err(GemError::NonFinite);
                    }
                }
                return Ok(total);
            };
            if iteration == max_iterations {
                return Err(GemError::QemdNonConvergence(max_iterations));
            }

            let entering_row = usize::from(self.cell_rows[entering_cell]);
            let entering_column = usize::from(self.cell_columns[entering_cell]);
            let start = entering_row;
            let target = row_count + entering_column;
            self.tree_parent_node.fill(usize::MAX);
            self.tree_parent_cell.fill(usize::MAX);
            self.tree_parent_node[start] = start;
            self.queue.clear();
            self.queue.push_back(start);
            while let Some(node) = self.queue.pop_front() {
                if node == target {
                    break;
                }
                for &cell in &self.adjacency[node] {
                    let row = usize::from(self.cell_rows[cell]);
                    let column_node = row_count + usize::from(self.cell_columns[cell]);
                    let neighbor = if node == row { column_node } else { row };
                    if self.tree_parent_node[neighbor] == usize::MAX {
                        self.tree_parent_node[neighbor] = node;
                        self.tree_parent_cell[neighbor] = cell;
                        self.queue.push_back(neighbor);
                    }
                }
            }
            self.path.clear();
            let mut node = target;
            while node != start {
                let cell = self.tree_parent_cell[node];
                if cell == usize::MAX {
                    return Err(GemError::InvalidManifest);
                }
                self.path.push(cell);
                node = self.tree_parent_node[node];
            }
            self.path.reverse();
            if self.path.is_empty() || self.path.len().is_multiple_of(2) {
                return Err(GemError::InvalidManifest);
            }
            let theta = self
                .path
                .iter()
                .step_by(2)
                .map(|&cell| self.flow[cell])
                .min()
                .ok_or(GemError::InvalidManifest)?;
            let leaving_cell = self
                .path
                .iter()
                .step_by(2)
                .copied()
                .filter(|&cell| self.flow[cell] == theta)
                .min()
                .ok_or(GemError::InvalidManifest)?;
            self.flow[entering_cell] += theta;
            for (position, &cell) in self.path.iter().enumerate() {
                if position.is_multiple_of(2) {
                    self.flow[cell] -= theta;
                } else {
                    self.flow[cell] += theta;
                }
            }
            self.basis[entering_cell] = 1;
            self.basis[leaving_cell] = 0;

            let leaving_row = usize::from(self.cell_rows[leaving_cell]);
            let leaving_column_node = row_count + usize::from(self.cell_columns[leaving_cell]);
            for node in [leaving_row, leaving_column_node] {
                let position = self.adjacency[node]
                    .binary_search(&leaving_cell)
                    .map_err(|_| GemError::InvalidManifest)?;
                self.adjacency[node].remove(position);
            }
            for node in [entering_row, row_count + entering_column] {
                let position = self.adjacency[node]
                    .binary_search(&entering_cell)
                    .unwrap_err();
                self.adjacency[node].insert(position, entering_cell);
            }
        }
        Err(GemError::QemdNonConvergence(max_iterations))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct QemdOracleFixture {
        fixture_version: u16,
        reference_commit: String,
        solver: String,
        seed: u32,
        cases: Vec<QemdOracleCase>,
    }

    #[derive(Debug, Deserialize)]
    struct QemdOracleCase {
        case_id: u32,
        fine_count: u32,
        left: Vec<u32>,
        right: Vec<u32>,
        costs: Vec<f32>,
        expected_bits: u32,
    }

    #[test]
    fn known_uniform_optimum() {
        let codebook = QemdCodebookV3 {
            fine_count: 2,
            costs: vec![0.0, 1.0, 1.0, 0.0],
        };
        assert_eq!(codebook.distance(&[0, 1], &[0, 1]).unwrap(), 0.0);
        assert_eq!(codebook.distance(&[0, 0], &[1]).unwrap(), 1.0);
        assert_eq!(codebook.distance(&[0, 1], &[0]).unwrap(), 0.5);
    }

    #[test]
    fn rust_cost_radix_order_matches_total_cmp_and_cell_id() {
        let values = [
            1.0f32,
            -2.0,
            0.0,
            -0.0,
            f32::MIN_POSITIVE,
            -f32::MIN_POSITIVE,
            1.0,
            f32::MAX,
            -f32::MAX,
        ];
        let mut expected: Vec<usize> = (0..values.len()).collect();
        expected.sort_unstable_by(|&left, &right| {
            values[left]
                .total_cmp(&values[right])
                .then_with(|| left.cmp(&right))
        });
        let mut actual: Vec<usize> = (0..values.len()).collect();
        let mut scratch = vec![0usize; values.len()];
        for shift in [0, 8, 16, 24] {
            let mut counts = [0usize; 256];
            for &cell in &actual {
                let key = finite_f32_total_order_key(values[cell]);
                counts[((key >> shift) & 0xff) as usize] += 1;
            }
            let mut offset = 0usize;
            for count in &mut counts {
                let current = *count;
                *count = offset;
                offset += current;
            }
            for &cell in &actual {
                let key = finite_f32_total_order_key(values[cell]);
                let bucket = ((key >> shift) & 0xff) as usize;
                scratch[counts[bucket]] = cell;
                counts[bucket] += 1;
            }
            std::mem::swap(&mut actual, &mut scratch);
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn exact_solver_matches_pinned_lemon_fixture() {
        let fixture: QemdOracleFixture =
            serde_json::from_str(include_str!("../../../tests/fixtures/golden/qemd-lemon-v3.json"))
                .unwrap();
        assert_eq!(fixture.fixture_version, 1);
        assert_eq!(
            fixture.reference_commit,
            "1b559d0ccb2bea7a23ac9f2f8e84040924e3972f"
        );
        assert_eq!(
            fixture.solver,
            "hnswlib/otlib/EMD_wrapper.cpp:EMD_wrap_self"
        );
        assert_eq!(fixture.seed, 1_296_387_396);
        assert_eq!(fixture.cases.len(), 64);
        for case in fixture.cases {
            let codebook = QemdCodebookV3 {
                fine_count: case.fine_count,
                costs: case.costs,
            };
            let actual = codebook
                .distance(&case.left, &case.right)
                .unwrap_or_else(|error| {
                    panic!("qEMD oracle case {} failed: {error}", case.case_id)
                });
            let expected = f32::from_bits(case.expected_bits);
            #[cfg(feature = "lemon-qemd")]
            assert_eq!(
                actual.to_bits(),
                case.expected_bits,
                "LEMON qEMD oracle case {} differs bitwise: actual={actual:?} expected={expected:?}",
                case.case_id
            );
            assert!(
                (actual - expected).abs() <= 2.0e-6,
                "qEMD oracle case {} differs: Rust={actual:?}, LEMON={expected:?}",
                case.case_id
            );
        }
    }

    #[test]
    fn thread_local_workspace_supports_parallel_calls() {
        let fine_count = 40u32;
        let costs = (0..fine_count)
            .flat_map(|left| {
                (0..fine_count).map(move |right| left.abs_diff(right) as f32 / fine_count as f32)
            })
            .collect();
        let codebook = QemdCodebookV3 { fine_count, costs };
        let left: Vec<u32> = (0..fine_count).collect();
        let expected: Vec<u32> = (0..16)
            .map(|offset| {
                let right: Vec<u32> = (0..fine_count)
                    .map(|code| (code + offset) % fine_count)
                    .collect();
                codebook.distance(&left, &right).unwrap().to_bits()
            })
            .collect();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let actual: Vec<u32> = pool.install(|| {
            (0..16)
                .into_par_iter()
                .map(|offset| {
                    let right: Vec<u32> = (0..fine_count)
                        .map(|code| (code + offset) % fine_count)
                        .collect();
                    codebook.distance(&left, &right).unwrap().to_bits()
                })
                .collect()
        });
        assert_eq!(actual, expected);
    }
}
