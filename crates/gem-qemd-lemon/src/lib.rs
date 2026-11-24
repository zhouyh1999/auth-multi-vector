#![forbid(unsafe_op_in_unsafe_fn)]

use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LemonQemdError {
    InvalidInput,
    IterationLimit,
    SolverFailure,
    NonFiniteOutput,
}

impl fmt::Display for LemonQemdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid LEMON qEMD input",
            Self::IterationLimit => "LEMON qEMD iteration limit reached",
            Self::SolverFailure => "LEMON qEMD solver failure",
            Self::NonFiniteOutput => "LEMON qEMD returned a non-finite cost",
        })
    }
}

impl Error for LemonQemdError {}

/// Calls GEM's vendored LEMON transportation solver through a narrow checked ABI.
///
/// All raw pointers are derived from slices after their exact dimensions, finite
/// values, positivity, and iteration bound have been checked here. The C++ shim
/// only reads those slices and writes one `f32` result.
pub fn solve(
    rows: usize,
    columns: usize,
    supplies: &[f64],
    demands: &[f64],
    costs: &[f64],
    max_iterations: usize,
) -> Result<f32, LemonQemdError> {
    let cells = rows
        .checked_mul(columns)
        .ok_or(LemonQemdError::InvalidInput)?;
    // The Rust reference counts one basis-update search as an iteration, while
    // LEMON counts lower-level network-simplex pivots. Scale the fail-safe by
    // the transport graph's node count so the public limit retains its role as
    // a non-convergence guard without accepting GEM's 1,000-pivot intermediate
    // solution as an exact qEMD result.
    let solver_iterations = max_iterations
        .checked_mul(
            rows.checked_add(columns)
                .ok_or(LemonQemdError::InvalidInput)?,
        )
        .ok_or(LemonQemdError::InvalidInput)?;
    if rows == 0
        || columns == 0
        || supplies.len() != rows
        || demands.len() != columns
        || costs.len() != cells
        || max_iterations == 0
        || i32::try_from(rows).is_err()
        || i32::try_from(columns).is_err()
        || u64::try_from(solver_iterations).is_err()
        || supplies
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        || demands
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        || costs.iter().any(|value| !value.is_finite())
    {
        return Err(LemonQemdError::InvalidInput);
    }

    let mut output = f32::NAN;
    // SAFETY: the validation above proves that all buffers have the dimensions
    // supplied to C++, remain alive for the call, and the sole output pointer is
    // valid and uniquely borrowed. The shim does not retain any pointer.
    let status = unsafe {
        gem_emd_solve_v3(
            rows as i32,
            columns as i32,
            supplies.as_ptr(),
            demands.as_ptr(),
            costs.as_ptr(),
            solver_iterations as u64,
            &mut output,
        )
    };
    match status {
        0 if output.is_finite() => Ok(output),
        0 => Err(LemonQemdError::NonFiniteOutput),
        1 => Err(LemonQemdError::IterationLimit),
        _ => Err(LemonQemdError::SolverFailure),
    }
}

/// Solves from compact code IDs and the frozen FP32 ground-cost table.
///
/// This avoids materializing a second dense `f64` cost matrix at every call;
/// each table value is converted to `f64` exactly once when loaded by LEMON.
#[allow(clippy::too_many_arguments)]
pub fn solve_codebook(
    rows: usize,
    columns: usize,
    supplies: &[f64],
    demands: &[f64],
    row_codes: &[u32],
    column_codes: &[u32],
    fine_count: usize,
    codebook: &[f32],
    max_iterations: usize,
) -> Result<f32, LemonQemdError> {
    let cells = rows
        .checked_mul(columns)
        .ok_or(LemonQemdError::InvalidInput)?;
    let codebook_cells = fine_count
        .checked_mul(fine_count)
        .ok_or(LemonQemdError::InvalidInput)?;
    let solver_iterations = max_iterations
        .checked_mul(
            rows.checked_add(columns)
                .ok_or(LemonQemdError::InvalidInput)?,
        )
        .ok_or(LemonQemdError::InvalidInput)?;
    if rows == 0
        || columns == 0
        || cells == 0
        || supplies.len() != rows
        || demands.len() != columns
        || row_codes.len() != rows
        || column_codes.len() != columns
        || fine_count == 0
        || codebook.len() != codebook_cells
        || max_iterations == 0
        || i32::try_from(rows).is_err()
        || i32::try_from(columns).is_err()
        || u32::try_from(fine_count).is_err()
        || u64::try_from(solver_iterations).is_err()
        || supplies
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        || demands
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        || row_codes.iter().any(|&code| code as usize >= fine_count)
        || column_codes.iter().any(|&code| code as usize >= fine_count)
    {
        return Err(LemonQemdError::InvalidInput);
    }

    let mut output = f32::NAN;
    // SAFETY: all dimensions, code IDs and buffers are checked above. The C++
    // shim reads them only for this call and writes exactly one `f32` result.
    let status = unsafe {
        gem_emd_solve_codebook_v3(
            rows as i32,
            columns as i32,
            supplies.as_ptr(),
            demands.as_ptr(),
            row_codes.as_ptr(),
            column_codes.as_ptr(),
            fine_count as u32,
            codebook.as_ptr(),
            solver_iterations as u64,
            &mut output,
        )
    };
    match status {
        0 if output.is_finite() => Ok(output),
        0 => Err(LemonQemdError::NonFiniteOutput),
        1 => Err(LemonQemdError::IterationLimit),
        _ => Err(LemonQemdError::SolverFailure),
    }
}

unsafe extern "C" {
    fn gem_emd_solve_v3(
        rows: i32,
        columns: i32,
        supplies: *const f64,
        demands: *const f64,
        costs: *const f64,
        max_iterations: u64,
        output: *mut f32,
    ) -> i32;

    fn gem_emd_solve_codebook_v3(
        rows: i32,
        columns: i32,
        supplies: *const f64,
        demands: *const f64,
        row_codes: *const u32,
        column_codes: *const u32,
        fine_count: u32,
        codebook: *const f32,
        max_iterations: u64,
        output: *mut f32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_dimension_mismatch_before_ffi() {
        assert_eq!(
            solve(1, 2, &[1.0], &[0.5, 0.5], &[0.0], 10),
            Err(LemonQemdError::InvalidInput)
        );
    }

    #[test]
    fn solves_a_small_transport_problem() {
        let actual = solve(
            2,
            2,
            &[0.5, 0.5],
            &[0.5, 0.5],
            &[0.0, 1.0, 1.0, 0.0],
            10_000,
        )
        .expect("LEMON solver");
        assert_eq!(actual.to_bits(), 0.0f32.to_bits());
    }

    #[test]
    fn codebook_path_matches_dense_cost_path() {
        let dense = solve(
            2,
            2,
            &[0.5, 0.5],
            &[0.5, 0.5],
            &[0.0, 1.0, 1.0, 0.0],
            10_000,
        )
        .expect("dense LEMON solver");
        let codebook = solve_codebook(
            2,
            2,
            &[0.5, 0.5],
            &[0.5, 0.5],
            &[0, 1],
            &[0, 1],
            2,
            &[0.0, 1.0, 1.0, 0.0],
            10_000,
        )
        .expect("codebook LEMON solver");
        assert_eq!(codebook.to_bits(), dense.to_bits());
    }
}
