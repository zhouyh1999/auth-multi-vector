use half::f16;

use crate::{GemError, Result};

#[inline(always)]
fn rounded_mul(left: f32, right: f32) -> f32 {
    left * right
}

#[inline(always)]
fn rounded_add(left: f32, right: f32) -> f32 {
    left + right
}

pub fn decode_f16(bits: u16) -> Result<f32> {
    let value = f16::from_bits(bits).to_f32();
    if !value.is_finite() {
        return Err(GemError::NonFinite);
    }
    Ok(value)
}

/// Scalar FP32 dot product with a fixed multiply/add order.
pub fn strict_dot_f32(left: &[f32], right: &[f32]) -> Result<f32> {
    if left.len() != right.len() {
        return Err(GemError::InvalidDimension {
            expected: left.len(),
            actual: right.len(),
        });
    }
    let mut accumulator = 0.0f32;
    for (&left_value, &right_value) in left.iter().zip(right) {
        accumulator = rounded_add(accumulator, rounded_mul(left_value, right_value));
    }
    if !accumulator.is_finite() {
        return Err(GemError::NonFinite);
    }
    Ok(accumulator)
}

/// Exact scalar FP32 MaxSim using the V3 deterministic operation order.
pub fn strict_maxsim_f32(
    query: &[f32],
    query_tokens: usize,
    document: &[f32],
    document_tokens: usize,
    dimension: usize,
) -> Result<f32> {
    if dimension == 0 {
        return Err(GemError::InvalidDimension {
            expected: 1,
            actual: 0,
        });
    }
    if query_tokens == 0 || document_tokens == 0 {
        return Err(GemError::InvalidTokenCount);
    }
    let expected_query = query_tokens
        .checked_mul(dimension)
        .ok_or(GemError::NumericOverflow)?;
    let expected_document = document_tokens
        .checked_mul(dimension)
        .ok_or(GemError::NumericOverflow)?;
    if query.len() != expected_query {
        return Err(GemError::InvalidDimension {
            expected: expected_query,
            actual: query.len(),
        });
    }
    if document.len() != expected_document {
        return Err(GemError::InvalidDimension {
            expected: expected_document,
            actual: document.len(),
        });
    }

    let mut score = 0.0f32;
    for query_vector in query.chunks_exact(dimension) {
        let mut maximum: Option<f32> = None;
        for document_vector in document.chunks_exact(dimension) {
            let value = strict_dot_f32(query_vector, document_vector)?;
            maximum = Some(match maximum {
                Some(current) if current >= value => current,
                _ => value,
            });
        }
        score = rounded_add(score, maximum.ok_or(GemError::InvalidTokenCount)?);
        if !score.is_finite() {
            return Err(GemError::NonFinite);
        }
    }
    Ok(score)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_dot_rejects_invalid_inputs() {
        assert_eq!(
            strict_dot_f32(&[1.0], &[1.0, 2.0]),
            Err(GemError::InvalidDimension {
                expected: 1,
                actual: 2,
            })
        );
        assert_eq!(
            strict_dot_f32(&[f32::NAN], &[1.0]),
            Err(GemError::NonFinite)
        );
    }

    #[test]
    fn maxsim_uses_every_document_token() {
        let score = strict_maxsim_f32(&[1.0, 0.0], 1, &[0.0, 1.0, 1.0, 0.0], 2, 2).unwrap();
        assert_eq!(score.to_bits(), 1.0f32.to_bits());
    }

    #[test]
    fn zero_dimension_maxsim_is_rejected_without_panic() {
        assert!(strict_maxsim_f32(&[], 1, &[], 1, 0).is_err());
    }
}
