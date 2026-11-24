//! PPT sol2 numeric contract: floor(32767*x), int16 coordinates and int32 dots.
use crate::{FixedDistanceV3, GemError, QueryV3, Result};
use serde::{Deserialize, Serialize};

pub const COMPACT_PROFILE_ID_V1: &str = "gem-int16-s32767-i32-floor-v1";
pub const COMPACT_SCALE_V1: i64 = 32767;
pub const COMPACT_SCALE_SQUARED_V1: i128 = 1073676289;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactNumericProfileV1 {
    pub id: String,
    pub scale: u32,
    pub rounding: String,
    pub maximum_absolute_coordinate: u32,
}
impl Default for CompactNumericProfileV1 {
    fn default() -> Self {
        Self {
            id: COMPACT_PROFILE_ID_V1.into(),
            scale: 32767,
            rounding: "f64-floor-no-clipping-v1".into(),
            maximum_absolute_coordinate: 1,
        }
    }
}
impl CompactNumericProfileV1 {
    pub fn validate(&self) -> Result<()> {
        if self != &Self::default() {
            return Err(GemError::InvalidScale);
        }
        Ok(())
    }
}
pub fn compact_coordinate_v1(x: f32) -> Result<i16> {
    if !x.is_finite() {
        return Err(GemError::NonFinite);
    }
    // v_max=1 is a pinned coordinate bound, never a query-dependent scale.
    if x.abs() > 1.0 {
        return Err(GemError::NumericOverflow);
    }
    let q = (f64::from(x) * COMPACT_SCALE_V1 as f64).floor();
    if q < f64::from(i16::MIN) || q > f64::from(i16::MAX) {
        return Err(GemError::NumericOverflow);
    }
    Ok(q as i16)
}
pub fn compact_coordinates_v1(a: &[f32]) -> Result<Vec<i16>> {
    a.iter().copied().map(compact_coordinate_v1).collect()
}
pub fn compact_fp16_v1(a: &[u16]) -> Result<Vec<i16>> {
    a.iter()
        .map(|&b| compact_coordinate_v1(half::f16::from_bits(b).to_f32()))
        .collect()
}
pub fn compact_dot_v1(a: &[i16], b: &[i16]) -> Result<i32> {
    if a.is_empty() || a.len() != b.len() {
        return Err(GemError::InvalidDimension {
            expected: a.len(),
            actual: b.len(),
        });
    }
    let sum = a.iter().zip(b).try_fold(0i64, |s, (&x, &y)| {
        s.checked_add(i64::from(x) * i64::from(y))
            .ok_or(GemError::NumericOverflow)
    })?;
    i32::try_from(sum).map_err(|_| GemError::NumericOverflow)
}
pub fn compact_distance_v1(
    maxima: impl IntoIterator<Item = i32>,
    tokens: usize,
) -> Result<FixedDistanceV3> {
    if tokens == 0 {
        return Err(GemError::InvalidTokenCount);
    }
    let mut count = 0usize;
    let sum = maxima.into_iter().try_fold(0i128, |s, x| {
        count += 1;
        s.checked_add(i128::from(x))
            .ok_or(GemError::NumericOverflow)
    })?;
    if count != tokens {
        return Err(GemError::InvalidTokenCount);
    }
    Ok(FixedDistanceV3(
        (tokens as i128)
            .checked_mul(COMPACT_SCALE_SQUARED_V1)
            .and_then(|v| v.checked_sub(sum))
            .ok_or(GemError::NumericOverflow)?,
    ))
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactQueryV3 {
    pub source: QueryV3,
    pub coordinates: Vec<i16>,
}
impl CompactQueryV3 {
    pub fn new(source: QueryV3) -> Result<Self> {
        source.validate(source.dimension)?;
        let coordinates = compact_coordinates_v1(&source.coordinates)?;
        Ok(Self {
            source,
            coordinates,
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.source.validate(self.source.dimension)?;
        if self.coordinates != compact_coordinates_v1(&self.source.coordinates)? {
            return Err(GemError::HashMismatch);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn floor_sign_zero_endpoints_and_rejection() {
        assert_eq!(compact_coordinate_v1(1.0).unwrap(), 32767);
        assert_eq!(compact_coordinate_v1(-1.0).unwrap(), -32767);
        assert_eq!(compact_coordinate_v1(0.5).unwrap(), 16383);
        assert_eq!(compact_coordinate_v1(-0.5).unwrap(), -16384);
        assert_eq!(compact_coordinate_v1(-0.0).unwrap(), 0);
        assert_eq!(compact_coordinate_v1(-f32::from_bits(1)).unwrap(), -1);
        for x in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 1.001, -1.001] {
            assert!(compact_coordinate_v1(x).is_err());
        }
    }
    #[test]
    fn checked_dot_accepts_cancellation_and_rejects_actual_overflow() {
        let a = [32767; 4];
        // Large row norms alone do not reject otherwise representable products.
        assert_eq!(
            compact_dot_v1(&a, &[32767, 32767, -32767, -32767]).unwrap(),
            0
        );
        assert!(compact_dot_v1(&a, &a).is_err());
        assert_eq!(
            compact_dot_v1(&[32767, 0], &[32767, 0]).unwrap(),
            1073676289
        );
        assert_eq!(
            compact_distance_v1([-1, -2], 2).unwrap().0,
            2 * COMPACT_SCALE_SQUARED_V1 + 3
        );
    }
}
