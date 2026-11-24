//! Exact integer semantics for scheme authentication. Source floating bits stay external.
use crate::{GemError, QueryV3, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const FIXED_PROFILE_ID_V1: &str = "gem-fixed-s16-i64-v1";
pub const FIXED_SCALE_V1: i64 = 1 << 16;
pub const FIXED_SCALE_SQUARED_V1: i128 = 1 << 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixedNumericProfileV1 {
    pub id: String,
    pub scale: u32,
    pub rounding: String,
}
impl Default for FixedNumericProfileV1 {
    fn default() -> Self {
        Self {
            id: FIXED_PROFILE_ID_V1.into(),
            scale: 65536,
            rounding: "f64-round-half-away-from-zero-no-clipping-v1".into(),
        }
    }
}
impl FixedNumericProfileV1 {
    pub fn validate(&self) -> Result<()> {
        if self != &Self::default() {
            return Err(GemError::InvalidScale);
        }
        Ok(())
    }
}
pub fn fixed_coordinate_v1(x: f32) -> Result<i32> {
    if !x.is_finite() {
        return Err(GemError::NonFinite);
    }
    let value = (f64::from(x) * FIXED_SCALE_V1 as f64).round();
    if value < f64::from(i32::MIN) || value > f64::from(i32::MAX) {
        return Err(GemError::NumericOverflow);
    }
    Ok(value as i32)
}
pub fn fixed_coordinates_v1(xs: &[f32]) -> Result<Vec<i32>> {
    xs.iter().copied().map(fixed_coordinate_v1).collect()
}
pub fn fixed_fp16_v1(bits: &[u16]) -> Result<Vec<i32>> {
    bits.iter()
        .map(|&b| fixed_coordinate_v1(half::f16::from_bits(b).to_f32()))
        .collect()
}
pub fn fixed_dot_v1(a: &[i32], b: &[i32]) -> Result<i64> {
    if a.is_empty() || a.len() != b.len() {
        return Err(GemError::InvalidDimension {
            expected: a.len(),
            actual: b.len(),
        });
    }
    a.iter().zip(b).try_fold(0i64, |sum, (&x, &y)| {
        sum.checked_add(i64::from(x) * i64::from(y))
            .ok_or(GemError::NumericOverflow)
    })
}
/// JSON uses decimal strings; binary serializers keep fixed-width i128.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedDistanceV3(pub i128);
impl Serialize for FixedDistanceV3 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.0.to_string())
        } else {
            s.serialize_i128(self.0)
        }
    }
}
impl<'de> Deserialize<'de> for FixedDistanceV3 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        if d.is_human_readable() {
            String::deserialize(d)?
                .parse::<i128>()
                .map(Self)
                .map_err(serde::de::Error::custom)
        } else {
            i128::deserialize(d).map(Self)
        }
    }
}
pub fn fixed_distance_v1(
    maxima: impl IntoIterator<Item = i64>,
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
            .checked_mul(FIXED_SCALE_SQUARED_V1)
            .and_then(|x| x.checked_sub(sum))
            .ok_or(GemError::NumericOverflow)?,
    ))
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FixedQueryV3 {
    pub source: QueryV3,
    pub coordinates: Vec<i32>,
}
impl FixedQueryV3 {
    pub fn new(source: QueryV3) -> Result<Self> {
        source.validate(source.dimension)?;
        let coordinates = fixed_coordinates_v1(&source.coordinates)?;
        Ok(Self {
            source,
            coordinates,
        })
    }
    pub fn validate(&self) -> Result<()> {
        self.source.validate(self.source.dimension)?;
        if self.coordinates != fixed_coordinates_v1(&self.source.coordinates)? {
            return Err(GemError::HashMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rounding_sign_and_limits() {
        for (x, n) in [
            (0.5 / 65536., 1),
            (-0.5 / 65536., -1),
            (1.5 / 65536., 2),
            (-1.5 / 65536., -2),
            (0., 0),
            (-0., 0),
        ] {
            assert_eq!(fixed_coordinate_v1(x).unwrap(), n);
        }
        assert_eq!(fixed_coordinate_v1(-32768.).unwrap(), i32::MIN);
        for x in [32768., f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert!(fixed_coordinate_v1(x).is_err());
        }
        assert!(fixed_dot_v1(&[i32::MIN; 3], &[i32::MIN; 3]).is_err());
        assert_eq!(fixed_dot_v1(&[i32::MIN], &[i32::MIN]).unwrap(), 1i64 << 62);
        assert_eq!(
            fixed_distance_v1([-9, -7], 2).unwrap().0,
            2 * FIXED_SCALE_SQUARED_V1 + 16
        );
        assert_eq!(
            serde_json::to_string(&FixedDistanceV3(i128::MAX)).unwrap(),
            format!("\"{}\"", i128::MAX)
        );
    }
}
