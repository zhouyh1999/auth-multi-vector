//! Internal total ordering for FP32 distances and canonical document-id ties.

use std::cmp::Ordering;

use gem_core::{GemError, NodeDistanceF32V3, Result};

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct DistanceDocV3 {
    pub(super) doc_id: u32,
    pub(super) distance_bits: u32,
}

impl DistanceDocV3 {
    pub(super) fn new(doc_id: u32, distance: f32) -> Result<Self> {
        if !distance.is_finite() {
            return Err(GemError::NonFinite);
        }
        Ok(Self {
            doc_id,
            distance_bits: distance.to_bits(),
        })
    }

    pub(super) fn distance(self) -> f32 {
        f32::from_bits(self.distance_bits)
    }

    pub(super) fn public(self) -> NodeDistanceF32V3 {
        NodeDistanceF32V3 {
            doc_id: self.doc_id,
            distance_bits: self.distance_bits,
        }
    }
}

impl Ord for DistanceDocV3 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.distance()
            .total_cmp(&other.distance())
            .then_with(|| self.doc_id.cmp(&other.doc_id))
    }
}

impl PartialOrd for DistanceDocV3 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for DistanceDocV3 {}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct ClosestFirstV3(pub(super) DistanceDocV3);

impl Ord for ClosestFirstV3 {
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.cmp(&self.0)
    }
}

impl PartialOrd for ClosestFirstV3 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for ClosestFirstV3 {}
