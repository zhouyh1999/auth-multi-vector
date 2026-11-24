//! Compact PPT metric uses the same V3R3 execution state machine.
use super::{ComponentUsageV3, ExecutionNodeV3, ExecutionTraceV3, SearchAccessV3, engine};
mod fixed_numeric {
    pub type Coordinate = i16;
    pub type Similarity = i32;
    pub use gem_core::{
        CompactQueryV3 as FixedQueryV3, compact_distance_v1 as fixed_distance_v1,
        compact_dot_v1 as fixed_dot_v1,
    };
    #[cfg(test)]
    pub const SCALE_SQUARED: i128 = gem_core::COMPACT_SCALE_SQUARED_V1;
}
#[path = "fixed.rs"]
mod fixed;
pub use fixed::*;
