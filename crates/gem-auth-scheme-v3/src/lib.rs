#![forbid(unsafe_code)]
#![allow(
    clippy::duplicate_mod,
    reason = "The shared algorithm is instantiated for two distinct numeric types and schemas"
)]
//! Complete schema 8 fixed-point raw and matrix authentication of V3R3 execution.
mod attacks;
mod protocol;
mod snapshot;
mod types;
pub use attacks::*;
mod wire;
pub use protocol::*;
pub use snapshot::*;
pub use types::*;
pub use wire::*;

#[cfg(test)]
mod tests;

pub mod compact;
pub mod numeric;
