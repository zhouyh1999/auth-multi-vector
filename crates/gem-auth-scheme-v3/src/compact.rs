//! PPT sol2/sol3 compact int16/int32 authentication. Schema 9.
#[path = "attacks.rs"]
mod attacks;
#[path = "compact_numeric.rs"]
pub mod numeric;
#[path = "protocol.rs"]
mod protocol;
#[path = "snapshot.rs"]
mod snapshot;
#[path = "compact_types.rs"]
mod types;
#[path = "wire.rs"]
mod wire;
pub use attacks::*;
pub use protocol::*;
pub use snapshot::*;
pub use types::*;
pub use wire::*;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
