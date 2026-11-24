#![allow(
    clippy::duplicate_mod,
    reason = "Run the same independent process checks for both numeric schemas"
)]
mod family {
    pub use gem_auth_scheme_v3::numeric::SNAPSHOT_MAGIC;
    pub use gem_auth_scheme_v3::*;
}
#[path = "support/scheme_auth_cases.rs"]
mod cases;
#[path = "support/compact_cases.rs"]
mod compact;
