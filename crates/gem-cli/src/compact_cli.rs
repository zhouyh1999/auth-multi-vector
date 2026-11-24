//! Uses shared CLI and independent oracle with compact typed protocol.
mod scheme_family {
    pub use gem_auth_scheme_v3::compact::numeric::*;
    pub use gem_auth_scheme_v3::compact::*;
}
#[path = "scheme_auth.rs"]
mod cli;
#[path = "fixed_reference.rs"]
pub mod fixed_reference;
pub use cli::run;
