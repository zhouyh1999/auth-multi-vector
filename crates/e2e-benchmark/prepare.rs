use anyhow::{Context, Result};
use gem_lotte_auth_pilot::offline;
use std::path::PathBuf;

fn main() -> Result<()> {
    let root = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("expected dataset directory")?,
    );
    gem_lotte_auth_pilot::workspace_output(&root)?;
    offline::import_index(&root)?;
    offline::prepare_raw(&root)?;
    offline::prepare_compact(&root)
}
