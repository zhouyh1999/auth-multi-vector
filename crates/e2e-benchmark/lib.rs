pub use gem_cli::full_snapshot as offline;
use serde::Deserialize;
#[derive(Deserialize)]
pub struct Envelope {
    pub version: u32,
    pub input_binding: gem_core::Hash,
    pub corpus: offline::PublishedConfig,
    pub prepared: gem_auth_scheme_multi::compact::PreparedSchemeSnapshotV3,
}

/// The standalone executables share the same write boundary as the Python runner.
/// Resolve before creating any output. The workspace root is the launch directory.
pub fn workspace_output(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let root = std::env::current_dir()?.canonicalize()?;
    anyhow::ensure!(
        root.join("config.toml").is_file()
            && root.join("crates/authentication/Cargo.toml").is_file(),
        "start in auth-gem"
    );
    let absolute = root.join(path);
    anyhow::ensure!(
        !absolute
            .components()
            .any(|c| c == std::path::Component::ParentDir)
            && ["artifacts", "results"]
                .iter()
                .any(|p| absolute.starts_with(root.join(p)) && absolute != root.join(p)),
        "invalid output {}",
        path.display()
    );
    for ancestor in absolute.ancestors().take_while(|p| *p != root) {
        if let Ok(meta) = std::fs::symlink_metadata(ancestor) {
            anyhow::ensure!(!meta.is_symlink(), "linked output");
        }
    }
    if absolute.exists() {
        for entry in walkdir::WalkDir::new(absolute) {
            let entry = entry?;
            anyhow::ensure!(
                !entry.file_type().is_symlink()
                    && (!entry.file_type().is_file() || entry.metadata()?.nlink() == 1),
                "linked file {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}
