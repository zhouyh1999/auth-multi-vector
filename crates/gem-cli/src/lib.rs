#![forbid(unsafe_code)]
#![allow(
    clippy::duplicate_mod,
    reason = "The shared algorithm is instantiated for two distinct numeric types and schemas"
)]

//! Shared I/O helpers and the structured GEM V3 Native command runner.

pub mod full_snapshot;
pub mod native;

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use gem_core::RawDocumentV3;
use gem_search::{
    OfficialShardSpecV3, discover_official_shard_ids_v3, import_official_document_shard,
};

/// Atomically install a completed report, checkpoint, or index in one
/// filesystem by writing a PID-scoped sibling and renaming it into place.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create output directory {}", parent.display()))?;
    let temporary = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("out"),
        std::process::id()
    ));
    fs::write(&temporary, bytes)
        .with_context(|| format!("write temporary output {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("install output {}", path.display()))?;
    Ok(())
}

/// Import every consecutive official ColBERT shard needed by V3 exact
/// reranking. Missing members and gaps in the shard sequence are rejected.
pub fn load_raw_corpus(
    encoder_dir: &Path,
    code_dir: &Path,
    dimension: u16,
    max_doc_tokens: u16,
) -> Result<Vec<RawDocumentV3>> {
    let mut documents = Vec::new();
    for shard_id in discover_official_shard_ids_v3(code_dir, encoder_dir, Some(encoder_dir))? {
        let encoding = encoder_dir.join(format!("encoding{shard_id}_float16.npy"));
        let doclens = encoder_dir.join(format!("doclens{shard_id}.npy"));
        let codes = code_dir.join(format!("doc_codes_{shard_id}.npy"));
        let shard = import_official_document_shard(&OfficialShardSpecV3 {
            dimension,
            max_doc_tokens,
            start_doc_id: u32::try_from(documents.len())?,
            encoding_f16_npy: encoding,
            doc_codes_i32_npy: codes,
            doclens_i64_npy: doclens,
        })?;
        documents.extend(shard.documents);
    }
    if documents.is_empty() {
        bail!("no raw document shards found");
    }
    Ok(documents)
}
pub mod raw_auth;

mod fixed_reference;
pub mod scheme_auth;

pub mod compact_cli;
mod scheme_family;
