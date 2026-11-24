//! Filename-only discovery shared by build evidence, compact import and reranking.

use std::{collections::BTreeSet, fs, path::Path};

use gem_core::{GemError, Result};

fn shard_ids(directory: &Path, prefix: &str, suffix: &str) -> Result<BTreeSet<u32>> {
    let mut ids = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(digits) = name
            .strip_prefix(prefix)
            .and_then(|name| name.strip_suffix(suffix))
        else {
            continue;
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let id = digits.parse::<u32>().map_err(|_| {
            GemError::InvalidShardLayout(format!("shard ID overflow: {}", entry.path().display()))
        })?;
        if digits != id.to_string() || !entry.path().is_file() {
            return Err(GemError::InvalidShardLayout(format!(
                "non-canonical shard file: {}",
                entry.path().display()
            )));
        }
        ids.insert(id);
    }
    if ids.is_empty() {
        return Err(GemError::InvalidShardLayout(format!(
            "no {prefix}*{suffix} shards in {}",
            directory.display()
        )));
    }
    for (expected, &id) in ids.iter().enumerate() {
        if expected != id as usize {
            return Err(GemError::InvalidShardLayout(format!(
                "missing shard {expected} before {id} in {} ({prefix}*{suffix})",
                directory.display()
            )));
        }
    }
    Ok(ids)
}

/// Discover matching, contiguous shard IDs starting at zero before reading any
/// payload. Passing an encoder directory also requires matching raw embeddings.
/// This runs once per corpus load, never inside the per-query search loop.
pub fn discover_official_shard_ids_v3(
    code_dir: &Path,
    doclens_dir: &Path,
    encoder_dir: Option<&Path>,
) -> Result<Vec<u32>> {
    let codes = shard_ids(code_dir, "doc_codes_", ".npy")?;
    let lengths = shard_ids(doclens_dir, "doclens", ".npy")?;
    if codes != lengths {
        return Err(GemError::InvalidShardLayout(
            "compact-code and doclens shard IDs differ".into(),
        ));
    }
    if let Some(directory) = encoder_dir
        && shard_ids(directory, "encoding", "_float16.npy")? != codes
    {
        return Err(GemError::InvalidShardLayout(
            "raw encoding and compact-code shard IDs differ".into(),
        ));
    }
    Ok(codes.into_iter().collect())
}
