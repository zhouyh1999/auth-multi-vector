//! Content hashes and lightweight process telemetry used by reproducible runs.

use std::{fs, path::Path};

use anyhow::Result;
use gem_core::{hash_bytes, sha256_file};
use gem_search::discover_official_shard_ids_v3;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FileEvidence {
    pub(super) path: String,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct ContentEvidence {
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

pub(super) fn file_evidence(path: &Path) -> Result<FileEvidence> {
    Ok(FileEvidence {
        path: path.display().to_string(),
        bytes: fs::metadata(path)?.len(),
        sha256: hex::encode(sha256_file(path)?),
    })
}

pub(super) fn content_evidence(path: &Path) -> Result<ContentEvidence> {
    Ok(ContentEvidence {
        bytes: fs::metadata(path)?.len(),
        sha256: hex::encode(sha256_file(path)?),
    })
}

pub(super) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn input_files(
    fine: &Path,
    coarse: &Path,
    mapping: &Path,
    code_dir: &Path,
    doclens_dir: &Path,
) -> Result<Vec<FileEvidence>> {
    let mut files = vec![
        file_evidence(fine)?,
        file_evidence(coarse)?,
        file_evidence(mapping)?,
    ];
    for shard_id in discover_official_shard_ids_v3(code_dir, doclens_dir, None)? {
        let codes = code_dir.join(format!("doc_codes_{shard_id}.npy"));
        let doclens = doclens_dir.join(format!("doclens{shard_id}.npy"));
        files.push(file_evidence(&codes)?);
        files.push(file_evidence(&doclens)?);
    }
    Ok(files)
}

pub(super) fn input_digest(files: &[FileEvidence]) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    for file in files {
        bytes.extend_from_slice(file.path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&hex::decode(&file.sha256)?);
    }
    Ok(hash_bytes(b"gem.repo.deterministic.v3.inputs", &bytes))
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(super) struct ProcessSample {
    pub(super) rss_kib: u64,
    pub(super) swap_kib: u64,
    pub(super) voluntary_context_switches: u64,
    pub(super) nonvoluntary_context_switches: u64,
    pub(super) cpu_runtime_nanos: u64,
}

pub(super) fn process_sample() -> ProcessSample {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let value = |prefix: &str| -> u64 {
        status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|tail| tail.split_ascii_whitespace().next())
            .and_then(|field| field.parse().ok())
            .unwrap_or(0)
    };
    let mut cpu_runtime_nanos = 0u64;
    let mut voluntary_context_switches = 0u64;
    let mut nonvoluntary_context_switches = 0u64;
    if let Ok(tasks) = fs::read_dir("/proc/self/task") {
        for task in tasks.flatten() {
            let task_path = task.path();
            let runtime = fs::read_to_string(task_path.join("schedstat"))
                .ok()
                .and_then(|line| line.split_ascii_whitespace().next()?.parse::<u64>().ok())
                .unwrap_or(0);
            cpu_runtime_nanos = cpu_runtime_nanos.saturating_add(runtime);
            let task_status = fs::read_to_string(task_path.join("status")).unwrap_or_default();
            let task_value = |prefix: &str| -> u64 {
                task_status
                    .lines()
                    .find_map(|line| line.strip_prefix(prefix))
                    .and_then(|tail| tail.split_ascii_whitespace().next())
                    .and_then(|field| field.parse().ok())
                    .unwrap_or(0)
            };
            voluntary_context_switches =
                voluntary_context_switches.saturating_add(task_value("voluntary_ctxt_switches:"));
            nonvoluntary_context_switches = nonvoluntary_context_switches
                .saturating_add(task_value("nonvoluntary_ctxt_switches:"));
        }
    }
    ProcessSample {
        rss_kib: value("VmRSS:"),
        swap_kib: value("VmSwap:"),
        voluntary_context_switches,
        nonvoluntary_context_switches,
        cpu_runtime_nanos,
    }
}

#[cfg(test)]
mod tests {
    use super::ContentEvidence;

    #[test]
    fn validation_content_evidence_has_no_path_field() {
        let value = serde_json::to_value(ContentEvidence {
            bytes: 7,
            sha256: "ab".repeat(32),
        })
        .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert_eq!(value["bytes"], 7);
        assert_eq!(value["sha256"], "ab".repeat(32));
        assert!(value.get("path").is_none());
    }
}
