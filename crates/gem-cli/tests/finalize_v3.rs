//! Exercise the CLI boundary used to recover a completed validation-failed build.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use gem_core::{
    GRAPH_CHECKPOINT_MAGIC_V3, INDEX_MAGIC_V3, decode_frame_v3, encode_frame_v3, sha256_file,
};
use gem_search::{GraphCheckpointV3, SearchIndexV3};
use serde_json::{Value, json};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn npy(path: &Path, dtype: &str, shape: &str, payload: &[u8]) {
    let mut header = format!("{{'descr': '{dtype}', 'fortran_order': False, 'shape': {shape}, }}");
    let padding = (64 - (10 + header.len() + 1) % 64) % 64;
    header.extend(std::iter::repeat_n(' ', padding));
    header.push('\n');
    let mut bytes = b"\x93NUMPY\x01\x00".to_vec();
    bytes.extend_from_slice(&(header.len() as u16).to_le_bytes());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(payload);
    fs::write(path, bytes).unwrap();
}

fn run(dir: &Path, args: &[&str], success: bool) -> Output {
    let output = Command::new(env!("CARGO_BIN_EXE_gem-native-v3"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

#[test]
fn finalize_preserves_complete_graph_and_accepts_disconnection_but_rejects_invalid_sources() {
    let fixture = Fixture(std::env::temp_dir().join(format!(
            "gem-v3-finalize-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    let dir = &fixture.0;
    fs::create_dir_all(dir.join("codes")).unwrap();
    fs::create_dir(dir.join("encoder")).unwrap();
    npy(
        &dir.join("fine.npy"),
        "<f2",
        "(1, 1)",
        &0x3800u16.to_le_bytes(),
    );
    npy(
        &dir.join("coarse.npy"),
        "<f4",
        "(1, 1)",
        &0.5f32.to_le_bytes(),
    );
    npy(&dir.join("map.npy"), "<i4", "(1,)", &0i32.to_le_bytes());
    npy(
        &dir.join("codes/doc_codes_0.npy"),
        "<i4",
        "(3,)",
        &[0u8; 12],
    );
    npy(
        &dir.join("encoder/doclens0.npy"),
        "<i8",
        "(3,)",
        &[1i64.to_le_bytes(); 3].concat(),
    );
    npy(
        &dir.join("encoder/encoding0_float16.npy"),
        "<f2",
        "(3, 1)",
        &[0x3800u16.to_le_bytes(); 3].concat(),
    );
    npy(
        &dir.join("queries.npy"),
        "<f4",
        "(1, 1, 1)",
        &1f32.to_le_bytes(),
    );
    write_json(&dir.join("ids.json"), &json!([0]));
    run(
        dir,
        &[
            "build",
            "--index-builder-commit",
            "0123456789012345678901234567890123456789",
            "--builder-kind",
            "repo-sequential-oracle",
            "--wave-size",
            "1",
            "--build-threads",
            "1",
            "--dimension",
            "1",
            "--max-doc-tokens",
            "1",
            "--fine-centroids-npy",
            "fine.npy",
            "--coarse-centroids-npy",
            "coarse.npy",
            "--fine-to-coarse-npy",
            "map.npy",
            "--code-dir",
            "codes",
            "--doclens-dir",
            "encoder",
            "--output",
            "original.v3",
            "--checkpoint",
            "checkpoint.v3",
            "--report",
            "build.json",
            "--progress-jsonl",
            "progress.jsonl",
            "--posting-sizes-json",
            "postings.json",
        ],
        true,
    );
    let original_report = read_json(&dir.join("build.json"));
    assert_eq!(original_report["repair_policy"], "repo-faithful");
    run(
        dir,
        &[
            "finalize",
            "--build-report",
            "build.json",
            "--output",
            "copy.v3",
            "--report",
            "copy.json",
        ],
        true,
    );
    assert_eq!(
        fs::read(dir.join("original.v3")).unwrap(),
        fs::read(dir.join("copy.v3")).unwrap()
    );

    // Model a retained old build which failed only the reachability gate.
    let mut checkpoint: GraphCheckpointV3 = decode_frame_v3(
        GRAPH_CHECKPOINT_MAGIC_V3,
        &fs::read(dir.join("checkpoint.v3")).unwrap(),
        1 << 20,
    )
    .unwrap();
    checkpoint.state.adjacency.iter_mut().for_each(Vec::clear);
    checkpoint.builder_binary_sha256 = "a".repeat(64);
    let bytes = encode_frame_v3(GRAPH_CHECKPOINT_MAGIC_V3, &checkpoint).unwrap();
    fs::write(dir.join("checkpoint.v3"), &bytes).unwrap();
    let mut failed = original_report.clone();
    failed["status"] = json!("validation-failed");
    failed["validation_error"] = json!("V3 directed cluster reachability failed");
    failed["output"] = Value::Null;
    failed["validation"] = Value::Null;
    failed["builder_binary"]["sha256"] = json!(checkpoint.builder_binary_sha256);
    failed["checkpoint"]["sha256"] =
        json!(hex::encode(sha256_file(dir.join("checkpoint.v3")).unwrap()));
    failed["checkpoint"]["bytes"] = json!(bytes.len());
    write_json(&dir.join("failed.json"), &failed);
    let report_before = fs::read(dir.join("failed.json")).unwrap();
    run(
        dir,
        &[
            "finalize",
            "--build-report",
            "failed.json",
            "--output",
            "disconnected.v3",
            "--report",
            "finalize.json",
        ],
        true,
    );
    let report = read_json(&dir.join("finalize.json"));
    assert_eq!(report["validation"]["unreachable_memberships"], 2);
    assert_eq!(report["validation"]["directed_reachability_passed"], false);
    assert_eq!(report["builder_binary"]["sha256"], "a".repeat(64));
    assert_ne!(
        report["builder_binary"]["sha256"],
        report["finalizer_binary"]["sha256"]
    );
    assert_eq!(bytes, fs::read(dir.join("checkpoint.v3")).unwrap());
    assert_eq!(report_before, fs::read(dir.join("failed.json")).unwrap());
    let index: SearchIndexV3 = decode_frame_v3(
        INDEX_MAGIC_V3,
        &fs::read(dir.join("disconnected.v3")).unwrap(),
        1 << 20,
    )
    .unwrap();
    assert!(index.documents.iter().all(|doc| doc.adjacency.is_empty()));
    run(
        dir,
        &[
            "validate",
            "--index",
            "disconnected.v3",
            "--report",
            "validate.json",
        ],
        true,
    );
    run(
        dir,
        &[
            "query",
            "--index",
            "disconnected.v3",
            "--encoder-dir",
            "encoder",
            "--code-dir",
            "codes",
            "--queries-npy",
            "queries.npy",
            "--query-ids",
            "ids.json",
            "--query-tokens",
            "1",
            "--k",
            "2",
            "--rerank-k",
            "3",
            "--ef-search",
            "3",
            "--cluster-top-t",
            "1",
            "--threads",
            "1",
            "--output",
            "query.json",
        ],
        true,
    );
    let query = read_json(&dir.join("query.json"));
    assert_eq!(
        query["rows"][0]["native"]["exact"]["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Existing output, partial run, altered input, and wrong checkpoint are rejected.
    run(
        dir,
        &[
            "finalize",
            "--build-report",
            "failed.json",
            "--output",
            "disconnected.v3",
            "--report",
            "duplicate.json",
        ],
        false,
    );
    let mut partial = failed.clone();
    partial["status"] = json!("partial-checkpoint");
    write_json(&dir.join("partial.json"), &partial);
    run(
        dir,
        &[
            "finalize",
            "--build-report",
            "partial.json",
            "--output",
            "invalid.v3",
            "--report",
            "invalid.json",
        ],
        false,
    );
    let fine = fs::read(dir.join("fine.npy")).unwrap();
    fs::write(dir.join("fine.npy"), b"changed input").unwrap();
    run(
        dir,
        &[
            "finalize",
            "--build-report",
            "failed.json",
            "--output",
            "invalid.v3",
            "--report",
            "invalid.json",
        ],
        false,
    );
    fs::write(dir.join("fine.npy"), fine).unwrap();
    run(
        dir,
        &[
            "finalize",
            "--build-report",
            "build.json",
            "--output",
            "invalid.v3",
            "--report",
            "invalid.json",
        ],
        false,
    );

    checkpoint.state.next_cluster = 0;
    let bytes = encode_frame_v3(GRAPH_CHECKPOINT_MAGIC_V3, &checkpoint).unwrap();
    fs::write(dir.join("checkpoint.v3"), &bytes).unwrap();
    failed["checkpoint"]["bytes"] = json!(bytes.len());
    failed["checkpoint"]["sha256"] =
        json!(hex::encode(sha256_file(dir.join("checkpoint.v3")).unwrap()));
    write_json(&dir.join("failed.json"), &failed);
    run(
        dir,
        &[
            "finalize",
            "--build-report",
            "failed.json",
            "--output",
            "invalid.v3",
            "--report",
            "invalid.json",
        ],
        false,
    );
    assert!(!dir.join("invalid.v3").exists());
}
