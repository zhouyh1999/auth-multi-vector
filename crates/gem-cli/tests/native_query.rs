use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gem-v3-cli-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn npy(&self, name: &str, dtype: &str, shape: &str, payload: &[u8]) {
        let mut header =
            format!("{{'descr': '{dtype}', 'fortran_order': False, 'shape': {shape}}}");
        header.push_str(&" ".repeat((64 - (10 + header.len() + 1) % 64) % 64));
        header.push('\n');
        let mut bytes = b"\x93NUMPY\x01\x00".to_vec();
        bytes.extend_from_slice(&(header.len() as u16).to_le_bytes());
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(payload);
        fs::write(self.0.join(name), bytes).unwrap();
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_gem-native-v3"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }

    fn raw(&self, n: usize) {
        self.npy(
            "doc_codes_0.npy",
            "<i4",
            &format!("({n},)"),
            &vec![0; n * 4],
        );
        let lengths: Vec<u8> = (0..n).flat_map(|_| 1_i64.to_le_bytes()).collect();
        self.npy("doclens0.npy", "<i8", &format!("({n},)"), &lengths);
        let vectors: Vec<u8> = (0..n).flat_map(|_| [0x00, 0x3c, 0x00, 0x00]).collect();
        self.npy(
            "encoding0_float16.npy",
            "<f2",
            &format!("({n}, 2)"),
            &vectors,
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn query_batch_handles_empty_buckets_and_determinism_checks_raw_count() {
    let fixture = Fixture::new();
    fixture.npy("fine.npy", "<f2", "(1, 2)", &[0x00, 0x3c, 0x00, 0x00]);
    let vectors: Vec<u8> = [1_f32, 0.0, 0.0, 1.0]
        .into_iter()
        .flat_map(f32::to_le_bytes)
        .collect();
    fixture.npy("coarse.npy", "<f4", "(2, 2)", &vectors);
    fixture.npy("queries.npy", "<f4", "(2, 1, 2)", &vectors);
    fixture.npy("map.npy", "<i4", "(1,)", &[0; 4]);
    fixture.raw(2);
    fs::write(fixture.0.join("ids.json"), b"[0,1]").unwrap();
    let build = fixture.run(&[
        "build",
        "--index-builder-commit",
        "0000000000000000000000000000000000000000",
        "--builder-kind",
        "repo-sequential-oracle",
        "--fine-centroids-npy",
        "fine.npy",
        "--coarse-centroids-npy",
        "coarse.npy",
        "--fine-to-coarse-npy",
        "map.npy",
        "--code-dir",
        ".",
        "--doclens-dir",
        ".",
        "--dimension",
        "2",
        "--max-doc-tokens",
        "1",
        "--wave-size",
        "1",
        "--build-threads",
        "1",
        "--output",
        "index.v3",
        "--checkpoint",
        "checkpoint.v3",
        "--report",
        "build.json",
        "--progress-jsonl",
        "progress.jsonl",
        "--posting-sizes-json",
        "postings.json",
    ]);
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let common = [
        "--index",
        "index.v3",
        "--encoder-dir",
        ".",
        "--code-dir",
        ".",
        "--queries-npy",
        "queries.npy",
        "--query-ids",
        "ids.json",
        "--query-tokens",
        "1",
        "--k",
        "1",
    ];
    let mut args = vec!["query"];
    args.extend(common);
    args.extend([
        "--rerank-k",
        "2",
        "--ef-search",
        "2",
        "--cluster-top-t",
        "1",
        "--threads",
        "2",
        "--output",
        "query.json",
    ]);
    let query = fixture.run(&args);
    assert!(
        query.status.success(),
        "{}",
        String::from_utf8_lossy(&query.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.0.join("query.json")).unwrap()).unwrap();
    assert_eq!(report["rows"].as_array().unwrap().len(), 2);
    assert_eq!(
        report["rows"][0]["native"]["exact"]["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        report["rows"][1]["native"]["exact"]["results"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let mut deterministic = vec!["determinism"];
    deterministic.extend(common);
    deterministic.extend([
        "--rerank-k",
        "2",
        "--ef-search",
        "2",
        "--cluster-top-t",
        "1",
        "--threads",
        "1,2",
        "--repetitions",
        "2",
        "--output",
        "determinism.json",
    ]);
    assert!(fixture.run(&deterministic).status.success());

    // Every direct query-family entry point must reject a whole missing middle
    // shard even though shard 0 alone still matches the index document count.
    let shard_names = [
        ("doc_codes_0.npy", "doc_codes_2.npy"),
        ("doclens0.npy", "doclens2.npy"),
        ("encoding0_float16.npy", "encoding2_float16.npy"),
    ];
    for (source, target) in shard_names {
        fs::copy(fixture.0.join(source), fixture.0.join(target)).unwrap();
    }
    for mode in ["query", "exact-oracle", "determinism"] {
        let mut args = vec![mode];
        args.extend(common);
        args.extend(["--threads", "1", "--output", "gap.json"]);
        let result = fixture.run(&args);
        assert!(
            !result.status.success(),
            "{mode} silently accepted a shard gap"
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("missing shard 1"));
    }
    for (_, target) in shard_names {
        fs::remove_file(fixture.0.join(target)).unwrap();
    }
    fixture.raw(3);
    for mode in ["query", "exact-oracle", "determinism"] {
        let mut args = vec![mode];
        args.extend(common);
        args.extend(["--output", "mismatched.json"]);
        if mode == "determinism" {
            args.extend(["--threads", "1,2", "--repetitions", "2"]);
        } else {
            args.extend(["--threads", "1"]);
        }
        let result = fixture.run(&args);
        assert!(
            !result.status.success(),
            "{mode} accepted mismatched raw count"
        );
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("counts differ"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn shard_discovery_and_compact_import_reject_gaps_without_a_preflight() {
    use gem_search::{discover_official_shard_ids_v3, import_compact_codes};
    let fixture = Fixture::new();
    let path = fixture.0.as_path();
    assert!(discover_official_shard_ids_v3(path, path, None).is_err());
    fixture.raw(2);
    let members = [
        ("doc_codes_0.npy", "doc_codes_1.npy", "doc_codes_2.npy"),
        ("doclens0.npy", "doclens1.npy", "doclens2.npy"),
        (
            "encoding0_float16.npy",
            "encoding1_float16.npy",
            "encoding2_float16.npy",
        ),
    ];
    for (source, _, target) in members {
        fs::copy(path.join(source), path.join(target)).unwrap();
    }
    assert!(
        import_compact_codes(path, path, 1, 1)
            .unwrap_err()
            .to_string()
            .contains("missing shard 1")
    );
    // Build discovers the gap before opening even the deliberately invalid
    // fine/coarse placeholders, proving evidence collection uses the helper.
    fs::write(path.join("placeholder"), b"not an npy").unwrap();
    let result = fixture.run(&[
        "build",
        "--index-builder-commit",
        "0000000000000000000000000000000000000000",
        "--fine-centroids-npy",
        "placeholder",
        "--builder-kind",
        "repo-sequential-oracle",
        "--wave-size",
        "1",
        "--build-threads",
        "1",
        "--coarse-centroids-npy",
        "placeholder",
        "--fine-to-coarse-npy",
        "placeholder",
        "--code-dir",
        ".",
        "--doclens-dir",
        ".",
        "--output",
        "gap-index.v3",
        "--checkpoint",
        "gap-checkpoint.v3",
        "--report",
        "gap-build.json",
        "--progress-jsonl",
        "gap-progress.jsonl",
        "--posting-sizes-json",
        "gap-postings.json",
    ]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("missing shard 1"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!path.join("gap-index.v3").exists());
    // Filling the gap imports all six documents, not just the original prefix.
    for (source, target, _) in members {
        fs::copy(path.join(source), path.join(target)).unwrap();
    }
    assert_eq!(
        discover_official_shard_ids_v3(path, path, Some(path)).unwrap(),
        vec![0, 1, 2]
    );
    assert_eq!(import_compact_codes(path, path, 1, 1).unwrap().len(), 6);
    assert_eq!(gem_cli::load_raw_corpus(path, path, 2, 1).unwrap().len(), 6);
    fs::remove_file(path.join("encoding2_float16.npy")).unwrap();
    assert!(
        gem_cli::load_raw_corpus(path, path, 2, 1)
            .unwrap_err()
            .to_string()
            .contains("shard IDs differ")
    );
    fs::remove_file(path.join("doclens2.npy")).unwrap();
    assert!(
        import_compact_codes(path, path, 1, 1)
            .unwrap_err()
            .to_string()
            .contains("shard IDs differ")
    );
    fs::copy(path.join("doc_codes_0.npy"), path.join("doc_codes_00.npy")).unwrap();
    assert!(
        discover_official_shard_ids_v3(path, path, None)
            .unwrap_err()
            .to_string()
            .contains("non-canonical shard")
    );
}
