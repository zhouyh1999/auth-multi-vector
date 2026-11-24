use bincode::Options;
use ed25519_dalek::SigningKey;
use gem_auth_v3::*;
use gem_core::{
    GraphBuilderKindV3, QueryV3, RawDocumentV3, SearchDocumentV3, SearchParamsV3, SemanticProfileV3,
};
use gem_search::{GraphBuildParamsV3, SearchIndexV3};
use std::{fs, path::Path, process::Command};
fn call(args: &[&str], cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_gem-raw-auth-v3"))
        .args(args)
        .current_dir(cwd)
        .env("RAYON_NUM_THREADS", "8")
        .output()
        .unwrap()
}
#[test]
fn isolated_process_client_and_persistence() {
    let root = std::env::temp_dir().join(format!(
        "gem-auth-v3-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let client = root.join("client");
    fs::create_dir(&client).unwrap();
    let owner = root.join("owner");
    let output = call(&["keygen", "--output-dir", owner.to_str().unwrap()], &root);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !call(&["keygen", "--output-dir", owner.to_str().unwrap()], &root)
            .status
            .success()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(owner.join("owner.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&owner).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let key = SigningKey::from_bytes(
        &fs::read(owner.join("owner.key"))
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let docs = vec![
        SearchDocumentV3 {
            doc_id: 0,
            token_count: 2,
            compact_codes: vec![0, 0],
            cluster_ids: vec![0],
            adjacency: vec![1],
        },
        SearchDocumentV3 {
            doc_id: 1,
            token_count: 1,
            compact_codes: vec![1],
            cluster_ids: vec![0, 1],
            adjacency: vec![0, 2],
        },
        SearchDocumentV3 {
            doc_id: 2,
            token_count: 1,
            compact_codes: vec![0],
            cluster_ids: vec![1],
            adjacency: vec![1],
        },
    ];
    let raw = vec![
        RawDocumentV3 {
            doc_id: 0,
            token_count: 2,
            dimension: 2,
            coordinate_bits: vec![0x3c00, 0x8000, 0x3c00, 0],
        },
        RawDocumentV3 {
            doc_id: 1,
            token_count: 1,
            dimension: 2,
            coordinate_bits: vec![0, 0x3c00],
        },
        RawDocumentV3 {
            doc_id: 2,
            token_count: 1,
            dimension: 2,
            coordinate_bits: vec![0x3c00, 0],
        },
    ];
    let index = SearchIndexV3 {
        semantic_profile: SemanticProfileV3::repo_faithful(
            GraphBuilderKindV3::RepoDeterministicWavefront,
            16,
        ),
        graph_params: GraphBuildParamsV3 {
            m: 24,
            m0: 48,
            ef_construction: 80,
            qemd_max_iterations: 1000,
            wave_size: 16,
        },
        dimension: 2,
        max_doc_tokens: 2,
        fine_centroids: vec![1., 0., 0., 1.],
        coarse_centroids: vec![1., 0., 0., 1.],
        fine_to_coarse: vec![0, 1],
        cluster_entries: vec![Some(1), Some(2)],
        documents: docs,
    };
    let params = SearchParamsV3 {
        k: 1,
        rerank_k: 2,
        ef_search: 2,
        cluster_top_t: 1,
    };
    let prepared =
        prepare_raw_snapshot_v3(index, &raw, &[81, 82, 83], 1, params.clone(), [0; 32], &key)
            .unwrap();
    let mut snapshot = b"G3SNAP!!".to_vec();
    snapshot.extend(AUTH_SCHEMA_V3.to_le_bytes());
    let payload = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .serialize(&prepared)
        .unwrap();
    snapshot.extend((payload.len() as u64).to_le_bytes());
    snapshot.extend(payload);
    let snapshotpath = root.join("snapshot.auth3");
    fs::write(&snapshotpath, &snapshot).unwrap();
    let validation = root.join("validation.json");
    assert!(
        call(
            &[
                "validate",
                "--snapshot",
                snapshotpath.to_str().unwrap(),
                "--output",
                validation.to_str().unwrap()
            ],
            &root
        )
        .status
        .success()
    );
    fs::write(
        client.join("trusted.json"),
        serde_json::to_vec(&prepared.trusted).unwrap(),
    )
    .unwrap();
    for (position, (wire, mode)) in [
        (RawWireV3::Fp16, PublicModeV3::Cold),
        (RawWireV3::Fp32, PublicModeV3::Cold),
    ]
    .into_iter()
    .enumerate()
    {
        let request = RawRequestV3 {
            manifest_digest: prepared.trusted.expected_manifest_digest,
            query: QueryV3 {
                query_id: 0,
                dimension: 2,
                token_count: 1,
                coordinates: vec![1., -0.],
                params: params.clone(),
            },
            raw_wire: wire,
            public_mode: mode,
        };
        let requestpath = client.join(format!("request-{position}.json"));
        let vopath = client.join(format!("proof-{position}.vo"));
        fs::write(&requestpath, serde_json::to_vec(&request).unwrap()).unwrap();
        let proved = call(
            &[
                "prove",
                "--snapshot",
                snapshotpath.to_str().unwrap(),
                "--request",
                requestpath.to_str().unwrap(),
                "--output",
                vopath.to_str().unwrap(),
                "--threads",
                "8",
            ],
            &root,
        );
        assert!(
            proved.status.success(),
            "{}",
            String::from_utf8_lossy(&proved.stderr)
        );
        let disabled = root.join("server-unavailable");
        fs::rename(&snapshotpath, &disabled).unwrap();
        for threads in ["1", "8"] {
            let output = client.join(format!("verified-{position}-{threads}.json"));
            let args = vec![
                "verify",
                "--trusted",
                "trusted.json",
                "--request",
                requestpath.file_name().unwrap().to_str().unwrap(),
                "--vo",
                vopath.file_name().unwrap().to_str().unwrap(),
                "--output",
                output.file_name().unwrap().to_str().unwrap(),
                "--threads",
                threads,
            ];
            let verified = call(&args, &client);
            assert!(
                verified.status.success(),
                "{}",
                String::from_utf8_lossy(&verified.stderr)
            );
            assert!(!call(&args, &client).status.success());
        }
        fs::rename(&disabled, &snapshotpath).unwrap();
    }
    assert!(
        !call(
            &["verify", "--corpus", "missing", "--index", "missing"],
            &client
        )
        .status
        .success()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn removed_public_cache_cli_is_rejected() {
    let root = std::env::temp_dir();
    let request = call(&["request", "--mode", "cached"], &root);
    assert!(!request.status.success());
    assert!(String::from_utf8_lossy(&request.stderr).contains("invalid value 'cached'"));
    let verify = call(&["verify", "--cache", "obsolete.cache"], &root);
    assert!(!verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stderr).contains("unexpected argument '--cache'"));
    let help = call(&["request", "--help"], &root);
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("[default: cold]"));
    assert!(!help.contains("cached"));
}
