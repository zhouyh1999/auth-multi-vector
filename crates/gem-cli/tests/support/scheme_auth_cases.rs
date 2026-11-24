use super::family::*;
use bincode::Options;
use ed25519_dalek::{Signer, SigningKey};
use gem_auth_v3::{PublicModeV3, prepare_raw_snapshot_v3};
use gem_core::{
    GraphBuilderKindV3, QueryV3, RawDocumentV3, SearchDocumentV3, SearchParamsV3, SemanticProfileV3,
};
use gem_search::{GraphBuildParamsV3, SearchIndexV3};
use std::{fs, path::Path, process::Command};
fn call(args: &[&str], cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_gem-scheme-auth-v3"))
        .args(args)
        .current_dir(cwd)
        .env("RAYON_NUM_THREADS", "8")
        .output()
        .unwrap()
}
#[test]
fn isolated_process_client_and_persistence() {
    let root = std::env::temp_dir().join(format!(
        "gem-scheme-auth-v3-cli-{}-{}",
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
    let raw_prepared =
        prepare_raw_snapshot_v3(index, &raw, &[81, 82, 83], 1, params.clone(), [0; 32], &key)
            .unwrap();
    let sourcepath = root.join("source.auth3");
    let raw_payload = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .serialize(&raw_prepared)
        .unwrap();
    let mut raw_frame = b"G3SNAP!!".to_vec();
    raw_frame.extend(gem_auth_v3::AUTH_SCHEMA_V3.to_le_bytes());
    raw_frame.extend((raw_payload.len() as u64).to_le_bytes());
    raw_frame.extend(raw_payload);
    fs::write(&sourcepath, raw_frame).unwrap();
    let (prepared, _) = prepare_scheme_snapshot_v3(raw_prepared, &key).unwrap();
    let published = root.join("published");
    let owner_key = owner.join("owner.key");
    let mut prepare_args = vec![
        "prepare",
        "--raw-snapshot",
        sourcepath.to_str().unwrap(),
        "--owner-key",
        owner_key.to_str().unwrap(),
        "--output-dir",
        published.to_str().unwrap(),
    ];
    // Exercise default schema 9 preparation and explicit schema 8 preparation.
    if SCHEME_AUTH_SCHEMA_V3 == 8 {
        prepare_args.extend(["--numeric-profile", "s16"]);
    }
    let prepared_cli = call(&prepare_args, &root);
    assert!(
        prepared_cli.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared_cli.stderr)
    );
    let provisioned: serde_json::Value =
        serde_json::from_slice(&fs::read(published.join("preparation.json")).unwrap()).unwrap();
    assert_eq!(provisioned["reloaded_commitments_rebuilt"], true);
    assert_eq!(provisioned["client_published_after_deep_validation"], true);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(published.join("client/trusted.json")).unwrap()
        )
        .unwrap(),
        serde_json::to_value(&prepared.trusted).unwrap()
    );
    // A deliberately incorrect NEW-owner preparation may authenticate its own
    // committed matrix, but deep validation must reject the source mismatch.
    let mut bad = prepared.clone();
    bad.fixed_documents[0][0] -= 1;
    bad.commitments[0] = gem_matrix_proof::commit_scalars_v1(
        &bad.fixed_documents[0]
            .iter()
            .map(|&x| gem_matrix_proof::scalar_i64_v1(x as i64))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    bad.component_hashes[0][4] = scheme_component_hash_v3(
        &bad.metadata[0],
        5,
        &DocumentMatrixCommitmentV3::new(bad.commitments[0]),
    )
    .unwrap();
    bad.tree = gem_auth_v3::DocumentTreeV3::build(
        &bad.component_hashes
            .iter()
            .map(scheme_document_leaf_v3)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    bad.trusted.signed.manifest.document_root = bad.tree.root().unwrap();
    bad.trusted.signed.manifest.fixed_documents_digest = gem_core::hash_bytes(
        super::family::numeric::DOCUMENTS_DOMAIN,
        &bincode::serialize(&bad.fixed_documents).unwrap(),
    );
    let bad_digest = scheme_manifest_digest_v3(&bad.trusted.signed.manifest).unwrap();
    bad.trusted.expected_manifest_digest = bad_digest;
    bad.trusted.signed.signature = key.sign(&bad_digest).to_bytes().to_vec();
    assert!(initialize_scheme_server_snapshot_v3(bad.clone()).is_ok());
    assert!(validate_scheme_snapshot_v3(&bad).is_err());
    let bad_payload = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .serialize(&bad)
        .unwrap();
    let mut bad_frame = SNAPSHOT_MAGIC.to_vec();
    bad_frame.extend(SCHEME_AUTH_SCHEMA_V3.to_le_bytes());
    bad_frame.extend((bad_payload.len() as u64).to_le_bytes());
    bad_frame.extend(bad_payload);
    let bad_path = root.join("wrong-owner-preparation.scheme3");
    fs::write(&bad_path, bad_frame).unwrap();
    let bad_report = root.join("wrong-owner-preparation-validation.json");
    assert!(
        !call(
            &[
                "validate",
                "--snapshot",
                bad_path.to_str().unwrap(),
                "--output",
                bad_report.to_str().unwrap()
            ],
            &root
        )
        .status
        .success()
    );
    assert!(!bad_report.exists());
    let mut snapshot = SNAPSHOT_MAGIC.to_vec();
    snapshot.extend(SCHEME_AUTH_SCHEMA_V3.to_le_bytes());
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
    for (position, (backend, mode)) in [
        (SchemeBackendV3::FixedRawFp16, PublicModeV3::Cold),
        (SchemeBackendV3::FixedRawFp32, PublicModeV3::Cold),
        (SchemeBackendV3::MatrixScheme, PublicModeV3::Cold),
    ]
    .into_iter()
    .enumerate()
    {
        let request = SchemeRequestV3 {
            manifest_digest: prepared.trusted.expected_manifest_digest,
            query: QueryV3 {
                query_id: 0,
                dimension: 2,
                token_count: 1,
                coordinates: vec![1., -0.],
                params: params.clone(),
            },
            backend,
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
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(vopath.with_extension("server.json")).unwrap())
                .unwrap();
        assert_eq!(report["vo_sha256_kind"], "sha256-file-v1");
        assert_eq!(
            report["vo_sha256"],
            hex::encode(gem_core::sha256_file(&vopath).unwrap())
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
    // Run the real serializer/bench for all backend/mode/thread combinations.
    // Report digests must identify the persisted files, including matrix proofs.
    let queries = root.join("queries.npy");
    let mut header = "{'descr': '<f4', 'fortran_order': False, 'shape': (1, 1, 2), }"
        .as_bytes()
        .to_vec();
    while !(10 + header.len() + 1).is_multiple_of(16) {
        header.push(b' ');
    }
    header.push(b'\n');
    let mut npy = b"\x93NUMPY\x01\x00".to_vec();
    npy.extend((header.len() as u16).to_le_bytes());
    npy.extend(header);
    npy.extend(1.0f32.to_le_bytes());
    npy.extend((-0.0f32).to_le_bytes());
    fs::write(&queries, npy).unwrap();
    let ids = root.join("query-ids.json");
    fs::write(&ids, b"[0]").unwrap();
    let bench_dir = root.join("bench");
    let bench = call(
        &[
            "bench",
            "--snapshot",
            snapshotpath.to_str().unwrap(),
            "--queries-npy",
            queries.to_str().unwrap(),
            "--query-ids",
            ids.to_str().unwrap(),
            "--client-threads",
            "1,8",
            "--persist",
            "--output-dir",
            bench_dir.to_str().unwrap(),
        ],
        &root,
    );
    assert!(
        bench.status.success(),
        "{}",
        String::from_utf8_lossy(&bench.stderr)
    );
    let rows = fs::read_to_string(bench_dir.join("rows.jsonl")).unwrap();
    assert_eq!(rows.lines().count(), 6);
    for line in rows.lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let path = bench_dir.join(format!(
            "q0-{}-{}.vo",
            row["backend"].as_str().unwrap(),
            row["public_mode"].as_str().unwrap()
        ));
        assert_eq!(row["vo_sha256_kind"], "sha256-file-v1");
        assert_eq!(
            row["vo_sha256"],
            hex::encode(gem_core::sha256_file(&path).unwrap())
        );
        assert_eq!(
            row["vo_domain_digest"],
            hex::encode(gem_core::hash_bytes(
                b"gem.scheme.vo.file",
                &fs::read(path).unwrap()
            ))
        );
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
