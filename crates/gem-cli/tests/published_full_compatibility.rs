use ed25519_dalek::SigningKey;
use gem_auth_scheme_v3::compact;
use gem_auth_v3::*;
use gem_core::*;
use gem_search::{GraphBuildParamsV3, SearchIndexV3, execute_search_v3};

fn fixture() -> (SearchIndexV3, Vec<RawDocumentV3>, QueryV3) {
    let memberships = (0..25).collect::<Vec<_>>();
    let nodes = vec![
        SearchDocumentV3 {
            doc_id: 0,
            token_count: 1,
            compact_codes: vec![0],
            cluster_ids: memberships.clone(),
            adjacency: vec![2, 1, 2],
        },
        SearchDocumentV3 {
            doc_id: 1,
            token_count: 1,
            compact_codes: vec![1],
            cluster_ids: memberships.clone(),
            adjacency: vec![0, 2],
        },
        SearchDocumentV3 {
            doc_id: 2,
            token_count: 1,
            compact_codes: vec![0],
            cluster_ids: memberships,
            adjacency: vec![1, 0],
        },
    ];
    let index = SearchIndexV3 {
        semantic_profile: SemanticProfileV3::published_fixed_graph(),
        graph_params: GraphBuildParamsV3 {
            m: 24,
            m0: 48,
            ef_construction: 80,
            qemd_max_iterations: 1000,
            wave_size: 1,
        },
        dimension: 2,
        max_doc_tokens: 3,
        fine_centroids: vec![1., 0., 0., 1.],
        coarse_centroids: (0..25).flat_map(|_| [1., 0.]).collect(),
        fine_to_coarse: vec![],
        cluster_entries: vec![Some(0); 25],
        documents: nodes,
    };
    let raw = vec![[1., 0.], [0., 1.], [0.5, 0.5]]
        .into_iter()
        .enumerate()
        .map(|(id, values)| RawDocumentV3 {
            doc_id: id as u32,
            dimension: 2,
            token_count: 1,
            coordinate_bits: values
                .iter()
                .map(|&x| half::f16::from_f32(x).to_bits())
                .collect(),
        })
        .collect();
    let query = QueryV3 {
        query_id: 42,
        dimension: 2,
        token_count: 1,
        coordinates: vec![1., 0.],
        params: SearchParamsV3 {
            k: 2,
            rerank_k: 3,
            ef_search: 3,
            cluster_top_t: 2,
        },
    };
    (index, raw, query)
}

#[test]
fn published_graph_preserves_25_memberships_order_and_original_entry_in_both_wire_codecs() {
    let (index, raw, query) = fixture();
    let summary = index.validate_policy().unwrap();
    assert_eq!(summary.membership_count, 75);
    assert_eq!(index.cluster_entries[0], Some(0)); // Original entry is not maximum posting ID.
    let reference = execute_search_v3(&index, (&index).into(), &query).unwrap();
    let original_order = index.documents[0].adjacency.clone();
    let key = SigningKey::from_bytes(&[17; 32]);
    let prepared = prepare_raw_snapshot_v3(
        index,
        &raw,
        &[100, 200, 300],
        1,
        query.params.clone(),
        [3; 32],
        &key,
    )
    .unwrap();
    let trusted = prepared.trusted.clone();
    let server = initialize_server_snapshot_v3(prepared.clone()).unwrap();
    for raw_wire in [RawWireV3::Fp16, RawWireV3::Fp32] {
        let request = RawRequestV3 {
            manifest_digest: trusted.expected_manifest_digest,
            query: query.clone(),
            raw_wire,
            public_mode: PublicModeV3::Cold,
        };
        let vo = execute_raw_retrieval_v3(&server, &request).unwrap();
        let (bytes, _) = encode_raw_vo_v3(&vo).unwrap();
        let verified = verify_raw_retrieval_v3(&trusted, &request, &bytes).unwrap();
        assert_eq!(verified.execution, reference);
        assert_eq!(server.index.documents[0].adjacency, original_order);
        let mut corrupted = vo.clone();
        corrupted
            .documents
            .iter_mut()
            .find(|d| d.metadata.doc_id == 0)
            .unwrap()
            .membership = ComponentOpening::Revealed((0..24).collect());
        let (bytes, _) = encode_raw_vo_v3(&corrupted).unwrap();
        assert!(verify_raw_retrieval_v3(&trusted, &request, &bytes).is_err());
    }
    let (scheme, _) = compact::prepare_scheme_snapshot_v3(prepared, &key).unwrap();
    let trusted = scheme.trusted.clone();
    let server = compact::initialize_scheme_server_snapshot_v3(scheme).unwrap();
    let mut expected = None;
    for backend in [
        compact::SchemeBackendV3::FixedRawFp16,
        compact::SchemeBackendV3::FixedRawFp32,
        compact::SchemeBackendV3::MatrixScheme,
    ] {
        let request = compact::SchemeRequestV3 {
            manifest_digest: trusted.expected_manifest_digest,
            query: query.clone(),
            backend,
            public_mode: PublicModeV3::Cold,
        };
        let vo = compact::execute_scheme_retrieval_v3(&server, &request).unwrap();
        let (bytes, _) = compact::encode_scheme_vo_v3(&vo).unwrap();
        let verified = compact::verify_scheme_retrieval_v3(&trusted, &request, &bytes).unwrap();
        let semantic = (verified.execution, verified.results);
        if let Some(ref old) = expected {
            assert_eq!(&semantic, old)
        } else {
            expected = Some(semantic)
        }
    }
}

#[test]
fn streamed_hash_is_exactly_the_previous_canonical_hash() {
    let rows = vec![vec![0u16, 1, 0x8000, 0x3c00, 0xbc00], vec![0xffff; 70000]];
    assert_eq!(
        hash_serialized(b"binding", &rows).unwrap(),
        hash_bytes(b"binding", &bincode::serialize(&rows).unwrap())
    );
    let (index, _, _) = fixture();
    assert_eq!(
        hash_serialized(b"index", &index).unwrap(),
        hash_bytes(b"index", &bincode::serialize(&index).unwrap())
    );
}

#[test]
fn full_fine_codebook_dimension_is_supported_without_weakening_the_allocation_bound() {
    let ctx = gem_matrix_proof::ProjectionContextV1 {
        binding: [0; 32],
        stage: gem_matrix_proof::ProjectionStageV1::Fine,
        rows: 262144,
        columns: 128,
        commitment: [0; 32],
    };
    assert_eq!(ctx.dimension().unwrap(), 1 << 25);
    let invalid = gem_matrix_proof::ProjectionContextV1 {
        rows: 262145,
        ..ctx
    };
    assert!(invalid.dimension().is_err());
}

#[test]
fn streamed_legacy_offline_reader_preserves_frames_and_rejects_lengths() {
    let dir = std::env::temp_dir().join(format!("gem-offline-reader-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("frame");
    let values = vec![1u32, 7, 99];
    let bytes = encode_frame_v3(*b"GEMIDXV3", &values).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let decoded: Vec<u32> =
        gem_cli::full_snapshot::load_legacy_offline_frame(&path, b"GEMIDXV3", 2).unwrap();
    assert_eq!(decoded, values);
    let mut bad = bytes.clone();
    bad[10..18].fill(255);
    std::fs::write(&path, bad).unwrap();
    assert!(
        gem_cli::full_snapshot::load_legacy_offline_frame::<Vec<u32>>(&path, b"GEMIDXV3", 2)
            .is_err()
    );
    std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
    assert!(
        gem_cli::full_snapshot::load_legacy_offline_frame::<Vec<u32>>(&path, b"GEMIDXV3", 2)
            .is_err()
    );
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
