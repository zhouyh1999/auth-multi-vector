use super::numeric::{FixedQueryV3, IS_COMPACT};
use super::*;
use ed25519_dalek::SigningKey;
use gem_auth_v3::{
    ComponentOpening, PreparedRawSnapshotV3, PublicModeV3, RawOpeningV3, prepare_raw_snapshot_v3,
};
use gem_core::{
    GraphBuilderKindV3, QueryV3, RawDocumentV3, SearchDocumentV3, SearchParamsV3, SemanticProfileV3,
};
use gem_search::{GraphBuildParamsV3, SearchIndexV3};
use half::f16;
use rand::{Rng, SeedableRng};
fn raw_fixture(seed: u64) -> (PreparedRawSnapshotV3, QueryV3) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let n = rng.gen_range(3..18);
    let fine: Vec<f32> = (0..8 * 4)
        .map(|_| rng.gen_range(-4..5) as f32 / if IS_COMPACT { 8. } else { 4. })
        .collect();
    let mut docs = Vec::new();
    let mut raw = Vec::new();
    for id in 0..n {
        let count = rng.gen_range(1..6);
        let codes: Vec<u32> = (0..count).map(|_| rng.gen_range(0..8)).collect();
        let clusters: Vec<u32> = if seed.is_multiple_of(11) {
            vec![0]
        } else {
            (0..3).filter(|_| rng.gen_bool(0.5)).collect()
        };
        let clusters = if clusters.is_empty() {
            vec![rng.gen_range(0..3)]
        } else {
            clusters
        };
        let adjacency: Vec<u32> = if seed.is_multiple_of(13) {
            vec![]
        } else {
            (0..n).filter(|&x| x != id && rng.gen_bool(0.25)).collect()
        };
        let bits = codes
            .iter()
            .flat_map(|&c| {
                fine[c as usize * 4..c as usize * 4 + 4]
                    .iter()
                    .map(|&v| f16::from_f32(v).to_bits())
            })
            .collect();
        raw.push(RawDocumentV3 {
            doc_id: id,
            token_count: count,
            dimension: 4,
            coordinate_bits: bits,
        });
        docs.push(SearchDocumentV3 {
            doc_id: id,
            token_count: count,
            compact_codes: codes,
            cluster_ids: clusters,
            adjacency,
        });
    }
    let entries = (0..3)
        .map(|c| {
            docs.iter()
                .filter(|d| d.cluster_ids.contains(&c))
                .map(|d| d.doc_id)
                .max()
        })
        .collect();
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
        dimension: 4,
        max_doc_tokens: 5,
        fine_centroids: fine,
        coarse_centroids: vec![1., 0., 0., 0., 0., 1., 0., 0., 0., 0., 1., 0.],
        fine_to_coarse: (0..8).map(|c| c % 3).collect(),
        cluster_entries: entries,
        documents: docs,
    };
    let params = SearchParamsV3 {
        k: 2,
        rerank_k: 2,
        ef_search: 2,
        cluster_top_t: if seed.is_multiple_of(7) { 3 } else { 1 },
    };
    let q = QueryV3 {
        query_id: seed,
        dimension: 4,
        token_count: 2,
        coordinates: if seed.is_multiple_of(11) {
            vec![0., 1., 0., 0., 0., 1., 0., 0.]
        } else {
            (0..8)
                .map(|_| rng.gen_range(-4..5) as f32 / if IS_COMPACT { 8. } else { 4. })
                .collect()
        },
        params: params.clone(),
    };
    let snapshot = prepare_raw_snapshot_v3(
        index,
        &raw,
        &(0..n).map(|x| u64::from(x) + 100).collect::<Vec<_>>(),
        2,
        params,
        [7; 32],
        &SigningKey::from_bytes(&[42; 32]),
    )
    .unwrap();
    (snapshot, q)
}

pub(super) fn fixture(seed: u64) -> (SchemeServerSnapshotV3, QueryV3) {
    let (raw, q) = raw_fixture(seed);
    let (s, _) = prepare_scheme_snapshot_v3(raw, &SigningKey::from_bytes(&[42; 32])).unwrap();
    validate_scheme_snapshot_v3(&s).unwrap();
    (initialize_scheme_server_snapshot_v3(s).unwrap(), q)
}
pub(super) fn req(
    s: &SchemeServerSnapshotV3,
    q: &QueryV3,
    b: SchemeBackendV3,
    m: PublicModeV3,
) -> SchemeRequestV3 {
    SchemeRequestV3 {
        manifest_digest: s.trusted.expected_manifest_digest,
        query: q.clone(),
        backend: b,
        public_mode: m,
    }
}
fn reject(s: &SchemeServerSnapshotV3, r: &SchemeRequestV3, v: &SchemeRetrievalVoV3) {
    let b = encode_scheme_vo_v3(v).unwrap().0;
    assert!(verify_scheme_retrieval_v3(&s.trusted, r, &b).is_err());
}

#[test]
fn separate_five_component_trees_and_backend_specific_wire() {
    // Disconnected graph: the VO opens a strict subset, so sibling hashes differ.
    let (s, q) = fixture(13);
    let manifest = &s.trusted.signed.manifest;
    assert_eq!(s.raw_tree.root().unwrap(), manifest.source().document_root);
    assert_eq!(s.tree.root().unwrap(), manifest.document_root);
    assert_ne!(manifest.document_root, manifest.source().document_root);
    let raw_request = req(&s, &q, SchemeBackendV3::FixedRawFp16, PublicModeV3::Cold);
    let scheme_request = req(&s, &q, SchemeBackendV3::MatrixScheme, PublicModeV3::Cold);
    let raw = execute_scheme_retrieval_v3(&s, &raw_request).unwrap();
    let scheme = execute_scheme_retrieval_v3(&s, &scheme_request).unwrap();
    assert!(!raw.proof.siblings.is_empty());
    assert_eq!(raw.results, scheme.results);
    for (request, vo) in [(&raw_request, &raw), (&scheme_request, &scheme)] {
        let (bytes, stats) = encode_scheme_vo_v3(vo).unwrap();
        let decoded = decode_scheme_vo_v3(&bytes, &s.trusted).unwrap();
        assert_eq!(stats.parts["metadata"], 6 * decoded.documents.len());
        let hidden_count = decoded
            .documents
            .iter()
            .map(|d| {
                assert!(d.vector.matches_backend(request.backend));
                usize::from(!d.membership.is_revealed())
                    + usize::from(!d.codes.is_revealed())
                    + usize::from(!d.adjacency.is_revealed())
                    + usize::from(!d.vector.is_revealed())
            })
            .sum::<usize>();
        assert_eq!(
            stats.parts.get("hidden_digests").copied().unwrap_or(0),
            hidden_count * 32
        );
        if request.backend == SchemeBackendV3::MatrixScheme {
            assert!(!stats.parts.contains_key("raw"));
        } else {
            assert!(!stats.parts.contains_key("commitments"));
        }
        verify_scheme_retrieval_v3(&s.trusted, request, &bytes).unwrap();
    }
    let mut swapped = scheme.clone();
    swapped.proof = raw.proof.clone();
    reject(&s, &scheme_request, &swapped);
    swapped = raw.clone();
    swapped.proof = scheme.proof.clone();
    reject(&s, &raw_request, &swapped);

    // The encoder cannot emit both vector types or a placeholder for the other one.
    let mut wrong_type = scheme;
    wrong_type.documents[0].vector = raw.documents[0].vector.clone();
    assert!(encode_scheme_vo_v3(&wrong_type).is_err());
    let mut wrong_type = raw;
    wrong_type.documents[0].vector =
        DocumentVectorOpeningV3::Commitment(ComponentOpening::Digest([0; 32]));
    assert!(encode_scheme_vo_v3(&wrong_type).is_err());
}

#[test]
fn stored_raw_and_matrix_trees_are_both_validated() {
    let (raw, _) = raw_fixture(13);
    let (prepared, _) =
        prepare_scheme_snapshot_v3(raw, &SigningKey::from_bytes(&[42; 32])).unwrap();
    let mut bad = prepared.clone();
    bad.raw_component_hashes[0][4][0] ^= 1;
    assert!(initialize_scheme_server_snapshot_v3(bad).is_err());
    let mut bad = prepared.clone();
    bad.raw_tree.levels[0][0][0] ^= 1;
    assert!(initialize_scheme_server_snapshot_v3(bad).is_err());
    let mut bad = prepared.clone();
    bad.source_ids.reverse();
    assert!(initialize_scheme_server_snapshot_v3(bad).is_err());
    let mut bad = prepared;
    bad.component_hashes[0][4][0] ^= 1;
    assert!(initialize_scheme_server_snapshot_v3(bad).is_err());
}
#[test]
fn all_backends_modes_threads_and_empty_entries() {
    for seed in [0, 1, 7, 11, 13, 22] {
        let (s, q) = fixture(seed);
        let mut expected = None;
        for b in [
            SchemeBackendV3::FixedRawFp16,
            SchemeBackendV3::FixedRawFp32,
            SchemeBackendV3::MatrixScheme,
        ] {
            {
                let mode = PublicModeV3::Cold;
                let r = req(&s, &q, b, mode);
                let (v, e, _) = execute_scheme_retrieval_measured_v3(&s, &r).unwrap();
                let (bytes, parts) = encode_scheme_vo_v3(&v).unwrap();
                assert_eq!(parts.total, parts.parts.values().sum::<usize>());
                assert_eq!(bytes.len(), parts.total);
                assert!(!parts.parts.contains_key("commitment_bounds"));
                assert!(!parts.parts.contains_key("token_boundaries"));
                assert_eq!(&bytes[..8], b"G3SCHVO4");
                assert_eq!(
                    parts.parts.get("merkle_siblings").copied().unwrap_or(0),
                    32 * v.proof.siblings.len()
                );
                let raw_bytes: usize = v
                    .documents
                    .iter()
                    .filter_map(|d| match &d.vector {
                        DocumentVectorOpeningV3::Raw(ComponentOpening::Revealed(
                            RawOpeningV3::Fp16(a),
                        )) => Some(a.len() * 2),
                        DocumentVectorOpeningV3::Raw(ComponentOpening::Revealed(
                            RawOpeningV3::Fp32(a),
                        )) => Some(a.len() * 4),
                        _ => None,
                    })
                    .sum();
                assert_eq!(parts.parts.get("raw").copied().unwrap_or(0), raw_bytes);
                let mut old_wire = bytes.clone();
                old_wire[..8].copy_from_slice(b"G3SCHVO!");
                assert!(decode_scheme_vo_v3(&old_wire, &s.trusted).is_err());
                old_wire[..8].copy_from_slice(b"G3SCHVO2");
                assert!(decode_scheme_vo_v3(&old_wire, &s.trusted).is_err());
                old_wire[..8].copy_from_slice(b"G3SCHVO3");
                assert!(decode_scheme_vo_v3(&old_wire, &s.trusted).is_err());
                assert_eq!(
                    parts.parts.get("commitments").copied().unwrap_or(0),
                    if b == SchemeBackendV3::MatrixScheme {
                        32 * v
                            .documents
                            .iter()
                            .filter(|d| d.vector.is_revealed())
                            .count()
                    } else {
                        0
                    }
                );
                for old_schema in [2u16, 3u16, 4u16, 5u16, 6u16, 7u16] {
                    let mut old = bytes.clone();
                    old[8..10].copy_from_slice(&old_schema.to_le_bytes());
                    assert!(decode_scheme_vo_v3(&old, &s.trusted).is_err());
                }
                if let Some(t) = &v.metrics {
                    assert_eq!(
                        parts.parts["coarse_table"],
                        t.coarse.len() * if IS_COMPACT { 4 } else { 8 }
                    );
                    assert_eq!(
                        parts.parts.get("fine_table").copied().unwrap_or(0),
                        t.fine.len() * if IS_COMPACT { 4 } else { 8 }
                    );
                }
                if let Some(y) = &v.reranking {
                    assert_eq!(
                        parts.parts["y"],
                        y.similarities.len() * if IS_COMPACT { 4 } else { 8 }
                    );
                }
                let mut cross = bytes.clone();
                cross[8] = if IS_COMPACT { 6 } else { 7 };
                assert!(decode_scheme_vo_v3(&cross, &s.trusted).is_err());
                assert_eq!(decode_scheme_vo_v3(&bytes, &s.trusted).unwrap(), v);
                for threads in [1, 8] {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(threads)
                        .build()
                        .unwrap();
                    let verified = pool
                        .install(|| verify_scheme_retrieval_v3(&s.trusted, &r, &bytes))
                        .unwrap();
                    assert_eq!(verified.execution, e);
                    assert_eq!(verified.results, v.results);
                }
                let current = (e, v.results);
                if let Some(previous) = &expected {
                    assert_eq!(previous, &current);
                } else {
                    expected = Some(current);
                }
            }
        }
    }
}
#[test]
fn table_y_commitment_boundaries_and_proof_attacks() {
    let (s, q) = fixture(1);
    let r = req(&s, &q, SchemeBackendV3::MatrixScheme, PublicModeV3::Cold);
    let v = execute_scheme_retrieval_v3(&s, &r).unwrap();
    assert!(v.reranking.is_some());
    let mut bad = v.clone();
    bad.metrics.as_mut().unwrap().coarse[0] += 1;
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.metrics.as_mut().unwrap().fine[0] += 1;
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.metrics.as_mut().unwrap().coarse_argument.projection[0] = [255; 32];
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.metrics.as_mut().unwrap().fine_argument =
        Some(v.metrics.as_ref().unwrap().coarse_argument.clone());
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.reranking.as_mut().unwrap().similarities[0] += 1;
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.reranking.as_mut().unwrap().similarities.pop();
    reject(&s, &r, &bad);
    bad = v.clone();
    let candidate = bad
        .documents
        .iter_mut()
        .find(|d| d.vector.is_revealed())
        .unwrap();
    candidate.metadata.token_count += 1;
    if let ComponentOpening::Revealed(codes) = &mut candidate.codes {
        codes.push(0);
    }
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.documents.reverse();
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.reranking.as_mut().unwrap().argument.projection[0] = [255; 32];
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.reranking = None;
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.documents[0].adjacency = ComponentOpening::Digest([0; 32]);
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.documents[0].vector = DocumentVectorOpeningV3::Commitment(ComponentOpening::Revealed(
        DocumentMatrixCommitmentV3::new(s.commitments.last().copied().unwrap()),
    ));
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.documents.pop();
    reject(&s, &r, &bad);
    bad = v.clone();
    bad.results[0].distance.0 += 1;
    reject(&s, &r, &bad);
    let mut other = r.clone();
    other.query.coordinates[0] += 0.1;
    assert!(
        verify_scheme_retrieval_v3(&s.trusted, &other, &encode_scheme_vo_v3(&v).unwrap().0)
            .is_err()
    );
}
#[test]
fn implicit_candidate_boundaries_require_exact_replay_disclosures() {
    let (s, q) = fixture(1);
    let r = req(&s, &q, SchemeBackendV3::MatrixScheme, PublicModeV3::Cold);
    let v = execute_scheme_retrieval_v3(&s, &r).unwrap();
    let (bytes, stats) = encode_scheme_vo_v3(&v).unwrap();
    assert!(!stats.parts.contains_key("token_boundaries"));
    assert!(
        serde_json::to_value(v.reranking.as_ref().unwrap())
            .unwrap()
            .get("candidates")
            .is_none()
    );
    assert_eq!(decode_scheme_vo_v3(&bytes, &s.trusted).unwrap(), v);
    verify_scheme_retrieval_v3(&s.trusted, &r, &bytes).unwrap();

    let candidate = v
        .documents
        .iter()
        .position(|d| d.vector.is_revealed())
        .unwrap();
    let mut bad = v.clone();
    let doc = &mut bad.documents[candidate];
    // Keep the valid component hash: omitting a required candidate must still fail.
    doc.vector = DocumentVectorOpeningV3::Commitment(ComponentOpening::Digest(
        s.component_hashes[doc.metadata.doc_id as usize][4],
    ));
    reject(&s, &r, &bad);

    let noncandidate = v
        .documents
        .iter()
        .position(|d| !d.vector.is_revealed())
        .unwrap();
    let mut bad = v.clone();
    let doc = &mut bad.documents[noncandidate];
    doc.vector = DocumentVectorOpeningV3::Commitment(ComponentOpening::Revealed(
        DocumentMatrixCommitmentV3::new(s.commitments[doc.metadata.doc_id as usize]),
    ));
    reject(&s, &r, &bad);

    // Preserve both the number of candidates and total tokens, but change Y's
    // document association. Metadata order and the projection binding reject it.
    let boundaries: Vec<_> = v
        .documents
        .iter()
        .filter(|d| d.vector.is_revealed())
        .map(|d| usize::from(d.metadata.token_count))
        .collect();
    assert_eq!(boundaries.len(), 2);
    let mut bad = v.clone();
    for row in bad
        .reranking
        .as_mut()
        .unwrap()
        .similarities
        .chunks_mut(boundaries.iter().sum())
    {
        row.rotate_left(boundaries[0]);
    }
    assert_ne!(bad.reranking, v.reranking);
    reject(&s, &r, &bad);
}
#[test]
fn external_trust_vo_preserves_results_and_local_matrix_request_binding() {
    let (s, q) = fixture(1);
    for backend in [
        SchemeBackendV3::FixedRawFp16,
        SchemeBackendV3::FixedRawFp32,
        SchemeBackendV3::MatrixScheme,
    ] {
        let r = req(&s, &q, backend, PublicModeV3::Cold);
        let v = execute_scheme_retrieval_v3(&s, &r).unwrap();
        let (bytes, stats) = encode_scheme_vo_v3(&v).unwrap();
        let json = serde_json::to_value(&v).unwrap();
        for key in [
            "signed",
            "request_digest",
            "index_digest",
            "raw_digest",
            "source_ids_digest",
            "provenance_digest",
            "fixed_documents_digest",
        ] {
            assert!(json.get(key).is_none(), "unexpected VO field: {key}");
        }
        assert!(!stats.parts.contains_key("manifest"));
        assert!(!stats.parts.contains_key("signature"));
        assert_eq!(&bytes[18..21], &[backend as u8, 0, 1]);
        assert_eq!(decode_scheme_vo_v3(&bytes, &s.trusted).unwrap(), v);
        assert_eq!(
            verify_scheme_retrieval_v3(&s.trusted, &r, &bytes)
                .unwrap()
                .results,
            v.results
        );

        let mut wrong = r.clone();
        wrong.manifest_digest[0] ^= 1;
        assert!(verify_scheme_retrieval_v3(&s.trusted, &wrong, &bytes).is_err());
        let mut bad_trust = s.trusted.clone();
        bad_trust.signed.signature[0] ^= 1;
        assert!(verify_scheme_retrieval_v3(&bad_trust, &r, &bytes).is_err());

        let mut same_integer_query = r.clone();
        same_integer_query.query.coordinates[0] = f32::from_bits(q.coordinates[0].to_bits() ^ 1);
        assert_eq!(
            validate_scheme_request_v3(&s.trusted, &same_integer_query)
                .unwrap()
                .coordinates,
            validate_scheme_request_v3(&s.trusted, &r)
                .unwrap()
                .coordinates
        );
        let verified = verify_scheme_retrieval_v3(&s.trusted, &same_integer_query, &bytes);
        if backend == SchemeBackendV3::MatrixScheme {
            assert!(verified.is_err()); // The transcript still binds the original FP32 bits.
        } else {
            assert_eq!(verified.unwrap().results, v.results); // Correct identical integer computation.
        }
        wrong = r.clone();
        wrong.query.coordinates.fill(0.);
        let other = execute_scheme_retrieval_v3(&s, &wrong).unwrap();
        assert_ne!(other.results, v.results);
        assert!(verify_scheme_retrieval_v3(&s.trusted, &wrong, &bytes).is_err());
    }
}
#[test]
fn bounded_parser_truncation_trailing_enums_lengths_and_public() {
    let (s, q) = fixture(1);
    let r = req(&s, &q, SchemeBackendV3::MatrixScheme, PublicModeV3::Cold);
    let v = execute_scheme_retrieval_v3(&s, &r).unwrap();
    let bytes = encode_scheme_vo_v3(&v).unwrap().0;
    for end in 0..bytes.len() {
        assert!(decode_scheme_vo_v3(&bytes[..end], &s.trusted).is_err());
    }
    let mut b = bytes.clone();
    b.push(0);
    assert!(decode_scheme_vo_v3(&b, &s.trusted).is_err());
    b = bytes.clone();
    b[8] = 99;
    assert!(decode_scheme_vo_v3(&b, &s.trusted).is_err());
    b = bytes.clone();
    b[10..18].fill(255);
    assert!(decode_scheme_vo_v3(&b, &s.trusted).is_err());
    let mut t = s.trusted.clone();
    t.owner_public_key[0] ^= 1;
    assert!(verify_scheme_retrieval_v3(&t, &r, &bytes).is_err());
    let mut p = scheme_public_payload_v3(&s, SchemeBackendV3::MatrixScheme);
    p.entries[0] = None;
    assert!(
        authenticate_scheme_public_data_v3(&s.trusted, SchemeBackendV3::MatrixScheme, &p).is_err()
    );
}
#[test]
fn raw_expansion_and_padding_corruption_rejected() {
    let (s, q) = fixture(1);
    let r = req(&s, &q, SchemeBackendV3::FixedRawFp32, PublicModeV3::Cold);
    let mut v = execute_scheme_retrieval_v3(&s, &r).unwrap();
    for d in &mut v.documents {
        if let DocumentVectorOpeningV3::Raw(ComponentOpening::Revealed(RawOpeningV3::Fp32(a))) =
            &mut d.vector
        {
            a[0] ^= 1;
            break;
        }
    }
    reject(&s, &r, &v);
    let (raw, _) = raw_fixture(1);
    let (mut prepared, _) =
        prepare_scheme_snapshot_v3(raw, &SigningKey::from_bytes(&[42; 32])).unwrap();
    prepared.fixed_documents[0].push(1);
    assert!(validate_scheme_snapshot_v3(&prepared).is_err());
    assert!(
        FixedQueryV3::new(QueryV3 {
            coordinates: vec![f32::NAN; 8],
            ..q
        })
        .is_err()
    );
}

#[test]
fn valid_unused_commitment_and_no_entry_payload_are_rejected() {
    let (s, q) = fixture(7);
    let r = req(&s, &q, SchemeBackendV3::MatrixScheme, PublicModeV3::Cold);
    let v = execute_scheme_retrieval_v3(&s, &r).unwrap();
    let (pos, doc) = v
        .documents
        .iter()
        .enumerate()
        .find(|(_, d)| !d.vector.is_revealed())
        .expect("fixture must contain an authenticated unused commitment");
    let id = doc.metadata.doc_id as usize;
    let mut bad = v.clone();
    bad.documents[pos].vector = DocumentVectorOpeningV3::Commitment(ComponentOpening::Revealed(
        DocumentMatrixCommitmentV3::new(s.commitments[id]),
    ));
    reject(&s, &r, &bad);
    let (empty, q) = fixture(11);
    let r = req(
        &empty,
        &q,
        SchemeBackendV3::MatrixScheme,
        PublicModeV3::Cold,
    );
    let mut v = execute_scheme_retrieval_v3(&empty, &r).unwrap();
    assert!(v.documents.is_empty());
    assert!(v.results.is_empty());
    assert!(v.metrics.as_ref().unwrap().fine_argument.is_none());
    v.metrics.as_mut().unwrap().fine =
        vec![
            0;
            usize::from(q.token_count) * empty.trusted.signed.manifest.source().fine_count as usize
        ];
    reject(&empty, &r, &v);
}
#[test]
fn nonwinner_token_deletion_and_commitment_tampering() {
    let (s, q) = fixture(1);
    let r = req(&s, &q, SchemeBackendV3::MatrixScheme, PublicModeV3::Cold);
    let v = execute_scheme_retrieval_v3(&s, &r).unwrap();
    let mut bad = v.clone();
    let candidates: Vec<_> = bad
        .documents
        .iter()
        .filter(|d| d.vector.is_revealed())
        .map(|d| d.metadata.clone())
        .collect();
    let y = bad.reranking.as_mut().unwrap();
    let index = candidates.iter().position(|b| b.token_count > 1).unwrap();
    let total = candidates
        .iter()
        .map(|b| usize::from(b.token_count))
        .sum::<usize>();
    let offset = candidates[..index]
        .iter()
        .map(|b| usize::from(b.token_count))
        .sum::<usize>();
    let mut reduced = vec![];
    for j in 0..usize::from(q.token_count) {
        for t in 0..total {
            if t != offset {
                reduced.push(y.similarities[j * total + t]);
            }
        }
    }
    y.similarities = reduced;
    let doc = bad
        .documents
        .iter_mut()
        .find(|d| d.metadata.doc_id == candidates[index].doc_id)
        .unwrap();
    doc.metadata.token_count -= 1;
    if let ComponentOpening::Revealed(codes) = &mut doc.codes {
        codes.pop();
    }
    reject(&s, &r, &bad);
    bad = v.clone();
    if let Some(d) = bad.documents.iter_mut().find(|d| d.vector.is_revealed())
        && let DocumentVectorOpeningV3::Commitment(ComponentOpening::Revealed(c)) = &mut d.vector
    {
        c.point = (gem_matrix_proof::canonical_point_v1(c.point).unwrap()
            + curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
            .compress()
            .to_bytes();
    }
    reject(&s, &r, &bad);
}

#[test]
fn directed_serialized_attack_runner_checks_each_backend() {
    let (s, q) = fixture(1);
    for backend in [
        SchemeBackendV3::FixedRawFp16,
        SchemeBackendV3::FixedRawFp32,
        SchemeBackendV3::MatrixScheme,
    ] {
        let r = req(&s, &q, backend, PublicModeV3::Cold);
        let v = execute_scheme_retrieval_v3(&s, &r).unwrap();
        let bytes = encode_scheme_vo_v3(&v).unwrap().0;
        let attacks = attack_scheme_retrieval_v3(&s.trusted, &r, &bytes).unwrap();
        assert!(attacks.len() >= 17);
        assert!(attacks.iter().all(|a| a.rejected));
        assert_eq!(
            attacks.iter().any(|a| a.name == "original_query_bits"),
            backend == SchemeBackendV3::MatrixScheme
        );
        for name in [
            "signature",
            "numeric_profile",
            "matrix_shape",
            "request_manifest_digest",
            "request_parameters",
        ] {
            assert!(
                attacks.iter().any(|a| a.name == name),
                "missing attack: {name}"
            );
        }
        assert!(
            attacks
                .iter()
                .any(|a| a.name == "valid_hidden_required_codes")
        );
    }
}

#[test]
fn every_request_reauthenticates_complete_public_payload() {
    let (s, q) = fixture(1);
    for backend in [
        SchemeBackendV3::FixedRawFp16,
        SchemeBackendV3::FixedRawFp32,
        SchemeBackendV3::MatrixScheme,
    ] {
        let r = req(&s, &q, backend, PublicModeV3::Cold);
        let (v, _, _) = execute_scheme_retrieval_measured_v3(&s, &r).unwrap();
        assert_eq!(v.public.as_ref().unwrap().entries, s.public.entries);
        if backend == SchemeBackendV3::MatrixScheme {
            assert!(v.public.as_ref().unwrap().raw_centroids.is_none());
            assert!(v.metrics.is_some());
        } else {
            assert_eq!(
                v.public.as_ref().unwrap().raw_centroids.as_ref(),
                Some(&s.public)
            );
        }
        let bytes = encode_scheme_vo_v3(&v).unwrap().0;
        for _ in 0..2 {
            verify_scheme_retrieval_v3(&s.trusted, &r, &bytes).unwrap();
            let mut bad = v.clone();
            bad.public = None;
            reject(&s, &r, &bad);
            let mut bad = v.clone();
            let public = bad.public.as_mut().unwrap();
            public.entries.clear();
            if let Some(raw) = &mut public.raw_centroids {
                raw.entries.clear();
            }
            reject(&s, &r, &bad);
            if backend == SchemeBackendV3::MatrixScheme {
                let mut bad = v.clone();
                bad.metrics = None;
                reject(&s, &r, &bad);
            } else {
                for component in 0..3 {
                    let mut bad = v.clone();
                    let public = bad.public.as_mut().unwrap();
                    match component {
                        0 => public.raw_centroids = None,
                        1 => public.raw_centroids.as_mut().unwrap().fine_bits[0] ^= 1,
                        _ => public.raw_centroids.as_mut().unwrap().coarse_bits[0] ^= 1,
                    }
                    reject(&s, &r, &bad);
                }
            }
        }
        let mut legacy = bytes;
        legacy[19] = 1;
        assert!(verify_scheme_retrieval_v3(&s.trusted, &r, &legacy).is_err());
        let mut request = serde_json::to_value(&r).unwrap();
        request["public_mode"] = serde_json::json!("cached");
        assert!(serde_json::from_value::<SchemeRequestV3>(request).is_err());
    }
}

#[test]
fn large_norms_with_representable_dots_are_authenticated() {
    let (source, mut query) = raw_fixture(1);
    let mut index = source.index.clone();
    index.fine_centroids.fill(1.);
    index.coarse_centroids.fill(1.);
    let documents = source
        .metadata
        .iter()
        .map(|m| RawDocumentV3 {
            doc_id: m.doc_id,
            dimension: source.trusted.signed.manifest.dimension,
            token_count: m.token_count,
            coordinate_bits: vec![
                f16::from_f32(1.).to_bits();
                usize::from(source.trusted.signed.manifest.dimension)
                    * usize::from(m.token_count)
            ],
        })
        .collect::<Vec<_>>();
    query.coordinates = vec![1., 1., -1., -1., 1., 1., -1., -1.];
    let key = SigningKey::from_bytes(&[42; 32]);
    let raw = prepare_raw_snapshot_v3(
        index,
        &documents,
        &source.source_ids,
        query.token_count,
        query.params.clone(),
        [7; 32],
        &key,
    )
    .unwrap();
    let (prepared, _) = prepare_scheme_snapshot_v3(raw, &key).unwrap();
    validate_scheme_snapshot_v3(&prepared).unwrap();
    let s = initialize_scheme_server_snapshot_v3(prepared).unwrap();
    let mut expected = None;
    for backend in [
        SchemeBackendV3::FixedRawFp16,
        SchemeBackendV3::FixedRawFp32,
        SchemeBackendV3::MatrixScheme,
    ] {
        let r = req(&s, &query, backend, PublicModeV3::Cold);
        let v = execute_scheme_retrieval_v3(&s, &r).unwrap();
        let bytes = encode_scheme_vo_v3(&v).unwrap().0;
        let verified = verify_scheme_retrieval_v3(&s.trusted, &r, &bytes).unwrap();
        assert!(!verified.results.is_empty());
        if let Some(previous) = &expected {
            assert_eq!(previous, &verified.results);
        } else {
            expected = Some(verified.results);
        }
        if backend == SchemeBackendV3::MatrixScheme {
            assert!(
                v.reranking
                    .as_ref()
                    .unwrap()
                    .similarities
                    .iter()
                    .all(|&x| x == 0)
            );
            let mut forged = v;
            forged.reranking.as_mut().unwrap().similarities[0] = numeric::Similarity::MAX;
            reject(&s, &r, &forged);
        }
        if IS_COMPACT {
            let mut overflow = r;
            overflow.query.coordinates.fill(1.);
            // Query conversion is permissive; the actual dot exceeding i32 is an error.
            validate_scheme_request_v3(&s.trusted, &overflow).unwrap();
            assert!(matches!(
                execute_scheme_retrieval_v3(&s, &overflow),
                Err(gem_core::GemError::NumericOverflow)
            ));
        }
    }
}

#[test]
fn explicit_centroid_preprocessing_preserves_self_contained_vo() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .unwrap();
    pool.install(|| {
        let (server, query) = fixture(7);
        let request = req(
            &server,
            &query,
            SchemeBackendV3::MatrixScheme,
            PublicModeV3::Cold,
        );
        let (cold, _, _) = execute_scheme_retrieval_measured_v3(&server, &request).unwrap();
        prepare_scheme_server_proofs_v3(&server).unwrap();
        prepare_scheme_server_proofs_v3(&server).unwrap();
        for query_id in [query.query_id, query.query_id + 1] {
            let mut request = request.clone();
            request.query.query_id = query_id;
            let (warm, _, timings) =
                execute_scheme_retrieval_measured_v3(&server, &request).unwrap();
            let (bytes, stats) = encode_scheme_vo_v3(&warm).unwrap();
            verify_scheme_retrieval_v3(&server.trusted, &request, &bytes).unwrap();
            assert_eq!(cold.results, warm.results);
            assert_eq!(
                cold.metrics.as_ref().unwrap().coarse,
                warm.metrics.as_ref().unwrap().coarse
            );
            assert_eq!(
                cold.metrics.as_ref().unwrap().fine,
                warm.metrics.as_ref().unwrap().fine
            );
            assert_eq!(encode_scheme_vo_v3(&cold).unwrap().1.parts, stats.parts);
            assert!(timings.phases.contains_key("centroid_cache_lookup"));
        }
    });
}
