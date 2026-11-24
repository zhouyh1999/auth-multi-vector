use super::*;
use ed25519_dalek::SigningKey;
use gem_core::{
    GraphBuilderKindV3, QueryV3, RawDocumentF32V3, RawDocumentV3, SearchDocumentV3, SearchParamsV3,
    SemanticProfileV3,
};
use gem_search::{GraphBuildParamsV3, SearchIndexV3, native_query_v3};
use half::f16;
use rand::{Rng, SeedableRng};
use std::collections::BTreeSet;
#[path = "audit_tests.rs"]
mod audit;
fn execute_raw_retrieval_v3(
    s: &PreparedRawSnapshotV3,
    r: &RawRequestV3,
) -> gem_core::Result<RawRetrievalVoV3> {
    crate::execute_raw_retrieval_v3(&initialize_server_snapshot_v3(s.clone())?, r)
}
fn fixture(seed: u64) -> (PreparedRawSnapshotV3, QueryV3) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let n = rng.gen_range(3..18);
    let fine: Vec<f32> = (0..8 * 4)
        .map(|_| rng.gen_range(-4..5) as f32 / 4.)
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
            (0..8).map(|_| rng.gen_range(-4..5) as f32 / 4.).collect()
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
fn req(s: &PreparedRawSnapshotV3, q: &QueryV3, w: RawWireV3, m: PublicModeV3) -> RawRequestV3 {
    RawRequestV3 {
        manifest_digest: s.trusted.expected_manifest_digest,
        query: q.clone(),
        raw_wire: w,
        public_mode: m,
    }
}
fn reject(s: &PreparedRawSnapshotV3, r: &RawRequestV3, v: &RawRetrievalVoV3) {
    let bytes = encode_raw_vo_v3(v).unwrap().0;
    assert!(verify_raw_retrieval_v3(&s.trusted, r, &bytes).is_err());
}
// Independent scalar oracle: separate loops and MaxSim distance order.
fn oracle(q: &QueryV3, coords: &[f32], codes: Option<&[u32]>) -> f32 {
    let mut sums = 0f32;
    for query in q.coordinates.chunks_exact(4) {
        let mut maxima = Vec::new();
        let vectors: Vec<&[f32]> = match codes {
            Some(c) => c
                .iter()
                .map(|&id| &coords[id as usize * 4..id as usize * 4 + 4])
                .collect(),
            None => coords.chunks_exact(4).collect(),
        };
        for v in vectors {
            let mut dot = 0f32;
            for j in 0..4 {
                let product = query[j] * v[j];
                dot += product;
            }
            maxima.push(dot);
        }
        let mut max = maxima[0];
        for x in maxima.into_iter().skip(1) {
            if x > max {
                max = x
            }
        }
        sums += if codes.is_some() { 1f32 - max } else { max };
    }
    if codes.is_some() {
        sums / f32::from(q.token_count)
    } else {
        1f32 - sums / f32::from(q.token_count)
    }
}
#[test]
fn randomized_256_sparse_dense_wire_threads_and_oracles() {
    let pools = [
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap(),
        rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap(),
    ];
    let mut pruning = 0;
    let mut stopping = 0;
    let mut empty = 0;
    for seed in 0..256 {
        let (s, q) = fixture(seed);
        validate_prepared_snapshot_v3(&s).unwrap();
        let raw: Vec<RawDocumentF32V3> = s
            .metadata
            .iter()
            .zip(&s.raw_bits)
            .map(|(m, b)| RawDocumentF32V3 {
                doc_id: m.doc_id,
                token_count: m.token_count,
                dimension: 4,
                coordinates: decode_fp16_v3(b).unwrap(),
            })
            .collect();
        let native = pools[0]
            .install(|| native_query_v3(&s.index, &raw, &q))
            .unwrap();
        pruning += native.trace.cluster_pruned.len();
        stopping += native.trace.early_stops.len();
        empty += usize::from(native.trace.queue_entries.is_empty());
        for row in &native.trace.compared {
            assert_eq!(
                row.distance_bits,
                oracle(
                    &q,
                    &s.index.fine_centroids,
                    Some(&s.index.documents[row.doc_id as usize].compact_codes)
                )
                .to_bits()
            )
        }
        let mut expected = native
            .trace
            .candidates
            .iter()
            .map(|c| {
                (
                    c.doc_id,
                    oracle(&q, &raw[c.doc_id as usize].coordinates, None),
                )
            })
            .collect::<Vec<_>>();
        expected.sort_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)));
        expected.truncate(q.params.k as usize);
        assert_eq!(
            native
                .exact
                .results
                .iter()
                .map(|r| (r.doc_id, r.distance_bits))
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|r| (r.0, r.1.to_bits()))
                .collect::<Vec<_>>()
        );
        for w in [RawWireV3::Fp16, RawWireV3::Fp32] {
            {
                let m = PublicModeV3::Cold;
                let r = req(&s, &q, w, m);
                let v = pools[0]
                    .install(|| execute_raw_retrieval_v3(&s, &r))
                    .unwrap();
                let (b, stats) = encode_raw_vo_v3(&v).unwrap();
                assert_eq!(stats.total, b.len());
                assert_eq!(stats.metadata, 6 * v.documents.len());
                assert_eq!(&b[..8], b"G3RAWVO4");
                assert_eq!(stats.merkle_siblings, 32 * v.proof.siblings.len());
                let raw_elements: usize = v
                    .documents
                    .iter()
                    .filter_map(|d| match &d.raw {
                        ComponentOpening::Revealed(RawOpeningV3::Fp16(a)) => Some(a.len() * 2),
                        ComponentOpening::Revealed(RawOpeningV3::Fp32(a)) => Some(a.len() * 4),
                        ComponentOpening::Digest(_) => None,
                    })
                    .sum();
                assert_eq!(stats.raw, raw_elements);
                let public = v.public.as_ref().unwrap();
                assert_eq!(
                    stats.globals,
                    public.fine_bits.len() * 2
                        + public.coarse_bits.len() * 4
                        + public.entries.len()
                        + 4 * public.entries.iter().flatten().count()
                );
                assert_eq!(
                    stats.codes,
                    4 * v
                        .documents
                        .iter()
                        .filter_map(|d| {
                            if let ComponentOpening::Revealed(codes) = &d.codes {
                                Some(codes.len())
                            } else {
                                None
                            }
                        })
                        .sum::<usize>()
                );
                let mut legacy = b.clone();
                legacy[..8].copy_from_slice(b"G3RAWVO!");
                assert!(decode_raw_vo_v3(&legacy, &s.trusted).is_err());
                legacy[..8].copy_from_slice(b"G3RAWVO2");
                assert!(decode_raw_vo_v3(&legacy, &s.trusted).is_err());
                legacy[..8].copy_from_slice(b"G3RAWVO3");
                assert!(decode_raw_vo_v3(&legacy, &s.trusted).is_err());
                legacy = b.clone();
                legacy[8..10].copy_from_slice(&1u16.to_le_bytes());
                assert!(decode_raw_vo_v3(&legacy, &s.trusted).is_err());
                assert_eq!(
                    encode_raw_vo_v3(&decode_raw_vo_v3(&b, &s.trusted).unwrap())
                        .unwrap()
                        .0,
                    b
                );
                for p in &pools {
                    let verified = p
                        .install(|| verify_raw_retrieval_v3(&s.trusted, &r, &b))
                        .unwrap();
                    assert_eq!(verified.result, native);
                }
                if w == RawWireV3::Fp16 && m == PublicModeV3::Cold {
                    for kind in 0..5 {
                        let mut tampered = v.clone();
                        if let Some(d) = tampered.documents.first_mut() {
                            match kind {
                                0 => {
                                    d.metadata.token_count ^= 1;
                                    if let ComponentOpening::Revealed(codes) = &mut d.codes {
                                        codes.resize(usize::from(d.metadata.token_count), 0);
                                    }
                                }
                                1 => d.membership = ComponentOpening::Digest([0; 32]),
                                2 => d.codes = ComponentOpening::Digest([0; 32]),
                                3 => d.adjacency = ComponentOpening::Digest([0; 32]),
                                _ => d.raw = ComponentOpening::Digest([0; 32]),
                            }
                            assert!(
                                verify_raw_retrieval_v3(
                                    &s.trusted,
                                    &r,
                                    &encode_raw_vo_v3(&tampered).unwrap().0
                                )
                                .is_err()
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(
        pruning > 0 && stopping > 0 && empty > 0,
        "actual coverage: pruning={pruning} stopping={stopping} empty={empty}"
    );
    println!("seed=0..255 pruning_events={pruning} early_stops={stopping} empty_traces={empty}");
    if let Ok(path) = std::env::var("GEM_AUTH_TEST_EVIDENCE") {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap();
        use std::io::Write;
        file.write_all(&serde_json::to_vec_pretty(&serde_json::json!({"passed":true,"fixture_count":256,"seed_range":[0,255],"wire_configurations":2,"client_threads":[1,8],"verifications":1024,"pruning_events":pruning,"early_stops":stopping,"empty_traces":empty,"independent_qch_maxsim_oracle":true,"all_component_mutations":true})).unwrap()).unwrap();
    }
}
#[test]
fn fp16_all_finite_patterns_and_illegal_fp32() {
    let bits: Vec<u16> = (0..=u16::MAX)
        .filter(|&b| f16::from_bits(b).is_finite())
        .collect();
    let f = decode_fp16_v3(&bits).unwrap();
    assert_eq!(
        fp32_to_canonical_fp16_v3(&f.iter().map(|v| v.to_bits()).collect::<Vec<_>>()).unwrap(),
        bits
    );
    assert_eq!(
        fp32_to_canonical_fp16_v3(&[0, 0x80000000]).unwrap(),
        vec![0, 0x8000]
    );
    for x in [
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        0.1,
        70000.,
        f32::from_bits(1),
    ] {
        assert!(fp32_to_canonical_fp16_v3(&[x.to_bits()]).is_err())
    }
    for x in [0x7c00, 0xfc00, 0x7e00] {
        assert!(decode_fp16_v3(&[x]).is_err())
    }
    assert!(gem_core::strict_dot_f32(&[f32::MAX, 1.], &[2., 1.]).is_err());
    let (mut s, _) = fixture(3);
    s.index.fine_centroids[0] = 0.1;
    let raw = s
        .raw_bits
        .iter()
        .zip(&s.metadata)
        .map(|(b, m)| RawDocumentV3 {
            doc_id: m.doc_id,
            token_count: m.token_count,
            dimension: s.trusted.signed.manifest.dimension,
            coordinate_bits: b.clone(),
        })
        .collect::<Vec<_>>();
    assert!(
        prepare_raw_snapshot_v3(
            s.index,
            &raw,
            &s.source_ids,
            2,
            s.trusted.signed.manifest.params,
            [0; 32],
            &SigningKey::from_bytes(&[1; 32])
        )
        .is_err()
    );
}
#[test]
fn multiproof_exhaustive_shapes_and_strictness() {
    for n in 1..10 {
        let leaves = (0..n)
            .map(|i| gem_core::hash_bytes(b"test", &[i as u8]))
            .collect::<Vec<_>>();
        let tree = DocumentTreeV3::build(&leaves).unwrap();
        for mask in 0..(1 << n) {
            let ids = (0..n)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| i as u32)
                .collect::<Vec<_>>();
            let mut proof = tree.prove(&ids).unwrap();
            let opened = ids
                .iter()
                .map(|&i| (i, leaves[i as usize]))
                .collect::<Vec<_>>();
            verify_document_multiproof_v3(n as u32, tree.root().unwrap(), &opened, &proof).unwrap();
            proof.siblings.push([0; 32]);
            assert!(
                verify_document_multiproof_v3(n as u32, tree.root().unwrap(), &opened, &proof)
                    .is_err()
            );
        }
        if n > 1 {
            assert!(tree.prove(&[0, 0]).is_err());
            assert!(tree.prove(&[1, 0]).is_err());
            let p = tree.prove(&[0]).unwrap();
            assert!(
                verify_document_multiproof_v3(n as u32, [0; 32], &[(0, leaves[0])], &p).is_err()
            );
        }
    }
}
#[test]
fn source_id_mapping_is_offline_and_not_in_document_leaves() {
    let (s, q) = fixture(13);
    let raw = s
        .metadata
        .iter()
        .zip(&s.raw_bits)
        .map(|(m, bits)| RawDocumentV3 {
            doc_id: m.doc_id,
            token_count: m.token_count,
            dimension: s.trusted.signed.manifest.dimension,
            coordinate_bits: bits.clone(),
        })
        .collect::<Vec<_>>();
    let mut ids = s.source_ids.clone();
    ids.reverse();
    let remapped = prepare_raw_snapshot_v3(
        s.index.clone(),
        &raw,
        &ids,
        q.token_count,
        q.params.clone(),
        s.trusted.signed.manifest.provenance_digest,
        &SigningKey::from_bytes(&[42; 32]),
    )
    .unwrap();
    validate_prepared_snapshot_v3(&remapped).unwrap();
    assert_eq!(s.metadata, remapped.metadata);
    assert_eq!(s.component_hashes, remapped.component_hashes);
    assert_eq!(s.tree, remapped.tree);
    assert_ne!(
        s.trusted.signed.manifest.source_ids_digest,
        remapped.trusted.signed.manifest.source_ids_digest
    );
    let mut tampered = s.clone();
    tampered.source_ids = ids;
    assert!(validate_prepared_snapshot_v3(&tampered).is_err());
}

#[test]
fn valid_unused_openings_missing_pruning_and_component_attacks() {
    for seed in 1..32 {
        let (s, q) = fixture(seed);
        let r = req(&s, &q, RawWireV3::Fp16, PublicModeV3::Cold);
        let v = execute_raw_retrieval_v3(&s, &r).unwrap();
        for k in 0..5 {
            let mut bad = v.clone();
            if let Some(d) = bad.documents.first_mut() {
                match k {
                    0 => {
                        d.metadata.token_count += 1;
                        if let ComponentOpening::Revealed(codes) = &mut d.codes {
                            codes.push(0);
                        }
                    }
                    1 => d.membership = ComponentOpening::Digest([3; 32]),
                    2 => d.codes = ComponentOpening::Digest([3; 32]),
                    3 => d.adjacency = ComponentOpening::Digest([3; 32]),
                    _ => d.raw = ComponentOpening::Digest([3; 32]),
                }
                reject(&s, &r, &bad)
            }
        }
        let execution = gem_search::execute_search_v3(&s.index, (&s.index).into(), &q).unwrap();
        for d in &v.documents {
            if !d.codes.is_revealed() {
                let mut extra = v.clone();
                extra
                    .documents
                    .iter_mut()
                    .find(|x| x.metadata.doc_id == d.metadata.doc_id)
                    .unwrap()
                    .codes = ComponentOpening::Revealed(
                    s.index.documents[d.metadata.doc_id as usize]
                        .compact_codes
                        .clone(),
                );
                reject(&s, &r, &extra)
            }
            if !d.raw.is_revealed() {
                let mut extra = v.clone();
                extra
                    .documents
                    .iter_mut()
                    .find(|x| x.metadata.doc_id == d.metadata.doc_id)
                    .unwrap()
                    .raw = ComponentOpening::Revealed(RawOpeningV3::Fp16(
                    s.raw_bits[d.metadata.doc_id as usize].clone(),
                ));
                reject(&s, &r, &extra)
            }
            if !d.adjacency.is_revealed() {
                let mut extra = v.clone();
                extra
                    .documents
                    .iter_mut()
                    .find(|x| x.metadata.doc_id == d.metadata.doc_id)
                    .unwrap()
                    .adjacency = ComponentOpening::Revealed(
                    s.index.documents[d.metadata.doc_id as usize]
                        .adjacency
                        .clone(),
                );
                reject(&s, &r, &extra)
            }
        }
        if let Some(id) = (0..s.metadata.len() as u32)
            .find(|id| !execution.component_usage.membership.contains(id))
        {
            let h = s.component_hashes[id as usize];
            let mut extra = v.clone();
            extra.documents.push(DocumentOpeningV3 {
                metadata: s.metadata[id as usize].clone(),
                membership: ComponentOpening::Revealed(
                    s.index.documents[id as usize].cluster_ids.clone(),
                ),
                codes: ComponentOpening::Digest(h[2]),
                adjacency: ComponentOpening::Digest(h[3]),
                raw: ComponentOpening::Digest(h[4]),
            });
            extra.documents.sort_by_key(|d| d.metadata.doc_id);
            extra.proof = s
                .tree
                .prove(
                    &extra
                        .documents
                        .iter()
                        .map(|d| d.metadata.doc_id)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            reject(&s, &r, &extra);
        }
        for &id in &execution.trace.cluster_pruned {
            let mut bad = v.clone();
            bad.documents
                .iter_mut()
                .find(|x| x.metadata.doc_id == id)
                .unwrap()
                .membership = ComponentOpening::Digest(s.component_hashes[id as usize][1]);
            reject(&s, &r, &bad);
        }
        let mut bad = v.clone();
        if let Some(d) = bad.documents.iter_mut().find(|d| d.raw.is_revealed()) {
            if let ComponentOpening::Revealed(RawOpeningV3::Fp16(b)) = &mut d.raw {
                b.truncate(b.len() - 1)
            }
            reject(&s, &r, &bad)
        }
    }
}
#[test]
fn external_trust_vo_keeps_results_and_authenticates_the_selected_root() {
    use ed25519_dalek::Signer;
    let (s, q) = fixture(7);
    for wire in [RawWireV3::Fp16, RawWireV3::Fp32] {
        let r = req(&s, &q, wire, PublicModeV3::Cold);
        let v = execute_raw_retrieval_v3(&s, &r).unwrap();
        let (bytes, stats) = encode_raw_vo_v3(&v).unwrap();
        let json = serde_json::to_value(&v).unwrap();
        for key in [
            "signed",
            "request_digest",
            "index_digest",
            "raw_digest",
            "source_ids_digest",
            "provenance_digest",
        ] {
            assert!(json.get(key).is_none(), "unexpected VO field: {key}");
        }
        assert_eq!(stats.framing, 33 + 4 * v.documents.len());
        assert_eq!(&bytes[18..21], &[wire as u8, 0, 1]);
        assert_eq!(decode_raw_vo_v3(&bytes, &s.trusted).unwrap(), v);
        let verified = verify_raw_retrieval_v3(&s.trusted, &r, &bytes).unwrap();
        assert_eq!(verified.result.exact.results, v.results);

        let mut bad = v.clone();
        bad.results[0].distance_bits ^= 1;
        reject(&s, &r, &bad);
        let mut wrong_request = r.clone();
        wrong_request.manifest_digest[0] ^= 1;
        assert!(verify_raw_retrieval_v3(&s.trusted, &wrong_request, &bytes).is_err());
        let mut wrong_trust = s.trusted.clone();
        wrong_trust.signed.signature[0] ^= 1;
        assert!(verify_raw_retrieval_v3(&wrong_trust, &r, &bytes).is_err());

        // A valid signature on another root must not authenticate this proof.
        wrong_trust = s.trusted.clone();
        wrong_trust.signed.manifest.document_root[0] ^= 1;
        wrong_trust.expected_manifest_digest =
            manifest_digest_v3(&wrong_trust.signed.manifest).unwrap();
        wrong_trust.signed.signature = SigningKey::from_bytes(&[42; 32])
            .sign(&wrong_trust.expected_manifest_digest)
            .to_bytes()
            .to_vec();
        validate_trusted_snapshot_v3(&wrong_trust).unwrap();
        wrong_request.manifest_digest = wrong_trust.expected_manifest_digest;
        assert!(verify_raw_retrieval_v3(&wrong_trust, &wrong_request, &bytes).is_err());
    }
}
#[test]
fn trust_request_public_snapshot_and_bounded_wire_attacks() {
    let (s, q) = fixture(7);
    let r = req(&s, &q, RawWireV3::Fp16, PublicModeV3::Cold);
    let v = execute_raw_retrieval_v3(&s, &r).unwrap();
    let bytes = encode_raw_vo_v3(&v).unwrap().0;
    for i in 0..bytes.len() {
        assert!(verify_raw_retrieval_v3(&s.trusted, &r, &bytes[..i]).is_err())
    }
    let mut trailing = bytes.clone();
    trailing.push(1);
    assert!(decode_raw_vo_v3(&trailing, &s.trusted).is_err());
    let mut huge = bytes.clone();
    huge[10..18].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(decode_raw_vo_v3(&huge, &s.trusted).is_err());
    let mut rng = rand::rngs::StdRng::seed_from_u64(20261005);
    for _ in 0..512 {
        let mut b = bytes.clone();
        let i = rng.gen_range(0..b.len());
        b[i] ^= 1;
        assert!(
            verify_raw_retrieval_v3(&s.trusted, &r, &b).is_err(),
            "changed byte {i}"
        )
    }
    let mut changed = r.clone();
    changed.query.coordinates[0] += 0.25;
    assert!(verify_raw_retrieval_v3(&s.trusted, &changed, &bytes).is_err());
    changed = r.clone();
    changed.query.params.ef_search += 1;
    assert!(verify_raw_retrieval_v3(&s.trusted, &changed, &bytes).is_err());
    let mut t = s.trusted.clone();
    t.owner_public_key = [0; 32];
    assert!(verify_raw_retrieval_v3(&t, &r, &bytes).is_err());
    t = s.trusted.clone();
    t.signed.manifest.snapshot_id[0] ^= 1;
    t.expected_manifest_digest = manifest_digest_v3(&t.signed.manifest).unwrap();
    assert!(validate_trusted_snapshot_v3(&t).is_err());
    let mut p = s.public.clone();
    p.fine_bits[0] ^= 1;
    assert!(authenticate_public_data_v3(&s.trusted, p).is_err());
    p = s.public.clone();
    p.coarse_bits[0] ^= 1;
    assert!(authenticate_public_data_v3(&s.trusted, p).is_err());
    p = s.public.clone();
    p.entries[0] = None;
    assert!(authenticate_public_data_v3(&s.trusted, p).is_err());
    let mut s2 = s.clone();
    s2.raw_bits[0][0] ^= 1;
    assert!(validate_prepared_snapshot_v3(&s2).is_err());
    let meta = &s.metadata[0];
    let values = vec![1u32, 2];
    assert_ne!(
        component_hash_v3(meta, 1, &values).unwrap(),
        component_hash_v3(meta, 2, &values).unwrap()
    );
    let mut other = meta.clone();
    other.doc_id += 1;
    assert_ne!(
        component_hash_v3(meta, 1, &values).unwrap(),
        component_hash_v3(&other, 1, &values).unwrap()
    );
    assert_eq!(
        s.index
            .documents
            .iter()
            .map(|d| d.doc_id)
            .collect::<BTreeSet<_>>()
            .len(),
        s.metadata.len()
    );
}
#[test]
fn hand_checked_queue_pruning_early_stop_and_selective_openings() {
    let docs = vec![
        SearchDocumentV3 {
            doc_id: 0,
            token_count: 1,
            compact_codes: vec![1],
            cluster_ids: vec![0],
            adjacency: vec![1, 2],
        },
        SearchDocumentV3 {
            doc_id: 1,
            token_count: 1,
            compact_codes: vec![0],
            cluster_ids: vec![0],
            adjacency: vec![0, 2],
        },
        SearchDocumentV3 {
            doc_id: 2,
            token_count: 1,
            compact_codes: vec![2],
            cluster_ids: vec![1],
            adjacency: vec![0],
        },
        SearchDocumentV3 {
            doc_id: 3,
            token_count: 1,
            compact_codes: vec![2],
            cluster_ids: vec![0],
            adjacency: vec![0, 1, 2],
        },
    ];
    let raw: Vec<RawDocumentV3> = docs
        .iter()
        .map(|d| RawDocumentV3 {
            doc_id: d.doc_id,
            token_count: 1,
            dimension: 1,
            coordinate_bits: vec![
                f16::from_f32([1., 0.5, -1.][d.compact_codes[0] as usize]).to_bits(),
            ],
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
        dimension: 1,
        max_doc_tokens: 1,
        fine_centroids: vec![1., 0.5, -1.],
        coarse_centroids: vec![1., -1.],
        fine_to_coarse: vec![0, 0, 1],
        cluster_entries: vec![Some(3), Some(2)],
        documents: docs,
    };
    let params = SearchParamsV3 {
        k: 1,
        rerank_k: 1,
        ef_search: 1,
        cluster_top_t: 1,
    };
    let s = prepare_raw_snapshot_v3(
        index,
        &raw,
        &[100, 101, 102, 103],
        1,
        params.clone(),
        [0; 32],
        &SigningKey::from_bytes(&[4; 32]),
    )
    .unwrap();
    let q = QueryV3 {
        query_id: 0,
        dimension: 1,
        token_count: 1,
        coordinates: vec![1.],
        params,
    };
    let r = req(&s, &q, RawWireV3::Fp16, PublicModeV3::Cold);
    let v = execute_raw_retrieval_v3(&s, &r).unwrap();
    let verified =
        verify_raw_retrieval_v3(&s.trusted, &r, &encode_raw_vo_v3(&v).unwrap().0).unwrap();
    let trace = &verified.result.trace;
    assert_eq!(trace.queue_entries, vec![(0, 3)]);
    assert_eq!(trace.expanded, vec![3, 1]);
    assert_eq!(trace.membership_examined, vec![0, 1, 2, 0, 2]);
    assert_eq!(trace.cluster_pruned, vec![2, 2]);
    assert_eq!(
        trace
            .compared
            .iter()
            .map(|r| (r.doc_id, r.distance_bits))
            .collect::<Vec<_>>(),
        vec![
            (3, 2f32.to_bits()),
            (0, 0.5f32.to_bits()),
            (1, 0f32.to_bits())
        ]
    );
    assert_eq!(trace.early_stops.len(), 1);
    assert_eq!(trace.early_stops[0].pass, 2);
    assert_eq!(trace.early_stops[0].doc_id, 0);
    assert_eq!(
        verified.execution.component_usage.codes,
        BTreeSet::from([0, 1, 3])
    );
    assert_eq!(
        verified.execution.component_usage.adjacency,
        BTreeSet::from([1, 3])
    );
    assert_eq!(verified.execution.component_usage.raw, BTreeSet::from([1]));
    assert_eq!(verified.result.exact.results[0].doc_id, 1);
    assert_eq!(
        verified.result.exact.results[0].distance_bits,
        0f32.to_bits()
    );
}
#[test]
fn negative_near_tie_signed_zero_and_finite_overflow() {
    let (s, mut q) = fixture(7);
    q.coordinates = vec![
        -f32::from_bits(0x3f800001),
        0.,
        -0.,
        1.,
        -1.,
        -0.,
        0.,
        f32::from_bits(0x3f800002),
    ];
    let r = req(&s, &q, RawWireV3::Fp16, PublicModeV3::Cold);
    let v = execute_raw_retrieval_v3(&s, &r).unwrap();
    let a = verify_raw_retrieval_v3(&s.trusted, &r, &encode_raw_vo_v3(&v).unwrap().0).unwrap();
    let r2 = req(&s, &q, RawWireV3::Fp32, PublicModeV3::Cold);
    let v2 = execute_raw_retrieval_v3(&s, &r2).unwrap();
    let b = verify_raw_retrieval_v3(&s.trusted, &r2, &encode_raw_vo_v3(&v2).unwrap().0).unwrap();
    assert_eq!(a.result, b.result);
    q.coordinates.fill(f32::MAX);
    let r = req(&s, &q, RawWireV3::Fp16, PublicModeV3::Cold);
    assert!(execute_raw_retrieval_v3(&s, &r).is_err());
}

#[test]
fn leaf_count_is_bound_even_with_hidden_padding_subtree() {
    let leaves = (0..4)
        .map(|i| gem_core::hash_bytes(b"test", &[i]))
        .collect::<Vec<_>>();
    let tree = DocumentTreeV3::build(&leaves).unwrap();
    let proof = tree.prove(&[0]).unwrap();
    assert!(
        verify_document_multiproof_v3(3, tree.root().unwrap(), &[(0, leaves[0])], &proof).is_err()
    );
}

#[test]
fn every_request_reauthenticates_complete_public_data() {
    let (s, q) = fixture(1);
    for wire in [RawWireV3::Fp16, RawWireV3::Fp32] {
        let r = req(&s, &q, wire, PublicModeV3::Cold);
        let v = execute_raw_retrieval_v3(&s, &r).unwrap();
        assert_eq!(v.public.as_ref(), Some(&s.public));
        let bytes = encode_raw_vo_v3(&v).unwrap().0;
        for _ in 0..2 {
            verify_raw_retrieval_v3(&s.trusted, &r, &bytes).unwrap();
            for component in 0..4 {
                let mut bad = v.clone();
                match component {
                    0 => bad.public = None,
                    1 => bad.public.as_mut().unwrap().fine_bits[0] ^= 1,
                    2 => bad.public.as_mut().unwrap().coarse_bits[0] ^= 1,
                    _ => bad.public.as_mut().unwrap().entries.clear(),
                }
                reject(&s, &r, &bad);
            }
        }
        let mut legacy = bytes;
        legacy[19] = 1;
        assert!(verify_raw_retrieval_v3(&s.trusted, &r, &legacy).is_err());
        let mut request = serde_json::to_value(&r).unwrap();
        request["public_mode"] = serde_json::json!("cached");
        assert!(serde_json::from_value::<RawRequestV3>(request).is_err());
    }
}
