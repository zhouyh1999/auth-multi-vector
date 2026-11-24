//! Independent audit models deliberately avoid the production metric, heap,
//! replay, and reranking implementations.
use super::*;
use gem_core::{EarlyStopEventV3, NodeDistanceF32V3, SearchTraceV3};
use gem_search::{ComponentUsageV3, QueryExecutionV3};
use std::collections::BTreeMap;

fn dot(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len());
    let mut sum = 0f32;
    for i in 0..a.len() {
        let product = a[i] * b[i];
        sum += product;
    }
    assert!(sum.is_finite());
    sum
}
fn sort(rows: &mut [NodeDistanceF32V3]) {
    rows.sort_by(|a, b| {
        f32::from_bits(a.distance_bits)
            .total_cmp(&f32::from_bits(b.distance_bits))
            .then(a.doc_id.cmp(&b.doc_id))
    });
}
fn reference_search(i: &SearchIndexV3, q: &QueryV3) -> QueryExecutionV3 {
    let dim = usize::from(i.dimension);
    let mut selected = vec![false; i.cluster_entries.len()];
    for token in q.coordinates.chunks_exact(dim) {
        let mut ranked: Vec<_> = i
            .coarse_centroids
            .chunks_exact(dim)
            .enumerate()
            .map(|(id, c)| NodeDistanceF32V3 {
                doc_id: id as u32,
                distance_bits: (-dot(token, c)).to_bits(),
            })
            .collect();
        sort(&mut ranked);
        for item in ranked.iter().take(q.params.cluster_top_t as usize) {
            selected[item.doc_id as usize] = true;
        }
    }
    let selected_clusters: Vec<_> = selected
        .iter()
        .enumerate()
        .filter_map(|(id, &yes)| yes.then_some(id as u32))
        .collect();
    let mut queue_entries = Vec::new();
    for &cluster in &selected_clusters {
        if let Some(entry) = i.cluster_entries[cluster as usize]
            && !queue_entries.iter().any(|&(_, id)| id == entry)
        {
            queue_entries.push((cluster, entry));
        }
    }
    let mut trace = SearchTraceV3 {
        selected_clusters,
        queue_entries,
        compared: vec![],
        expanded: vec![],
        membership_examined: vec![],
        cluster_pruned: vec![],
        retained: vec![],
        candidates: vec![],
        early_stops: vec![],
    };
    let mut usage = ComponentUsageV3::default();
    if trace.queue_entries.is_empty() {
        return QueryExecutionV3 {
            trace,
            component_usage: usage,
        };
    }
    let lookup: Vec<Vec<f32>> = q
        .coordinates
        .chunks_exact(dim)
        .map(|token| {
            i.fine_centroids
                .chunks_exact(dim)
                .map(|c| dot(token, c))
                .collect()
        })
        .collect();
    let score = |id: u32| {
        let codes = &i.documents[id as usize].compact_codes;
        let mut sum = 0f32;
        for row in &lookup {
            let mut maximum = row[codes[0] as usize];
            for &code in codes.iter().skip(1) {
                if row[code as usize] > maximum {
                    maximum = row[code as usize];
                }
            }
            sum += 1f32 - maximum;
        }
        NodeDistanceF32V3 {
            doc_id: id,
            distance_bits: (sum / f32::from(q.token_count)).to_bits(),
        }
    };
    let mut visited = vec![false; i.documents.len()];
    let mut queues: Vec<Vec<NodeDistanceF32V3>> = Vec::new();
    let mut stopped = vec![false; trace.queue_entries.len()];
    for &(_, entry) in &trace.queue_entries {
        let row = score(entry);
        queues.push(vec![row]);
        visited[entry as usize] = true;
        trace.compared.push(row);
        trace.retained.push(row);
        usage.membership.insert(entry);
        usage.codes.insert(entry);
    }
    sort(&mut trace.retained);
    let mut bound = *trace.retained.last().unwrap();
    let mut pass = 0;
    loop {
        let mut popped = false;
        for queue in 0..queues.len() {
            if stopped[queue] {
                continue;
            }
            sort(&mut queues[queue]);
            let Some(head) = queues[queue].first().copied() else {
                stopped[queue] = true;
                continue;
            };
            if f32::from_bits(head.distance_bits) > f32::from_bits(bound.distance_bits) {
                stopped[queue] = true;
                trace.early_stops.push(EarlyStopEventV3 {
                    pass,
                    cluster_id: trace.queue_entries[queue].0,
                    entry_doc_id: trace.queue_entries[queue].1,
                    doc_id: head.doc_id,
                    distance_bits: head.distance_bits,
                    lower_bound_bits: bound.distance_bits,
                });
                continue;
            }
            queues[queue].remove(0);
            popped = true;
            trace.expanded.push(head.doc_id);
            usage.adjacency.insert(head.doc_id);
            for &neighbor in &i.documents[head.doc_id as usize].adjacency {
                trace.membership_examined.push(neighbor);
                usage.membership.insert(neighbor);
                if !i.documents[neighbor as usize]
                    .cluster_ids
                    .iter()
                    .any(|&c| selected[c as usize])
                {
                    trace.cluster_pruned.push(neighbor);
                    continue;
                }
                if visited[neighbor as usize] {
                    continue;
                }
                visited[neighbor as usize] = true;
                let candidate = score(neighbor);
                trace.compared.push(candidate);
                usage.codes.insert(neighbor);
                if trace.retained.len() < q.params.ef_search as usize
                    || f32::from_bits(candidate.distance_bits) < f32::from_bits(bound.distance_bits)
                {
                    queues[queue].push(candidate);
                    trace.retained.push(candidate);
                    sort(&mut trace.retained);
                    trace.retained.truncate(q.params.ef_search as usize);
                    bound = *trace.retained.last().unwrap();
                }
            }
        }
        if !popped {
            break;
        }
        pass += 1;
    }
    trace.candidates = trace
        .retained
        .iter()
        .take(q.params.rerank_k as usize)
        .copied()
        .collect();
    usage.raw.extend(trace.candidates.iter().map(|x| x.doc_id));
    QueryExecutionV3 {
        trace,
        component_usage: usage,
    }
}
fn reference_exact(
    s: &PreparedRawSnapshotV3,
    q: &QueryV3,
    e: &QueryExecutionV3,
) -> Vec<NodeDistanceF32V3> {
    let dim = usize::from(q.dimension);
    let mut results = Vec::new();
    for candidate in &e.trace.candidates {
        let raw: Vec<f32> = s.raw_bits[candidate.doc_id as usize]
            .iter()
            .map(|&b| f16::from_bits(b).to_f32())
            .collect();
        let mut sum = 0f32;
        for token in q.coordinates.chunks_exact(dim) {
            let mut maxima = raw.chunks_exact(dim).map(|v| dot(token, v));
            let mut maximum = maxima.next().unwrap();
            for value in maxima {
                if value > maximum {
                    maximum = value;
                }
            }
            sum += maximum;
        }
        results.push(NodeDistanceF32V3 {
            doc_id: candidate.doc_id,
            distance_bits: (1f32 - sum / f32::from(q.token_count)).to_bits(),
        });
    }
    sort(&mut results);
    results.truncate(q.params.k as usize);
    results
}

#[test]
fn strict_unreachable_index_authenticates_without_graph_or_candidate_repair() {
    let pools: Vec<_> = [1, 8]
        .into_iter()
        .map(|threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
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
        dimension: 2,
        max_doc_tokens: 1,
        fine_centroids: vec![1., 0., 0., 1.],
        coarse_centroids: vec![1., 0.],
        fine_to_coarse: vec![0, 0],
        cluster_entries: vec![Some(2)],
        documents: (0..3)
            .map(|id| SearchDocumentV3 {
                doc_id: id,
                token_count: 1,
                compact_codes: vec![u32::from(id != 0)],
                cluster_ids: vec![0],
                adjacency: if id == 2 { vec![1] } else { vec![] },
            })
            .collect(),
    };
    let diagnostic = index.validate_policy().unwrap();
    assert!(!diagnostic.directed_reachability_passed);
    assert_eq!(diagnostic.unreachable_memberships, 1);
    // Document 0 is the globally best match and is genuinely unreachable.
    // Authentication must follow this graph, rather than complete its candidates.
    let raw: Vec<_> = (0..3)
        .map(|id| RawDocumentV3 {
            doc_id: id,
            token_count: 1,
            dimension: 2,
            coordinate_bits: if id == 0 {
                vec![0x3c00, 0]
            } else {
                vec![0, 0x3c00]
            },
        })
        .collect();
    let q = QueryV3 {
        query_id: 99,
        dimension: 2,
        token_count: 1,
        coordinates: vec![1., 0.],
        params: SearchParamsV3 {
            k: 1,
            rerank_k: 2,
            cluster_top_t: 1,
            ef_search: 2,
        },
    };
    let s = prepare_raw_snapshot_v3(
        index.clone(),
        &raw,
        &[100, 101, 102],
        1,
        q.params.clone(),
        [13; 32],
        &SigningKey::from_bytes(&[42; 32]),
    )
    .unwrap();
    let root = s.trusted.signed.manifest.document_root;
    assert_eq!(s.index, index);
    let expected = reference_search(&index, &q);
    assert_eq!(
        expected
            .trace
            .candidates
            .iter()
            .map(|x| x.doc_id)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    let exact = reference_exact(&s, &q, &expected);
    assert_eq!(
        exact,
        vec![NodeDistanceF32V3 {
            doc_id: 1,
            distance_bits: 1f32.to_bits()
        }]
    );
    let server = initialize_server_snapshot_v3(s.clone()).unwrap();
    for wire in [RawWireV3::Fp16, RawWireV3::Fp32] {
        {
            let mode = PublicModeV3::Cold;
            let r = req(&s, &q, wire, mode);
            let vo = pools[1]
                .install(|| crate::execute_raw_retrieval_v3(&server, &r))
                .unwrap();
            assert_eq!(
                vo.documents
                    .iter()
                    .map(|d| d.metadata.doc_id)
                    .collect::<Vec<_>>(),
                vec![1, 2]
            );
            let bytes = encode_raw_vo_v3(&vo).unwrap().0;
            for pool in &pools {
                let verified = pool
                    .install(|| verify_raw_retrieval_v3(&s.trusted, &r, &bytes))
                    .unwrap();
                assert_eq!(verified.execution, expected);
                assert_eq!(verified.result.exact.results, exact);
                assert!(!verified.execution.component_usage.membership.contains(&0));
                assert!(!verified.execution.component_usage.raw.contains(&0));
            }
        }
    }
    assert_eq!(server.index, index);
    assert_eq!(server.trusted.signed.manifest.document_root, root);
    println!(
        "strict_unreachable_auth=pass verifications=8 graph_unchanged=true candidates_unchanged=true"
    );
}

#[test]
fn independent_state_machine_matches_256_complete_traces_and_exact_results() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let mut pruning = 0;
    let mut early_stop = 0;
    let mut empty = 0;
    let mut above_ef = 0;
    for seed in 0..256 {
        let (s, q) = fixture(seed);
        let expected = reference_search(&s.index, &q);
        pruning += expected.trace.cluster_pruned.len();
        early_stop += expected.trace.early_stops.len();
        empty += usize::from(expected.trace.queue_entries.is_empty());
        above_ef += usize::from(expected.trace.queue_entries.len() > q.params.ef_search as usize);
        let r = req(&s, &q, RawWireV3::Fp16, PublicModeV3::Cold);
        let server = initialize_server_snapshot_v3(s.clone()).unwrap();
        let (vo, execution, _) = pool
            .install(|| execute_raw_retrieval_measured_v3(&server, &r))
            .unwrap();
        assert_eq!(execution, expected, "seed={seed}");
        assert_eq!(
            vo.results,
            reference_exact(&s, &q, &expected),
            "seed={seed}"
        );
        let verified = pool
            .install(|| verify_raw_retrieval_v3(&s.trusted, &r, &encode_raw_vo_v3(&vo).unwrap().0))
            .unwrap();
        assert_eq!(verified.execution, expected, "seed={seed}");
    }
    assert!(pruning > 0 && early_stop > 0 && empty > 0 && above_ef > 0);
    println!(
        "independent_trace_oracle fixtures=256 pruning={pruning} early_stop={early_stop} empty={empty} entries_above_ef={above_ef}"
    );
}

#[test]
fn complete_verifier_rejects_wire_mutations_and_truncations_without_panic() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let mut mutations = 0;
    let mut truncations = 0;
    for seed in [1, 7, 11, 13, 29, 42, 128, 255] {
        let (s, q) = fixture(seed);
        let server = initialize_server_snapshot_v3(s.clone()).unwrap();
        for wire in [RawWireV3::Fp16, RawWireV3::Fp32] {
            {
                let mode = PublicModeV3::Cold;
                let r = req(&s, &q, wire, mode);
                let vo = pool
                    .install(|| crate::execute_raw_retrieval_v3(&server, &r))
                    .unwrap();
                let bytes = encode_raw_vo_v3(&vo).unwrap().0;
                for step in 0..64 {
                    let position = step * (bytes.len() - 1) / 63;
                    let mut bad = bytes.clone();
                    bad[position] ^= 1 << (step % 8);
                    assert!(
                        pool.install(|| verify_raw_retrieval_v3(&s.trusted, &r, &bad))
                            .is_err(),
                        "accepted mutation seed={seed} at {position}"
                    );
                    mutations += 1;
                }
                for length in 0..bytes.len() {
                    assert!(decode_raw_vo_v3(&bytes[..length], &s.trusted).is_err());
                    truncations += 1;
                }
            }
        }
    }
    println!("wire_audit full_verifier_mutations={mutations} truncated_frames={truncations}");
}

#[test]
fn every_subset_of_small_merkle_trees_has_a_strict_canonical_proof() {
    let mut cases = 0;
    for count in 1..=9 {
        let leaves: Vec<_> = (0..count)
            .map(|id| gem_core::hash_bytes(b"independent-subset", &[id as u8]))
            .collect();
        let tree = DocumentTreeV3::build(&leaves).unwrap();
        for mask in 0..1 << count {
            let ids: Vec<_> = (0..count)
                .filter(|&id| mask & (1 << id) != 0)
                .map(|id| id as u32)
                .collect();
            let opened: Vec<_> = ids.iter().map(|&id| (id, leaves[id as usize])).collect();
            let proof = tree.prove(&ids).unwrap();
            // Independent set-based boundary oracle: only positions are inferred,
            // and the transmitted hashes stay identical to the old proof.
            let mut frontier: std::collections::BTreeSet<_> = ids.iter().copied().collect();
            let mut expected = vec![];
            for row in tree.levels.iter().take(tree.levels.len() - 1) {
                let missing: std::collections::BTreeSet<_> = frontier
                    .iter()
                    .map(|i| i ^ 1)
                    .filter(|i| !frontier.contains(i))
                    .collect();
                expected.extend(missing.iter().map(|&i| row[i as usize]));
                frontier = frontier.iter().map(|i| i / 2).collect();
            }
            assert_eq!(proof.siblings, expected);
            verify_document_multiproof_v3(count as u32, tree.root().unwrap(), &opened, &proof)
                .unwrap();
            for sibling in 0..proof.siblings.len() {
                let mut corrupt = proof.clone();
                corrupt.siblings[sibling][0] ^= 1;
                assert!(
                    verify_document_multiproof_v3(
                        count as u32,
                        tree.root().unwrap(),
                        &opened,
                        &corrupt
                    )
                    .is_err()
                );
                if sibling + 1 < proof.siblings.len() {
                    let mut reordered = proof.clone();
                    reordered.siblings.swap(sibling, sibling + 1);
                    assert!(
                        verify_document_multiproof_v3(
                            count as u32,
                            tree.root().unwrap(),
                            &opened,
                            &reordered
                        )
                        .is_err()
                    );
                }
                let mut bad = proof.clone();
                bad.siblings.remove(sibling);
                assert!(
                    verify_document_multiproof_v3(
                        count as u32,
                        tree.root().unwrap(),
                        &opened,
                        &bad
                    )
                    .is_err()
                );
            }
            cases += 1;
        }
    }
    println!("merkle_exhaustive_subset_cases={cases}");
}

/// Uses a supplied immutable real snapshot. Run explicitly; ordinary unit tests
/// never silently substitute a synthetic corpus for this acceptance check.
#[test]
#[ignore = "requires GEM_RAW_AUTH_AUDIT_ARTIFACT_ROOT and GEM_RAW_AUTH_AUDIT_OUTPUT"]
fn real_lotte10k_independent_membership_and_all_query_search_oracle() {
    use bincode::Options;
    let root = std::path::PathBuf::from(std::env::var("GEM_RAW_AUTH_AUDIT_ARTIFACT_ROOT").unwrap());
    let bytes = std::fs::read(root.join("snapshot/server/snapshot.auth3")).unwrap();
    assert_eq!(&bytes[..8], b"G3SNAP!!");
    let s: PreparedRawSnapshotV3 = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(MAX_VO_BYTES as u64)
        .deserialize(&bytes[18..])
        .unwrap();
    validate_prepared_snapshot_v3(&s).unwrap();
    let out = std::env::var("GEM_RAW_AUTH_AUDIT_OUTPUT").unwrap();
    let export = std::path::Path::new(&out).with_file_name("independent-index-export.json");
    let mut exported = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(export)
        .unwrap();
    use std::io::Write;
    serde_json::to_writer(&mut exported, &s.index).unwrap();
    exported.flush().unwrap();
    exported.sync_all().unwrap();
    assert_eq!(s.index.documents.len(), 10000);
    let codes: Vec<_> = s
        .index
        .documents
        .iter()
        .map(|d| d.compact_codes.clone())
        .collect();
    let memberships = reference_membership(
        &codes,
        &s.index.fine_to_coarse,
        s.index.cluster_entries.len(),
    );
    assert_eq!(
        memberships,
        s.index
            .documents
            .iter()
            .map(|d| d.cluster_ids.clone())
            .collect::<Vec<_>>()
    );
    let (_, coords) = gem_core::read_npy_f32(root.join("data/queries.npy")).unwrap();
    let m = &s.trusted.signed.manifest;
    let query_width = usize::from(m.dimension) * usize::from(m.query_tokens);
    assert_eq!(coords.len(), 661 * query_width);
    let frozen: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("acceptance/frozen-native-1.json")).unwrap(),
    )
    .unwrap();
    let frozen: BTreeMap<u64, gem_search::NativeQueryResultV3> = frozen["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["query_id"].as_u64().unwrap(),
                serde_json::from_value(row["native"].clone()).unwrap(),
            )
        })
        .collect();
    let exact_ids: BTreeSet<_> = [0, 1, 2, 3, 4, 5, 6, 7, 128, 256, 368, 512, 535, 560, 660]
        .into_iter()
        .collect();
    let mut audit = Vec::new();
    for (id, coordinates) in coords.chunks_exact(query_width).enumerate() {
        let q = QueryV3 {
            query_id: id as u64,
            dimension: m.dimension,
            token_count: m.query_tokens,
            coordinates: coordinates.to_vec(),
            params: m.params.clone(),
        };
        let reference = reference_search(&s.index, &q);
        assert_eq!(
            reference.trace,
            frozen[&(id as u64)].trace,
            "real query={id}"
        );
        if exact_ids.contains(&id) {
            assert_eq!(
                reference_exact(&s, &q, &reference),
                frozen[&(id as u64)].exact.results,
                "real MaxSim query={id}"
            );
        }
        audit.push(serde_json::json!({"query_id":id,"search_trace_match":true,"independent_exact_match":exact_ids.contains(&id)}));
        if id % 50 == 0 {
            println!("independent_real_queries={}", id + 1);
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .unwrap();
    file.write_all(&serde_json::to_vec_pretty(&serde_json::json!({"passed":true,"documents":10000,"membership_oracle":true,"independent_search_queries":661,"independent_exact_queries":exact_ids.len(),"root":m.document_root,"queries":audit})).unwrap()).unwrap();
    file.sync_all().unwrap();
}

// Dense counting and pairwise document-frequency scans provide an independent
// reference for normalized TF, IDF, top-20 selection, and cluster-ID ties.
fn reference_membership(codes: &[Vec<u32>], map: &[u32], clusters: usize) -> Vec<Vec<u32>> {
    let counts: Vec<Vec<usize>> = codes
        .iter()
        .map(|doc| {
            let mut row = vec![0; clusters];
            for &code in doc {
                row[map[code as usize] as usize] += 1;
            }
            row
        })
        .collect();
    let df: Vec<usize> = (0..clusters)
        .map(|c| counts.iter().filter(|row| row[c] != 0).count())
        .collect();
    counts
        .iter()
        .zip(codes)
        .map(|(row, doc)| {
            let mut ranked: Vec<(usize, f64)> = (0..clusters)
                .filter(|&c| row[c] != 0)
                .map(|c| {
                    (
                        c,
                        (row[c] as f64 / doc.len() as f64)
                            * (codes.len() as f64 / df[c] as f64).ln(),
                    )
                })
                .collect();
            ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
            let mut selected: Vec<_> = ranked.iter().take(20).map(|x| x.0 as u32).collect();
            selected.sort_unstable();
            selected
        })
        .collect()
}

#[test]
fn freshly_built_graphs_authenticate_and_match_independent_models() {
    use gem_search::QemdCodebookV3;
    use gem_search::{assemble_search_index_v3, build_qemd_graph_v3, build_repo_memberships_v3};
    let pools: Vec<_> = [1, 8]
        .into_iter()
        .map(|n| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .build()
                .unwrap()
        })
        .collect();
    for seed in 300..316 {
        let (base, q) = fixture(seed);
        let codes: Vec<_> = base
            .index
            .documents
            .iter()
            .map(|d| d.compact_codes.clone())
            .collect();
        let membership =
            build_repo_memberships_v3(&codes, base.index.fine_to_coarse.clone(), 3).unwrap();
        assert_eq!(
            membership.memberships,
            reference_membership(&codes, &membership.fine_to_coarse, 3)
        );
        let book = QemdCodebookV3::from_centroids(&base.index.fine_centroids, 4).unwrap();
        let profile = base.index.semantic_profile.clone();
        let params = base.index.graph_params;
        let a = pools[0]
            .install(|| build_qemd_graph_v3(&codes, &membership, &book, &profile, params))
            .unwrap();
        let b = pools[1]
            .install(|| build_qemd_graph_v3(&codes, &membership, &book, &profile, params))
            .unwrap();
        assert_eq!(a, b, "graph construction seed={seed}");
        let mut one_params = params;
        one_params.wave_size = 1;
        let sequential_profile =
            SemanticProfileV3::repo_faithful(GraphBuilderKindV3::RepoSequentialOracle, 1);
        let wave_one_profile =
            SemanticProfileV3::repo_faithful(GraphBuilderKindV3::RepoDeterministicWavefront, 1);
        let sequential = pools[0]
            .install(|| {
                build_qemd_graph_v3(&codes, &membership, &book, &sequential_profile, one_params)
            })
            .unwrap();
        let wave_one = pools[1]
            .install(|| {
                build_qemd_graph_v3(&codes, &membership, &book, &wave_one_profile, one_params)
            })
            .unwrap();
        assert_eq!(sequential, wave_one, "wave=1 seed={seed}");
        let index = assemble_search_index_v3(
            profile,
            params,
            4,
            5,
            base.index.fine_centroids.clone(),
            base.index.coarse_centroids.clone(),
            codes,
            membership,
            a.state.adjacency,
        )
        .unwrap();
        index.validate_policy().unwrap();
        let raw: Vec<_> = base
            .metadata
            .iter()
            .zip(&base.raw_bits)
            .map(|(m, b)| RawDocumentV3 {
                doc_id: m.doc_id,
                token_count: m.token_count,
                dimension: base.trusted.signed.manifest.dimension,
                coordinate_bits: b.clone(),
            })
            .collect();
        let s = prepare_raw_snapshot_v3(
            index,
            &raw,
            &base.source_ids,
            q.token_count,
            q.params.clone(),
            [11; 32],
            &SigningKey::from_bytes(&[42; 32]),
        )
        .unwrap();
        let expected = reference_search(&s.index, &q);
        let exact = reference_exact(&s, &q, &expected);
        let server = initialize_server_snapshot_v3(s.clone()).unwrap();
        for wire in [RawWireV3::Fp16, RawWireV3::Fp32] {
            {
                let mode = PublicModeV3::Cold;
                let r = req(&s, &q, wire, mode);
                let vo = pools[1]
                    .install(|| crate::execute_raw_retrieval_v3(&server, &r))
                    .unwrap();
                let bytes = encode_raw_vo_v3(&vo).unwrap().0;
                for pool in &pools {
                    let verified = pool
                        .install(|| verify_raw_retrieval_v3(&s.trusted, &r, &bytes))
                        .unwrap();
                    assert_eq!(verified.execution, expected);
                    assert_eq!(verified.result.exact.results, exact);
                }
            }
        }
    }
}
