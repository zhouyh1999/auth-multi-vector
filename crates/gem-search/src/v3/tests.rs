use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Mutex,
};

use gem_core::{
    GRAPH_CHECKPOINT_MAGIC_V3, GraphBuilderKindV3, INDEX_MAGIC_V3, QueryV3, RawDocumentF32V3,
    RepairPolicyV3, SemanticProfileV3, decode_frame_v3, encode_frame_v3,
};
use rayon::ThreadPoolBuilder;
use serde::Deserialize;

use super::{
    distance::DistanceDocV3,
    graph::{CACHE_SHARDS, QemdEngineV3, RepoGraphBuilderV3, RuntimeCountersV3},
    *,
};
use crate::qemd::{QEMD_IMPLEMENTATION_ID_V3, QemdCodebookV3, histogram};

#[derive(Debug, Deserialize)]
struct DifferentialFixture {
    reference_commit: String,
    official_hnsw_calls: Vec<String>,
    memberships: Vec<Vec<u32>>,
    postings: Vec<Vec<u32>>,
    graph_steps: Vec<Vec<Vec<u32>>>,
    owner_single_heuristic_union: Vec<u32>,
    owner_cap24_row: Vec<u32>,
    recipient_49_row: Vec<u32>,
    recipient_49_degree: usize,
    stale_owner_row: Vec<u32>,
    stale_reciprocal_row: Vec<u32>,
    strict_repair_capacity_exhausted: bool,
    strict_repair_entry_component: Vec<u32>,
    strict_repair_unbridged_component: Vec<u32>,
    strict_repair_entry_row: Vec<u32>,
    strict_repair_unreachable_row: Vec<u32>,
    qch_distance_bits: Vec<u32>,
    selected_clusters: Vec<u32>,
    queue_entries: Vec<(u32, u32)>,
    visited_order: Vec<u32>,
    expanded: Vec<u32>,
    candidate_ids: Vec<u32>,
    candidate_distance_bits: Vec<u32>,
    query_boundaries: Vec<QueryBoundaryFixture>,
    construction_score_boundary: ConstructionBoundaryFixture,
    qch_multitoken_boundary: QchBoundaryFixture,
}

#[derive(Debug, Deserialize)]
struct ConstructionBoundaryFixture {
    candidate_ids: Vec<u32>,
    owner_row: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct QchBoundaryFixture {
    qch_bits: Vec<u32>,
    candidate_id: u32,
}

fn assert_construction_score_boundary(fixture: &ConstructionBoundaryFixture) {
    // A valid descending-posting insertion prefix at the real ef=80, M0=48.
    // The late, lower-ID node 1 ties the worst distance and must not replace 81.
    let codes: Vec<Vec<u32>> = (0..82)
        .map(|id| {
            vec![if id == 0 {
                2
            } else if id == 1 || id == 81 {
                1
            } else {
                0
            }]
        })
        .collect();
    let book = QemdCodebookV3::from_centroids(&[1.0, 0.0, 0.5], 1).unwrap();
    let membership = build_repo_memberships_v3(&codes, vec![0; 3], 1).unwrap();
    let mut state = GraphBuildStateV3::empty(82);
    state.inserted.fill(true);
    state.inserted[0] = false;
    state.adjacency[81] = (2..=49).collect();
    state.adjacency[2] = (50..=80).collect();
    state.adjacency[80] = vec![1];
    let builder = RepoGraphBuilderV3 {
        compact_codes: &codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::RepoFaithful,
        repair_stats: RepairRunStatsV3::default(),
        state,
        qemd: qemd_engine(&codes, &book),
    };
    let candidates = builder
        .local_search(&builder.state.adjacency, &builder.state.inserted, 0, 81)
        .unwrap();
    assert_eq!(
        candidates.iter().map(|x| x.doc_id).collect::<Vec<_>>(),
        fixture.candidate_ids
    );
    assert_eq!(
        builder
            .owner_replacement(&builder.state.adjacency, 0, &candidates)
            .unwrap(),
        fixture.owner_row
    );
}

fn assert_qch_multitoken_boundary(fixture: &QchBoundaryFixture) {
    // FP16-exact centroids: 1-average rounds these two scores to a tie, changing
    // the sole rerank candidate. Official per-token subtraction retains doc 1.
    let fine = vec![
        0.244_140_63,
        0.0,
        0.245_605_47,
        0.0,
        0.239_746_1,
        0.0,
        0.249_511_72,
        0.0,
    ];
    let codes = vec![vec![0], vec![1]];
    let membership = build_repo_memberships_v3(&codes, vec![0, 0], 1).unwrap();
    let index = assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        4,
        1,
        fine,
        vec![1.0, 0.0, 0.0, 0.0],
        codes,
        membership,
        vec![vec![], vec![0]],
    )
    .unwrap();
    index.validate_policy().unwrap();
    let query = QueryV3 {
        query_id: 0,
        dimension: 4,
        token_count: 2,
        coordinates: vec![0.8, 0.6, 0.0, 0.0, 0.0, 0.0, 0.9, 0.435_889_9],
        params: gem_core::SearchParamsV3 {
            k: 1,
            rerank_k: 1,
            cluster_top_t: 1,
            ef_search: 2,
        },
    };
    let bits: Vec<u32> = (0..2)
        .map(|id| index.qch_distance(&query, id).unwrap().to_bits())
        .collect();
    assert_eq!(bits, fixture.qch_bits);
    let trace = index.search(&query).unwrap();
    assert_eq!(trace.compared.len(), 2);
    assert_eq!(trace.candidates.len(), 1);
    assert_eq!(trace.candidates[0].doc_id, fixture.candidate_id);
}

#[derive(Debug, Deserialize)]
struct QueryBoundaryFixture {
    name: String,
    fine: Vec<f32>,
    mapping: Vec<u32>,
    coarse: Vec<f32>,
    adjacency: Vec<Vec<u32>>,
    cluster_top_t: u32,
    visited: Vec<u32>,
    expanded: Vec<u32>,
    retained: Vec<u32>,
    distance_bits: Vec<u32>,
}

fn differential_fixture() -> DifferentialFixture {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/reference/gem_repo_v3_differential.expected.json"
    ))
    .unwrap()
}

fn params(wave_size: u32) -> GraphBuildParamsV3 {
    GraphBuildParamsV3 {
        m: 24,
        m0: 48,
        ef_construction: 80,
        qemd_max_iterations: 1_000,
        wave_size,
    }
}

fn equal_cost_codebook(count: usize) -> QemdCodebookV3 {
    let mut costs = vec![1.0f32; count * count];
    for code in 0..count {
        costs[code * count + code] = 0.0;
    }
    QemdCodebookV3 {
        fine_count: count as u32,
        costs,
    }
}

fn qemd_engine<'a>(
    compact_codes: &'a [Vec<u32>],
    codebook: &'a QemdCodebookV3,
) -> QemdEngineV3<'a> {
    QemdEngineV3 {
        compact_codes,
        histograms: compact_codes
            .iter()
            .map(|codes| histogram(codes, codebook.fine_count).unwrap())
            .collect(),
        codebook,
        max_iterations: 1_000,
        cache: (0..CACHE_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect(),
        in_flight: (0..CACHE_SHARDS)
            .map(|_| Mutex::new(HashSet::new()))
            .collect(),
        counters: RuntimeCountersV3::new(),
    }
}

fn transpose_sensitive_codebook() -> (QemdCodebookV3, Vec<Vec<u32>>) {
    let mut seed = 71_u64;
    let centroids: Vec<f32> = (0..32 * 8)
        .map(|_| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (((seed >> 32) as u32 % 2_049) as f32 - 1_024.0) / 2_048.0
        })
        .collect();
    // All coordinates are exactly representable as f16. This pair exposes a
    // one-ULP transpose difference with the production LEMON solver.
    let codes = vec![
        vec![21, 15, 7, 4, 4, 4, 29, 22],
        vec![
            16, 16, 4, 7, 14, 11, 26, 17, 17, 21, 4, 18, 6, 27, 26, 30, 26, 8, 16, 31,
        ],
    ];
    (
        QemdCodebookV3::from_centroids(&centroids, 8).unwrap(),
        codes,
    )
}

#[test]
fn qemd_cache_direction_is_identical_cold_warm_parallel_and_after_clear() {
    use rayon::prelude::*;
    let (book, codes) = transpose_sensitive_codebook();
    let expected = book.distance(&codes[0], &codes[1]).unwrap().to_bits();
    #[cfg(feature = "lemon-qemd")]
    assert_ne!(
        expected,
        book.distance(&codes[1], &codes[0]).unwrap().to_bits()
    );

    let pool = ThreadPoolBuilder::new().num_threads(4).build().unwrap();
    for reverse_first in [false, true] {
        let engine = qemd_engine(&codes, &book);
        let (a, b) = if reverse_first { (1, 0) } else { (0, 1) };
        assert_eq!(engine.distance(a, b).unwrap().to_bits(), expected);
        assert_eq!(engine.distance(b, a).unwrap().to_bits(), expected);
        assert_eq!(
            engine
                .cache
                .iter()
                .map(|s| s.lock().unwrap().len())
                .sum::<usize>(),
            1
        );
        for _ in 0..3 {
            for shard in &engine.cache {
                shard.lock().unwrap().clear();
            }
            let bits = pool.install(|| {
                (0..64_u32)
                    .into_par_iter()
                    .map(|i| engine.distance(i % 2, 1 - i % 2).unwrap().to_bits())
                    .collect::<Vec<_>>()
            });
            assert!(bits.iter().all(|&value| value == expected));
        }
    }
}

#[test]
#[cfg(feature = "lemon-qemd")]
fn qemd_cache_first_direction_cannot_change_cap24_heuristic() {
    let (original, mut codes) = transpose_sensitive_codebook();
    let reversed = original.distance(&codes[1], &codes[0]).unwrap();
    // Add a finite synthetic constant-cost code at the one-ULP boundary;
    // retain the real centroid-derived 32x32 submatrix.
    let mut costs = vec![reversed; 33 * 33];
    for i in 0..32 {
        for j in 0..32 {
            costs[i * 33 + j] = original.costs[i * 32 + j];
        }
    }
    costs[32 * 33 + 32] = 0.0;
    let book = QemdCodebookV3 {
        fine_count: 33,
        costs,
    };
    codes.push(vec![32]);
    codes.extend((0..22).map(|_| codes[0].clone()).collect::<Vec<_>>());
    for (a, b) in [(0, 1), (1, 0)] {
        let engine = qemd_engine(&codes, &book);
        engine.distance(a, b).unwrap();
        let row = engine
            .heuristic_neighbors(2, (0..25).filter(|&id| id != 2), 24)
            .unwrap();
        assert_eq!(row, vec![0]);
    }
}

#[test]
fn empty_selected_bucket_returns_an_empty_native_result() {
    let codes = vec![vec![0]];
    let membership = build_repo_memberships_v3(&codes, vec![0], 2).unwrap();
    let index = assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        2,
        1,
        vec![1.0, 0.0],
        vec![1.0, 0.0, 0.0, 1.0],
        codes,
        membership,
        vec![vec![]],
    )
    .unwrap();
    index.validate_policy().unwrap();
    let query = QueryV3 {
        query_id: 0,
        dimension: 2,
        token_count: 1,
        coordinates: vec![0.0, 1.0],
        params: gem_core::SearchParamsV3 {
            k: 1,
            rerank_k: 1,
            cluster_top_t: 1,
            ef_search: 1,
        },
    };
    let raw = vec![RawDocumentF32V3 {
        doc_id: 0,
        token_count: 1,
        dimension: 2,
        coordinates: vec![1.0, 0.0],
    }];
    let result = native_query_v3(&index, &raw, &query).unwrap();
    assert_eq!(result.trace.selected_clusters, vec![1]);
    assert!(result.trace.queue_entries.is_empty());
    assert!(result.trace.compared.is_empty());
    assert!(result.trace.expanded.is_empty());
    assert!(result.trace.candidates.is_empty());
    assert!(result.exact.results.is_empty());
}

#[test]
fn repo_membership_is_fixed_top20_with_canonical_ties_and_postings() {
    let codes = vec![(0..25).collect::<Vec<u32>>(), (0..25).collect()];
    let membership = build_repo_memberships_v3(&codes, (0..25).collect(), 25).unwrap();
    assert_eq!(membership.memberships[0], (0..20).collect::<Vec<_>>());
    assert_eq!(membership.memberships[1], (0..20).collect::<Vec<_>>());
    assert_eq!(membership.postings[0], vec![1, 0]);
    assert_eq!(membership.cluster_entries[0], Some(1));
    assert!(membership.postings[20].is_empty());
}

#[test]
fn rust_matches_independent_corrected_cpp_differential_fixture() {
    let fixture = differential_fixture();
    assert_construction_score_boundary(&fixture.construction_score_boundary);
    assert_qch_multitoken_boundary(&fixture.qch_multitoken_boundary);
    assert_eq!(fixture.reference_commit, gem_core::REFERENCE_COMMIT_V3);
    assert_eq!(
        fixture.official_hnsw_calls,
        [
            "addClusterPointEntry",
            "mutuallyConnectUpdateElementCluster",
            "mutuallyConnectNewElementCluster",
            "searchNodesForFix",
            "canAddEdgeinter",
            "mutuallyConnectTwoInterElement",
            "searchKnnClusterEntries",
        ]
    );
    let compact_codes = vec![vec![0], vec![1]];
    let membership = build_repo_memberships_v3(&compact_codes, vec![0, 0], 1).unwrap();
    assert_eq!(membership.memberships, fixture.memberships);
    assert_eq!(membership.postings, fixture.postings);
    assert_eq!(fixture.graph_steps[0], vec![Vec::<u32>::new(), Vec::new()]);
    let built = build_qemd_graph_v3(
        &compact_codes,
        &membership,
        &equal_cost_codebook(2),
        &SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
    )
    .unwrap();
    assert_eq!(built.state.adjacency, fixture.graph_steps[1]);

    let owner_codes: Vec<Vec<u32>> = (0..26).map(|code| vec![code]).collect();
    let owner_membership =
        build_repo_memberships_v3(&owner_codes, vec![0; owner_codes.len()], 1).unwrap();
    let owner_codebook = equal_cost_codebook(owner_codes.len());
    let mut owner_state = GraphBuildStateV3::empty(owner_codes.len());
    owner_state.inserted.fill(true);
    let owner_builder = RepoGraphBuilderV3 {
        compact_codes: &owner_codes,
        membership: &owner_membership,
        params: params(1),
        repair_policy: RepairPolicyV3::RepoFaithful,
        repair_stats: RepairRunStatsV3::default(),
        state: owner_state,
        qemd: qemd_engine(&owner_codes, &owner_codebook),
    };
    let owner_candidates: Vec<DistanceDocV3> = (1..26)
        .map(|doc_id| DistanceDocV3::new(doc_id, 1.0).unwrap())
        .collect();
    assert_eq!(
        owner_builder
            .owner_replacement(&owner_builder.state.adjacency, 0, &owner_candidates)
            .unwrap(),
        fixture.owner_cap24_row
    );

    let index = assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        2,
        1,
        vec![1.0, 0.0, 0.0, 1.0],
        vec![1.0, 0.0],
        compact_codes,
        membership,
        built.state.adjacency,
    )
    .unwrap();
    let query = native_query();
    let distance_bits: Vec<u32> = (0..2)
        .map(|doc_id| index.qch_distance(&query, doc_id).unwrap().to_bits())
        .collect();
    assert_eq!(distance_bits, fixture.qch_distance_bits);
    let trace = index.search(&query).unwrap();
    assert_eq!(trace.selected_clusters, fixture.selected_clusters);
    assert_eq!(trace.queue_entries, fixture.queue_entries);
    assert_eq!(
        trace
            .compared
            .iter()
            .map(|row| row.doc_id)
            .collect::<Vec<_>>(),
        fixture.visited_order
    );
    assert_eq!(trace.expanded, fixture.expanded);
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|row| row.doc_id)
            .collect::<Vec<_>>(),
        fixture.candidate_ids
    );
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|row| row.distance_bits)
            .collect::<Vec<_>>(),
        fixture.candidate_distance_bits
    );
    for boundary in fixture.query_boundaries {
        let codes: Vec<Vec<u32>> = (0..boundary.fine.len() as u32).map(|id| vec![id]).collect();
        let membership =
            build_repo_memberships_v3(&codes, boundary.mapping, boundary.coarse.len()).unwrap();
        let index = assemble_search_index_v3(
            SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
            params(1),
            1,
            1,
            boundary.fine,
            boundary.coarse,
            codes,
            membership,
            boundary.adjacency,
        )
        .unwrap();
        index.validate_policy().unwrap();
        let query = QueryV3 {
            query_id: 0,
            dimension: 1,
            token_count: 1,
            coordinates: vec![1.0],
            params: gem_core::SearchParamsV3 {
                k: 2,
                rerank_k: 2,
                cluster_top_t: boundary.cluster_top_t,
                ef_search: 2,
            },
        };
        let trace = index.search(&query).unwrap();
        assert_eq!(
            trace.compared.iter().map(|x| x.doc_id).collect::<Vec<_>>(),
            boundary.visited,
            "{}",
            boundary.name
        );
        assert_eq!(trace.expanded, boundary.expanded, "{}", boundary.name);
        assert_eq!(
            trace.retained.iter().map(|x| x.doc_id).collect::<Vec<_>>(),
            boundary.retained,
            "{}",
            boundary.name
        );
        assert_eq!(
            trace
                .retained
                .iter()
                .map(|x| x.distance_bits)
                .collect::<Vec<_>>(),
            boundary.distance_bits,
            "{}",
            boundary.name
        );
        assert_eq!(
            trace
                .candidates
                .iter()
                .map(|x| x.doc_id)
                .collect::<Vec<_>>(),
            boundary.retained.into_iter().take(2).collect::<Vec<_>>(),
            "{}",
            boundary.name
        );
    }
}

#[test]
fn owner_old_new_union_over_24_is_pruned_and_stale_reciprocal_survives() {
    let compact_codes: Vec<Vec<u32>> = (0..130).map(|code| vec![code]).collect();
    let codebook = equal_cost_codebook(compact_codes.len());
    let membership =
        build_repo_memberships_v3(&compact_codes, vec![0; compact_codes.len()], 1).unwrap();
    let mut state = GraphBuildStateV3::empty(compact_codes.len());
    state.inserted.fill(true);
    state.adjacency[129] = (100..124).collect();
    state.adjacency[100] = vec![129];
    let builder = RepoGraphBuilderV3 {
        compact_codes: &compact_codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::RepoFaithful,
        repair_stats: RepairRunStatsV3::default(),
        state,
        qemd: qemd_engine(&compact_codes, &codebook),
    };
    let candidates: Vec<DistanceDocV3> = (0..25)
        .map(|doc_id| DistanceDocV3::new(doc_id, 1.0).unwrap())
        .collect();
    let replacement = builder
        .owner_replacement(&builder.state.adjacency, 129, &candidates)
        .unwrap();
    assert_eq!(replacement.len(), 24);
    assert_eq!(replacement, (0..24).collect::<Vec<_>>());
    assert_eq!(builder.state.adjacency[100], vec![129]);
    assert!(replacement.binary_search(&100).is_err());
}

#[test]
fn existing_owner_union_uses_one_non_composable_repo_heuristic() {
    let fixture = differential_fixture();
    let compact_codes: Vec<Vec<u32>> = (0..26).map(|code| vec![code]).collect();
    let membership = build_repo_memberships_v3(&compact_codes, vec![0; 26], 1).unwrap();
    let mut costs = vec![2.0f32; 26 * 26];
    for code in 0..26 {
        costs[code * 26 + code] = 0.0;
    }
    let mut set_cost = |left: usize, right: usize, cost: f32| {
        costs[left * 26 + right] = cost;
        costs[right * 26 + left] = cost;
    };
    set_cost(0, 1, 0.5);
    set_cost(0, 2, 1.0);
    set_cost(0, 3, 1.5);
    set_cost(1, 2, 0.75);
    set_cost(1, 3, 1.75);
    set_cost(2, 3, 1.25);
    for filler in 4..26 {
        set_cost(0, filler, 1.9);
        set_cost(1, filler, 0.0);
        set_cost(2, filler, 0.0);
    }
    let codebook = QemdCodebookV3 {
        fine_count: 26,
        costs,
    };
    let mut state = GraphBuildStateV3::empty(compact_codes.len());
    state.inserted.fill(true);
    state.adjacency[0] = vec![1];
    let builder = RepoGraphBuilderV3 {
        compact_codes: &compact_codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::RepoFaithful,
        repair_stats: RepairRunStatsV3::default(),
        state,
        qemd: qemd_engine(&compact_codes, &codebook),
    };
    let mut candidates = vec![
        DistanceDocV3::new(2, 1.0).unwrap(),
        DistanceDocV3::new(3, 1.5).unwrap(),
    ];
    candidates.extend((4..26).map(|doc_id| DistanceDocV3::new(doc_id, 1.9).unwrap()));

    let one_shot = builder
        .owner_replacement(&builder.state.adjacency, 0, &candidates)
        .unwrap();
    let pretrimmed = builder
        .qemd
        .heuristic_neighbors(0, candidates.iter().map(|candidate| candidate.doc_id), 24)
        .unwrap();
    let old_double_heuristic = builder
        .qemd
        .heuristic_neighbors(
            0,
            builder.state.adjacency[0]
                .iter()
                .copied()
                .chain(pretrimmed.iter().copied()),
            24,
        )
        .unwrap();

    assert_eq!(one_shot, fixture.owner_single_heuristic_union);
    assert_eq!(pretrimmed, vec![2]);
    assert_eq!(old_double_heuristic, vec![1, 2]);
    assert_ne!(one_shot, old_double_heuristic);

    let mut stale_state = GraphBuildStateV3::empty(compact_codes.len());
    stale_state.inserted.fill(true);
    stale_state.adjacency[0] = vec![2];
    stale_state.adjacency[2] = vec![0];
    let stale_builder = RepoGraphBuilderV3 {
        compact_codes: &compact_codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::RepoFaithful,
        repair_stats: RepairRunStatsV3::default(),
        state: stale_state,
        qemd: qemd_engine(&compact_codes, &codebook),
    };
    let mut stale_candidates = vec![
        DistanceDocV3::new(1, 0.5).unwrap(),
        DistanceDocV3::new(3, 1.5).unwrap(),
    ];
    stale_candidates.extend((4..26).map(|doc_id| DistanceDocV3::new(doc_id, 1.9).unwrap()));
    assert_eq!(
        stale_builder
            .owner_replacement(&stale_builder.state.adjacency, 0, &stale_candidates)
            .unwrap(),
        fixture.stale_owner_row
    );
    assert_eq!(
        stale_builder.state.adjacency[2],
        fixture.stale_reciprocal_row
    );
}

#[test]
fn recipient_49th_intent_runs_m0_48_repo_heuristic() {
    let fixture = differential_fixture();
    let compact_codes: Vec<Vec<u32>> = (0..50).map(|code| vec![code]).collect();
    let codebook = equal_cost_codebook(compact_codes.len());
    let membership =
        build_repo_memberships_v3(&compact_codes, vec![0; compact_codes.len()], 1).unwrap();
    let mut state = GraphBuildStateV3::empty(compact_codes.len());
    state.inserted.fill(true);
    state.adjacency[0] = (1..=48).collect();
    let builder = RepoGraphBuilderV3 {
        compact_codes: &compact_codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::RepoFaithful,
        repair_stats: RepairRunStatsV3::default(),
        state,
        qemd: qemd_engine(&compact_codes, &codebook),
    };
    let reduced = builder
        .reduce_recipient(&builder.state.adjacency, &BTreeMap::new(), 0, &[(49, 49)])
        .unwrap();
    assert_eq!(reduced.len(), fixture.recipient_49_degree);
    assert_eq!(reduced, fixture.recipient_49_row);
}

fn four_document_membership() -> MembershipIndexV3 {
    MembershipIndexV3 {
        fine_to_coarse: vec![0, 0, 0, 0],
        memberships: vec![vec![0], vec![0], vec![0], vec![0]],
        postings: vec![vec![3, 2, 1, 0]],
        cluster_entries: vec![Some(3)],
    }
}

#[test]
fn disconnected_index_is_usable_and_reachability_remains_diagnostic() {
    let membership = four_document_membership();
    let compact_codes = vec![vec![0], vec![1], vec![2], vec![3]];
    let adjacency = vec![vec![], vec![0], vec![], vec![2]];
    let index = assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        1,
        1,
        vec![0.0, 1.0, 2.0, 3.0],
        vec![1.0],
        compact_codes.clone(),
        membership.clone(),
        adjacency.clone(),
    )
    .unwrap();
    for profile in [
        SemanticProfileV3::repo_faithful(GraphBuilderKindV3::RepoSequentialOracle, 1),
        SemanticProfileV3::reachability_safe(GraphBuilderKindV3::RepoSequentialOracle, 1),
    ] {
        let mut candidate = index.clone();
        candidate.semantic_profile = profile;
        let summary = candidate.validate_policy().unwrap();
        assert!(!summary.directed_reachability_passed);
        assert_eq!(summary.reachable_memberships, 2);
        assert_eq!(summary.unreachable_memberships, 2);
        assert_eq!(summary.membership_count, 4);
        let query = QueryV3 {
            query_id: 0,
            dimension: 1,
            token_count: 1,
            coordinates: vec![1.0],
            params: gem_core::SearchParamsV3 {
                k: 4,
                rerank_k: 4,
                cluster_top_t: 1,
                ef_search: 4,
            },
        };
        let trace = candidate.search(&query).unwrap();
        assert_eq!(trace.candidates.len(), 2);
        // Disconnection is allowed; malformed edges and incorrect entries are not.
        candidate.documents[3].adjacency.push(4);
        assert!(candidate.validate_policy().is_err());
        candidate.documents[3].adjacency.pop();
        candidate.cluster_entries[0] = Some(2);
        assert!(candidate.validate_policy().is_err());
    }

    let codebook = equal_cost_codebook(4);
    let mut state = GraphBuildStateV3::empty(4);
    state.inserted.fill(true);
    state.adjacency = adjacency;
    let mut builder = RepoGraphBuilderV3 {
        compact_codes: &compact_codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::RepoFaithful,
        repair_stats: RepairRunStatsV3::default(),
        state,
        qemd: qemd_engine(&compact_codes, &codebook),
    };
    builder.repair_cluster_repo(0).unwrap();
    let repaired_adjacency = builder.state.adjacency.clone();
    drop(builder);
    let repaired = assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        1,
        1,
        vec![0.0, 1.0, 2.0, 3.0],
        vec![1.0],
        compact_codes,
        membership,
        repaired_adjacency,
    )
    .unwrap();
    assert!(
        repaired
            .validate_policy()
            .unwrap()
            .directed_reachability_passed
    );
}

#[test]
fn reachability_safe_repair_evicts_only_nonmembership_edge() {
    let document_count = 51usize;
    let mut memberships = vec![vec![1]; document_count];
    memberships[49] = vec![0];
    memberships[50] = vec![0];
    let membership = MembershipIndexV3 {
        fine_to_coarse: vec![0, 1],
        memberships,
        postings: vec![vec![50, 49], (0..=48).rev().collect()],
        cluster_entries: vec![Some(50), Some(48)],
    };
    let compact_codes = vec![vec![0]; document_count];
    let codebook = equal_cost_codebook(2);
    let mut state = GraphBuildStateV3::empty(document_count);
    state.inserted.fill(true);
    state.adjacency[50] = (0..48).collect();
    let mut builder = RepoGraphBuilderV3 {
        compact_codes: &compact_codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::ReachabilitySafeExtension,
        repair_stats: RepairRunStatsV3::default(),
        state,
        qemd: qemd_engine(&compact_codes, &codebook),
    };

    builder.repair_cluster_repo(0).unwrap();

    assert_eq!(builder.state.adjacency[50].len(), 48);
    assert_eq!(builder.state.adjacency[50][0], 1);
    assert!(builder.state.adjacency[50].binary_search(&49).is_ok());
    assert_eq!(builder.state.adjacency[49], vec![50]);
    assert_eq!(builder.state.repair_capacity_evictions, 1);
    let mut marked = BTreeSet::new();
    assert_eq!(builder.bfs_component(0, 50, &mut marked), vec![50, 49]);
}

#[test]
fn repo_faithful_repair_records_full_capacity_and_leaves_component_unbridged() {
    let fixture = differential_fixture();
    let document_count = 51usize;
    let mut memberships = vec![vec![1]; document_count];
    memberships[49] = vec![0];
    memberships[50] = vec![0];
    let membership = MembershipIndexV3 {
        fine_to_coarse: vec![0, 1],
        memberships,
        postings: vec![vec![50, 49], (0..=48).rev().collect()],
        cluster_entries: vec![Some(50), Some(48)],
    };
    let compact_codes = vec![vec![0]; document_count];
    let codebook = equal_cost_codebook(2);
    let mut state = GraphBuildStateV3::empty(document_count);
    state.inserted.fill(true);
    state.adjacency[50] = (0..48).collect();
    let original_row = state.adjacency[50].clone();
    let mut builder = RepoGraphBuilderV3 {
        compact_codes: &compact_codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::RepoFaithful,
        repair_stats: RepairRunStatsV3::default(),
        state,
        qemd: qemd_engine(&compact_codes, &codebook),
    };

    builder.repair_cluster_repo(0).unwrap();

    assert_eq!(builder.state.adjacency[50], original_row);
    assert!(builder.state.adjacency[49].is_empty());
    assert!(fixture.strict_repair_capacity_exhausted);
    assert_eq!(vec![50], fixture.strict_repair_entry_component);
    assert_eq!(vec![49], fixture.strict_repair_unbridged_component);
    assert_eq!(builder.state.adjacency[50], fixture.strict_repair_entry_row);
    assert_eq!(
        builder.state.adjacency[49],
        fixture.strict_repair_unreachable_row
    );
    assert_eq!(builder.state.repair_capacity_evictions, 0);
    assert_eq!(builder.repair_stats.capacity_exhaustions, 1);
    assert_eq!(builder.repair_stats.capacity_evictions, 0);
    assert_eq!(
        builder.repair_stats.unbridged_components,
        vec![RepairUnbridgedComponentV3 {
            cluster_id: 0,
            component_entry: 49,
            entry_reached_documents: 1,
            component_documents: 1,
        }]
    );
    let repaired_adjacency = builder.state.adjacency.clone();
    drop(builder);

    let index = assemble_search_index_v3_unvalidated(
        SemanticProfileV3::repo_faithful(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        1,
        1,
        vec![1.0, 1.0],
        vec![1.0, 1.0],
        compact_codes,
        membership,
        repaired_adjacency,
    )
    .unwrap();
    let summary = index.validate_policy().unwrap();
    assert!(!summary.directed_reachability_passed);
    assert_eq!(summary.reachable_memberships, 2);
    assert_eq!(summary.unreachable_memberships, 49);
}

#[test]
fn reachability_safe_repair_can_evict_shared_but_redundant_edge() {
    let document_count = 51usize;
    let mut memberships = vec![vec![1]; document_count];
    memberships[49] = vec![0];
    memberships[50] = vec![0, 1];
    let mut cluster_one_posting = vec![50];
    cluster_one_posting.extend((0..=48).rev());
    let membership = MembershipIndexV3 {
        fine_to_coarse: vec![0, 1],
        memberships,
        postings: vec![vec![50, 49], cluster_one_posting],
        cluster_entries: vec![Some(50), Some(50)],
    };
    let compact_codes = vec![vec![0]; document_count];
    let codebook = equal_cost_codebook(2);
    let mut state = GraphBuildStateV3::empty(document_count);
    state.inserted.fill(true);
    state.adjacency[1] = vec![0];
    state.adjacency[50] = (0..48).collect();
    let mut builder = RepoGraphBuilderV3 {
        compact_codes: &compact_codes,
        membership: &membership,
        params: params(1),
        repair_policy: RepairPolicyV3::ReachabilitySafeExtension,
        repair_stats: RepairRunStatsV3::default(),
        state,
        qemd: qemd_engine(&compact_codes, &codebook),
    };
    let before = builder.reachable_set_skipping(1, 50, None);

    builder.repair_cluster_repo(0).unwrap();

    assert_eq!(builder.state.adjacency[50].len(), 48);
    assert!(builder.state.adjacency[50].binary_search(&0).is_err());
    assert!(builder.state.adjacency[50].binary_search(&49).is_ok());
    assert_eq!(builder.reachable_set_skipping(1, 50, None), before);
    assert_eq!(builder.state.repair_capacity_evictions, 1);
}

#[test]
fn safe_repair_preserves_other_cluster_and_rejects_only_essential_edges() {
    // Cluster 0 needs a bridge from full row 49 to document 48. All 48
    // existing edges are in cluster 1, whose entry is also 49. Edge 49->0
    // is essential; 49->1 is redundant only when the path 49->0->1 exists.
    for redundant_path in [false, true] {
        let mut compact_codes = vec![vec![1]; 50];
        compact_codes[48] = vec![0];
        compact_codes[49] = vec![0, 1];
        let membership = build_repo_memberships_v3(&compact_codes, vec![0, 1], 2).unwrap();
        let codebook = equal_cost_codebook(2);
        let mut state = GraphBuildStateV3::empty(50);
        state.inserted.fill(true);
        state.adjacency[49] = (0..48).collect();
        if redundant_path {
            state.adjacency[0] = vec![1];
        }
        let original = state.clone();
        let mut builder = RepoGraphBuilderV3 {
            compact_codes: &compact_codes,
            membership: &membership,
            params: params(1),
            repair_policy: RepairPolicyV3::ReachabilitySafeExtension,
            repair_stats: RepairRunStatsV3::default(),
            state,
            qemd: qemd_engine(&compact_codes, &codebook),
        };
        let result = builder.repair_cluster_repo(0);
        if redundant_path {
            result.unwrap();
            assert!(builder.state.adjacency[49].contains(&0));
            assert!(!builder.state.adjacency[49].contains(&1));
            assert!(builder.state.adjacency[49].contains(&48));
            assert_eq!(builder.state.adjacency[49].len(), 48);
            assert_eq!(builder.state.repair_capacity_evictions, 1);
            assert_eq!(
                builder.reachable_set_skipping(0, 49, None),
                BTreeSet::from([48, 49])
            );
            assert_eq!(
                builder.reachable_set_skipping(1, 49, None),
                (0..48).chain([49]).collect()
            );
        } else {
            assert!(result.unwrap_err().to_string().contains("no safe capacity"));
            assert_eq!(builder.state, original);
        }
    }
}

fn native_index() -> SearchIndexV3 {
    let membership = MembershipIndexV3 {
        fine_to_coarse: vec![0, 0],
        memberships: vec![vec![0], vec![0]],
        postings: vec![vec![1, 0]],
        cluster_entries: vec![Some(1)],
    };
    assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        2,
        1,
        vec![1.0, 0.0, 0.0, 1.0],
        vec![1.0, 0.0],
        vec![vec![0], vec![1]],
        membership,
        vec![vec![], vec![0]],
    )
    .unwrap()
}

fn native_query() -> QueryV3 {
    QueryV3 {
        query_id: 0,
        dimension: 2,
        token_count: 1,
        coordinates: vec![1.0, 0.0],
        params: gem_core::SearchParamsV3 {
            k: 1,
            rerank_k: 2,
            cluster_top_t: 1,
            ef_search: 2,
        },
    }
}

#[test]
fn repo_qch_round_robin_and_fp32_rerank_use_distance_direction() {
    let index = native_index();
    let query = native_query();
    assert_eq!(
        index.qch_distance(&query, 0).unwrap().to_bits(),
        0.0f32.to_bits()
    );
    assert_eq!(
        index.qch_distance(&query, 1).unwrap().to_bits(),
        1.0f32.to_bits()
    );
    let trace = index.search(&query).unwrap();
    assert_eq!(trace.queue_entries, vec![(0, 1)]);
    assert_eq!(trace.expanded, vec![1, 0]);
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|row| row.doc_id)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    let raw = vec![
        RawDocumentF32V3 {
            doc_id: 0,
            token_count: 1,
            dimension: 2,
            coordinates: vec![1.0, 0.0],
        },
        RawDocumentF32V3 {
            doc_id: 1,
            token_count: 1,
            dimension: 2,
            coordinates: vec![0.0, 1.0],
        },
    ];
    let native = native_query_v3(&index, &raw, &query).unwrap();
    assert_eq!(native.exact.results[0].doc_id, 0);
    assert_eq!(native.exact.results[0].distance_bits, 0.0f32.to_bits());
}

#[test]
fn repo_qch_initial_lower_bound_covers_all_entries_above_ef() {
    let membership = MembershipIndexV3 {
        fine_to_coarse: vec![0, 1, 2],
        memberships: vec![vec![0], vec![1], vec![2]],
        postings: vec![vec![0], vec![1], vec![2]],
        cluster_entries: vec![Some(0), Some(1), Some(2)],
    };
    let index = assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        2,
        1,
        vec![1.0, 0.0, 0.5, 0.0, 0.0, 1.0],
        vec![1.0, 0.0, 0.5, 0.0, 0.0, 1.0],
        vec![vec![0], vec![1], vec![2]],
        membership,
        vec![vec![], vec![], vec![]],
    )
    .unwrap();
    let query = QueryV3 {
        query_id: 0,
        dimension: 2,
        token_count: 1,
        coordinates: vec![1.0, 0.0],
        params: gem_core::SearchParamsV3 {
            k: 1,
            rerank_k: 2,
            cluster_top_t: 3,
            ef_search: 2,
        },
    };

    let trace = index.search(&query).unwrap();
    assert_eq!(trace.queue_entries, vec![(0, 0), (1, 1), (2, 2)]);
    assert_eq!(trace.expanded, vec![0, 1, 2]);
    assert!(trace.early_stops.is_empty());
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|row| row.doc_id)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
}

#[test]
fn equal_qch_distance_keeps_score_only_admission_without_early_stop() {
    let membership = MembershipIndexV3 {
        fine_to_coarse: vec![0],
        memberships: vec![vec![0], vec![0], vec![0]],
        postings: vec![vec![2, 1, 0]],
        cluster_entries: vec![Some(2)],
    };
    let index = assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        1,
        1,
        vec![1.0],
        vec![1.0],
        vec![vec![0], vec![0], vec![0]],
        membership,
        vec![vec![], vec![], vec![0, 1]],
    )
    .unwrap();
    let query = QueryV3 {
        query_id: 0,
        dimension: 1,
        token_count: 1,
        coordinates: vec![1.0],
        params: gem_core::SearchParamsV3 {
            k: 1,
            rerank_k: 2,
            cluster_top_t: 1,
            ef_search: 2,
        },
    };

    let trace = index.search(&query).unwrap();
    assert_eq!(trace.expanded, vec![2, 0]);
    assert!(trace.early_stops.is_empty());
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|row| row.doc_id)
            .collect::<Vec<_>>(),
        vec![0, 2]
    );
    assert!(
        trace
            .candidates
            .iter()
            .all(|row| row.distance_bits == 0.0f32.to_bits())
    );
}

#[test]
fn native_trace_and_score_bits_are_thread_invariant() {
    let index = native_index();
    let query = native_query();
    let run = |threads| {
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| index.search(&query).unwrap())
    };
    assert_eq!(run(1), run(4));
}

#[test]
fn disabled_default_retains_callable_canonical_shortcut_injector() {
    let membership = MembershipIndexV3 {
        fine_to_coarse: vec![0, 1],
        memberships: vec![vec![0], vec![0], vec![1]],
        postings: vec![vec![1, 0], vec![2]],
        cluster_entries: vec![Some(1), Some(2)],
    };
    let index = assemble_search_index_v3(
        SemanticProfileV3::repo(GraphBuilderKindV3::RepoSequentialOracle, 1),
        params(1),
        2,
        1,
        vec![1.0, 0.0, 0.0, 1.0],
        vec![1.0, 0.0, 0.0, 1.0],
        vec![vec![0], vec![1], vec![1]],
        membership,
        vec![vec![], vec![0], vec![]],
    )
    .unwrap();
    assert_eq!(
        index.semantic_profile.shortcut_policy_id,
        gem_core::SHORTCUT_POLICY_DISABLED_V3
    );
    let query = QueryV3 {
        query_id: 7,
        dimension: 2,
        token_count: 1,
        coordinates: vec![1.0, 0.0],
        params: gem_core::SearchParamsV3 {
            k: 1,
            rerank_k: 1,
            cluster_top_t: 1,
            ef_search: 1,
        },
    };
    let output = inject_shortcuts_v3(
        &index,
        &[query],
        &[ShortcutTrainingPairV3 {
            query_id: 7,
            positive_doc_id: 2,
        }],
        48,
    )
    .unwrap();
    assert_eq!(output.report.injected_undirected_edges, 1);
    assert_eq!(output.adjacency[0], vec![2]);
    assert_eq!(output.adjacency[2], vec![0]);
    assert_eq!(index.documents[0].adjacency, Vec::<u32>::new());
}

fn wave_fixture() -> (Vec<Vec<u32>>, MembershipIndexV3, QemdCodebookV3) {
    let compact_codes = vec![
        vec![0],
        vec![1],
        vec![2],
        vec![3],
        vec![0],
        vec![1],
        vec![2],
        vec![3],
    ];
    let membership = build_repo_memberships_v3(&compact_codes, vec![0, 0, 1, 1], 2).unwrap();
    let codebook = equal_cost_codebook(4);
    (compact_codes, membership, codebook)
}

#[test]
fn wavefront_repetition_threads_and_cross_thread_resume_are_identical() {
    let (compact_codes, membership, codebook) = wave_fixture();
    let profile = SemanticProfileV3::repo(GraphBuilderKindV3::RepoDeterministicWavefront, 4);
    let run = |threads| {
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| {
                build_qemd_graph_v3(&compact_codes, &membership, &codebook, &profile, params(4))
                    .unwrap()
            })
    };
    let one_a = run(1);
    let one_b = run(1);
    let sixteen_a = run(16);
    let sixteen_b = run(16);
    assert_eq!(one_a, one_b);
    assert_eq!(one_a, sixteen_a);
    assert_eq!(sixteen_a, sixteen_b);

    let partial = ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(|| {
            build_qemd_graph_v3_with_control(
                &compact_codes,
                &membership,
                &codebook,
                &profile,
                params(4),
                None,
                Some(1),
                |_| Ok(()),
                |_| Ok(()),
                || false,
            )
            .unwrap()
        });
    assert_eq!(partial.state.next_cluster, 1);
    let resumed = ThreadPoolBuilder::new()
        .num_threads(16)
        .build()
        .unwrap()
        .install(|| {
            build_qemd_graph_v3_with_control(
                &compact_codes,
                &membership,
                &codebook,
                &profile,
                params(4),
                Some(partial.state),
                None,
                |_| Ok(()),
                |_| Ok(()),
                || false,
            )
            .unwrap()
        });
    assert_eq!(one_a, resumed);
}

#[test]
fn wave_size_one_graph_state_matches_sequential_oracle() {
    let (compact_codes, membership, codebook) = wave_fixture();
    let sequential_profile =
        SemanticProfileV3::repo_faithful(GraphBuilderKindV3::RepoSequentialOracle, 1);
    let wavefront_profile =
        SemanticProfileV3::repo_faithful(GraphBuilderKindV3::RepoDeterministicWavefront, 1);

    let sequential = build_qemd_graph_v3(
        &compact_codes,
        &membership,
        &codebook,
        &sequential_profile,
        params(1),
    )
    .unwrap();
    let wavefront = build_qemd_graph_v3(
        &compact_codes,
        &membership,
        &codebook,
        &wavefront_profile,
        params(1),
    )
    .unwrap();

    assert_eq!(wavefront.state, sequential.state);
    assert_eq!(wavefront.repair, sequential.repair);
}

#[test]
fn v3_serialization_is_cross_family_rejected() {
    let index = native_index();
    let bytes = encode_frame_v3(INDEX_MAGIC_V3, &index).unwrap();
    let decoded: SearchIndexV3 = decode_frame_v3(INDEX_MAGIC_V3, &bytes, 1 << 20).unwrap();
    assert_eq!(index, decoded);
    assert!(decode_frame_v3::<SearchIndexV3>(*b"GEMIDXV2", &bytes, 1 << 20).is_err());
}

#[test]
fn superseded_v3_index_and_checkpoint_decode_but_fail_semantic_validation() {
    let mut old_index = native_index();
    old_index.semantic_profile.profile_id = "gem-repo-released-deterministic-v3".into();
    old_index.semantic_profile.graph_semantics_id =
        "repo-owner-m24-recipient-m0-48-directed-stale-reciprocal-repair-v3".into();
    let encoded = encode_frame_v3(INDEX_MAGIC_V3, &old_index).unwrap();
    let decoded: SearchIndexV3 = decode_frame_v3(INDEX_MAGIC_V3, &encoded, 1 << 20).unwrap();
    assert!(decoded.validate().is_err());

    let checkpoint = GraphCheckpointV3 {
        input_digest: [7; 32],
        semantic_profile: old_index.semantic_profile.clone(),
        params: params(1),
        index_builder_commit: "builder".into(),
        builder_binary_sha256: "binary".into(),
        qemd_implementation_id: QEMD_IMPLEMENTATION_ID_V3.into(),
        coarse_count: 1,
        document_count: 2,
        state: GraphBuildStateV3::empty(2),
    };
    let encoded = encode_frame_v3(GRAPH_CHECKPOINT_MAGIC_V3, &checkpoint).unwrap();
    let decoded: GraphCheckpointV3 =
        decode_frame_v3(GRAPH_CHECKPOINT_MAGIC_V3, &encoded, 1 << 20).unwrap();
    assert!(
        decoded
            .validate(
                [7; 32],
                &decoded.semantic_profile,
                params(1),
                "builder",
                "binary",
                1,
                2,
            )
            .is_err()
    );
}
