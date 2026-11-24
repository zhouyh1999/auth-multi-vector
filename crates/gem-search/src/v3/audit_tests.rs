use super::*;
use crate::qemd::QemdCodebookV3;
use gem_core::{GraphBuilderKindV3, SemanticProfileV3};

#[test]
fn index_validation_rejects_malformed_components_and_fixed_entries() {
    use gem_core::SearchDocumentV3;
    let index = SearchIndexV3 {
        semantic_profile: SemanticProfileV3::repo_faithful(
            GraphBuilderKindV3::RepoDeterministicWavefront,
            1,
        ),
        graph_params: GraphBuildParamsV3 {
            m: 24,
            m0: 48,
            ef_construction: 80,
            qemd_max_iterations: 1000,
            wave_size: 1,
        },
        dimension: 2,
        max_doc_tokens: 2,
        fine_centroids: vec![1., 0., 0., 1.],
        coarse_centroids: vec![1., 0.],
        fine_to_coarse: vec![0, 0],
        cluster_entries: vec![Some(51)],
        documents: (0..52)
            .map(|id| SearchDocumentV3 {
                doc_id: id,
                token_count: 2,
                compact_codes: vec![0, 1],
                cluster_ids: vec![0],
                adjacency: vec![],
            })
            .collect(),
    };
    assert!(index.validate_policy().is_ok());
    macro_rules! reject {
        ($change:expr) => {{
            let mut changed = index.clone();
            $change(&mut changed);
            assert!(changed.validate_policy().is_err());
        }};
    }
    reject!(|i: &mut SearchIndexV3| i.dimension = 0);
    reject!(|i: &mut SearchIndexV3| i.max_doc_tokens = 0);
    reject!(|i: &mut SearchIndexV3| i.fine_centroids[0] = f32::NAN);
    reject!(|i: &mut SearchIndexV3| i.coarse_centroids[0] = f32::INFINITY);
    reject!(|i: &mut SearchIndexV3| i.fine_centroids.pop());
    reject!(|i: &mut SearchIndexV3| i.fine_to_coarse[0] = 1);
    reject!(|i: &mut SearchIndexV3| i.documents[0].doc_id = 1);
    reject!(|i: &mut SearchIndexV3| i.documents[0].token_count = 0);
    reject!(|i: &mut SearchIndexV3| i.documents[0].compact_codes[0] = 2);
    reject!(|i: &mut SearchIndexV3| i.documents[0].compact_codes.pop());
    reject!(|i: &mut SearchIndexV3| i.documents[0].cluster_ids.clear());
    reject!(|i: &mut SearchIndexV3| i.documents[0].cluster_ids = vec![0, 0]);
    reject!(|i: &mut SearchIndexV3| i.documents[0].cluster_ids = vec![1]);
    reject!(|i: &mut SearchIndexV3| i.documents[0].adjacency = vec![0]);
    reject!(|i: &mut SearchIndexV3| i.documents[0].adjacency = vec![52]);
    reject!(|i: &mut SearchIndexV3| i.documents[0].adjacency = vec![2, 1]);
    reject!(|i: &mut SearchIndexV3| i.documents[0].adjacency = vec![1, 1]);
    reject!(|i: &mut SearchIndexV3| i.documents[0].adjacency = (1..50).collect());
    reject!(|i: &mut SearchIndexV3| i.cluster_entries[0] = Some(0));
    reject!(|i: &mut SearchIndexV3| i.cluster_entries[0] = None);
    reject!(|i: &mut SearchIndexV3| i.graph_params.m = 25);
    reject!(|i: &mut SearchIndexV3| i.semantic_profile.wave_size = 2);
}

#[test]
fn resume_rejects_out_of_range_cluster_and_wrong_inserted_prefix() {
    let codes = vec![vec![0], vec![1], vec![0]];
    let membership = build_repo_memberships_v3(&codes, vec![0, 1], 2).unwrap();
    let book = QemdCodebookV3::from_centroids(&[1., 0., 0., 1.], 2).unwrap();
    let profile =
        SemanticProfileV3::repo_faithful(GraphBuilderKindV3::RepoDeterministicWavefront, 1);
    let params = GraphBuildParamsV3 {
        m: 24,
        m0: 48,
        ef_construction: 80,
        qemd_max_iterations: 1000,
        wave_size: 1,
    };
    for (cluster, inserted) in [(3, vec![false; 3]), (1, vec![false; 3]), (0, vec![true; 3])] {
        let mut state = GraphBuildStateV3::empty(3);
        state.next_cluster = cluster;
        state.inserted = inserted;
        assert!(
            build_qemd_graph_v3_with_control(
                &codes,
                &membership,
                &book,
                &profile,
                params,
                Some(state),
                None,
                |_| Ok(()),
                |_| Ok(()),
                || false
            )
            .is_err(),
            "accepted malformed resume at cluster {cluster}"
        );
    }
}
