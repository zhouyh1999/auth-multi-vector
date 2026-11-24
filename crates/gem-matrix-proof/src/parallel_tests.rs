use super::*;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn parallel_freivalds_checks_every_query_row_in_both_domains() {
    let rows = 2048;
    let columns = 4;
    let witness: Vec<i32> = (0..rows * columns).map(|i| (i % 19) as i32 - 9).collect();
    let query: Vec<i32> = (0..8 * columns).map(|i| (i % 7) as i32 - 3).collect();
    let challenges: Vec<_> = (0..rows).map(|i| Scalar::from(i as u64 + 1)).collect();
    let projection = (0..columns)
        .map(|k| {
            (0..rows).fold(Scalar::ZERO, |sum, j| {
                sum + scalar_i32_v1(witness[j * columns + k]) * challenges[j]
            })
        })
        .collect();
    let verified = VerifiedProjectionV1 {
        rows: challenges,
        projection,
    };
    let table: Vec<i64> = query
        .chunks_exact(columns)
        .flat_map(|q| {
            witness.chunks_exact(columns).map(move |a| {
                q.iter()
                    .zip(a)
                    .map(|(&x, &y)| i64::from(x) * i64::from(y))
                    .sum()
            })
        })
        .collect();
    for workers in [1, 8, 24] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap();
        pool.install(|| {
            verify_freivalds_v1(&query, &table, columns, &verified).unwrap();
            let fields: Vec<_> = table.iter().copied().map(scalar_i64_v1).collect();
            verify_aggregated_freivalds_v1(&query, &fields, columns, &verified).unwrap();
            // Independently corrupt the first and last entry of every row.
            for offset in (0..8).flat_map(|j| [j * rows, (j + 1) * rows - 1]) {
                let mut bad = table.clone();
                bad[offset] += 1;
                assert!(verify_freivalds_v1(&query, &bad, columns, &verified).is_err());
                let mut bad = fields.clone();
                bad[offset] += Scalar::ONE;
                assert!(verify_aggregated_freivalds_v1(&query, &bad, columns, &verified).is_err());
            }
        });
    }
}

#[test]
fn g_only_generators_match_original_chain_and_shared_inputs() {
    for n in [1, 3, 513, 23040, 65536] {
        let original = BulletproofGens::new(n, 1);
        let expected: Vec<_> = original.share(0).G(n).copied().collect();
        assert_eq!(spring_generators(n), expected);
    }
    let g = generators_v1(7).unwrap();
    let ped = PedersenGens::default();
    let template = SpringLinearPublicInputs::new_with_shared_generators(
        vec![Scalar::ZERO; 3],
        Arc::clone(&g),
        &ped.B,
        &ped.B_blinding,
    )
    .unwrap();
    assert!(
        SpringLinearPublicInputs::new_with_shared_generators(
            vec![Scalar::ZERO; 8],
            g,
            &ped.B,
            &ped.B_blinding
        )
        .is_err()
    );
    let coefficients = vec![Scalar::ONE; 3];
    assert_eq!(
        template
            .with_owned_coefficients(coefficients)
            .unwrap()
            .len(),
        3
    );
}

#[test]
#[ignore = "real MSM dimensions: run explicitly with --release --ignored"]
fn seeded_serial_and_parallel_arguments_are_identical() {
    let serial = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let parallel = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .unwrap();
    let sixteen = rayon::ThreadPoolBuilder::new()
        .num_threads(16)
        .build()
        .unwrap();
    let thirty_two = rayon::ThreadPoolBuilder::new()
        .num_threads(32)
        .build()
        .unwrap();
    // Arbitrary-length document matrix and the first prover MSM parallel threshold.
    for (rows, columns) in [(180, 128), (512, 128), (8192, 128)] {
        let a: Vec<_> = (0..rows * columns)
            .map(|i| scalar_i32_v1((i % 101) as i32 - 50))
            .collect();
        let ctx = ProjectionContextV1 {
            binding: [23; 32],
            stage: ProjectionStageV1::Fine,
            rows,
            columns,
            commitment: commit_scalars_v1(&a).unwrap(),
        };
        let prepared = parallel
            .install(|| PreparedProjectionWitnessV1::new(a.clone()))
            .unwrap();
        for profile in [FIXED_PROFILE_ID_V1, gem_core::COMPACT_PROFILE_ID_V1] {
            let make = || {
                prove_projection_with_profile_v1(
                    profile,
                    &ctx,
                    &a,
                    &mut StdRng::seed_from_u64(20261008),
                )
                .unwrap()
                .0
            };
            let one = serial.install(make);
            let eight = parallel.install(make);
            let sixteen_proof = sixteen.install(make);
            let thirty_two_proof = thirty_two.install(make);
            assert_eq!(one, eight, "thread-dependent proof for {rows}x{columns}");
            for pool in [&serial, &parallel, &sixteen, &thirty_two] {
                let reused = pool
                    .install(|| {
                        prove_projection_with_prepared_witness_v1(
                            profile,
                            &ctx,
                            &prepared,
                            &mut StdRng::seed_from_u64(20261008),
                        )
                    })
                    .unwrap()
                    .0;
                assert_eq!(
                    one, reused,
                    "prepared witness changed {profile} {rows}x{columns}"
                );
            }
            assert_eq!(
                one, sixteen_proof,
                "sixteen-thread proof for {rows}x{columns}"
            );
            assert_eq!(
                one, thirty_two_proof,
                "thirty-two-thread proof for {rows}x{columns}"
            );
            serial
                .install(|| verify_projection_with_profile_v1(profile, &ctx, &eight))
                .unwrap();
            parallel
                .install(|| verify_projection_with_profile_v1(profile, &ctx, &one))
                .unwrap();
            sixteen
                .install(|| verify_projection_with_profile_v1(profile, &ctx, &eight))
                .unwrap();
            thirty_two
                .install(|| verify_projection_with_profile_v1(profile, &ctx, &one))
                .unwrap();
            let mut wrong = eight.clone();
            wrong.projection[0] = Scalar::ONE.to_bytes();
            assert!(
                parallel
                    .install(|| verify_projection_with_profile_v1(profile, &ctx, &wrong))
                    .is_err()
            );
        }
    }
}

#[test]
fn only_pinned_reference_and_execution_source_hashes_are_supported() {
    assert!(supported_spring_source_hash_v1(SPRING_SOURCE_HASH_V1));
    assert!(supported_spring_source_hash_v1(
        SPRING_PARALLEL_V1_SOURCE_HASH
    ));
    assert!(supported_spring_source_hash_v1(
        SPRING_PARALLEL_V2_SOURCE_HASH
    ));
    assert!(supported_spring_source_hash_v1(
        SPRING_PARALLEL_V3_SOURCE_HASH
    ));
    assert!(supported_spring_source_hash_v1(
        SPRING_IMPLEMENTATION_HASH_V1
    ));
    assert!(supported_spring_source_hash_v1(
        SPRING_PARALLEL_V4_SOURCE_HASH
    ));
    assert!(supported_spring_source_hash_v1(
        SPRING_PARALLEL_V5_SOURCE_HASH
    ));
    assert!(!supported_spring_source_hash_v1(&"0".repeat(64)));
}

#[test]
fn prepared_witness_binds_dimension_commitment_and_queries() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build()
        .unwrap();
    pool.install(|| {
        for rows in [1, 3, 8, 16] {
            let a: Vec<_> = (0..rows * 4).map(|i| scalar_i32_v1(i as i32 - 9)).collect();
            let prepared = PreparedProjectionWitnessV1::new(a.clone()).unwrap();
            for query in [23, 24] {
                let ctx = ProjectionContextV1 {
                    binding: [query; 32],
                    stage: ProjectionStageV1::Fine,
                    rows,
                    columns: 4,
                    commitment: commit_scalars_v1(&a).unwrap(),
                };
                let direct = prove_projection_with_profile_v1(
                    gem_core::COMPACT_PROFILE_ID_V1,
                    &ctx,
                    &a,
                    &mut StdRng::seed_from_u64(7),
                )
                .unwrap()
                .0;
                let reused = prove_projection_with_prepared_witness_v1(
                    gem_core::COMPACT_PROFILE_ID_V1,
                    &ctx,
                    &prepared,
                    &mut StdRng::seed_from_u64(7),
                )
                .unwrap()
                .0;
                assert_eq!(direct, reused);
                verify_projection_with_profile_v1(gem_core::COMPACT_PROFILE_ID_V1, &ctx, &reused)
                    .unwrap();
                let wrong = ProjectionContextV1 {
                    commitment: [0; 32],
                    ..ctx.clone()
                };
                assert!(
                    prove_projection_with_prepared_witness_v1(
                        gem_core::COMPACT_PROFILE_ID_V1,
                        &wrong,
                        &prepared,
                        &mut StdRng::seed_from_u64(7)
                    )
                    .is_err()
                );
                let wrong = ProjectionContextV1 { columns: 5, ..ctx };
                assert!(
                    prove_projection_with_prepared_witness_v1(
                        gem_core::COMPACT_PROFILE_ID_V1,
                        &wrong,
                        &prepared,
                        &mut StdRng::seed_from_u64(7)
                    )
                    .is_err()
                );
            }
        }
    });
}
