//! Owner-bound tables, independent client replay, full candidate matrices and exact disclosure.
use super::numeric::*;
use super::{
    snapshot::{hash, validate_scheme_structure},
    *,
};
use curve25519_dalek::scalar::Scalar;
use gem_auth_v3::{
    ComponentOpening, MetadataV3, RawOpeningV3, fp32_to_canonical_fp16_v3,
    verify_document_multiproof_v3,
};
use gem_core::{GemError, Hash, Result};
use gem_matrix_proof::{
    PreparedProjectionWitnessV1, ProjectionContextV1, ProjectionStageV1, ProjectionTimingsV1,
    aggregate_commitments_v1, canonical_point_v1, prove_projection_with_prepared_witness_v1,
    verify_aggregated_freivalds_v1, verify_freivalds_v1,
};
use gem_search::SearchAccessV3;
use rand::rngs::OsRng;
use rayon::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

pub fn validate_scheme_request_v3(
    t: &TrustedSchemeSnapshotV3,
    r: &SchemeRequestV3,
) -> Result<FixedQueryV3> {
    validate_trusted_scheme_snapshot_v3(t)?;
    let m = &t.signed.manifest;
    let base = m.source();
    r.query.validate(base.dimension)?;
    if r.manifest_digest != t.expected_manifest_digest
        || r.query.params != base.params
        || r.query.token_count != base.query_tokens
    {
        return Err(GemError::InvalidManifest);
    }
    FixedQueryV3::new(r.query.clone())
}
fn raw_backend(b: SchemeBackendV3) -> bool {
    b != SchemeBackendV3::MatrixScheme
}
#[derive(Clone, Debug)]
pub struct AuthenticatedSchemePublicV3 {
    entries: Vec<Option<u32>>,
    fine: Vec<Coordinate>,
    coarse: Vec<Coordinate>,
}
impl AuthenticatedSchemePublicV3 {
    pub fn entries(&self) -> &[Option<u32>] {
        &self.entries
    }
}
pub fn authenticate_scheme_public_data_v3(
    t: &TrustedSchemeSnapshotV3,
    backend: SchemeBackendV3,
    p: &SchemePublicPayloadV3,
) -> Result<AuthenticatedSchemePublicV3> {
    validate_trusted_scheme_snapshot_v3(t)?;
    let m = &t.signed.manifest;
    let base = m.source();
    if p.entries.len() != base.coarse_count as usize
        || p.entries
            .iter()
            .flatten()
            .any(|&id| id >= base.document_count)
        || scheme_entries_digest_v3(&p.entries)? != m.entries_digest
    {
        return Err(GemError::HashMismatch);
    }
    let (fine, coarse) = if raw_backend(backend) {
        let public = p.raw_centroids.as_ref().ok_or(GemError::InvalidManifest)?;
        if public.entries != p.entries
            || public.fine_bits.len() != base.fine_count as usize * usize::from(base.dimension)
            || public.coarse_bits.len() != base.coarse_count as usize * usize::from(base.dimension)
            || hash(b"gem.auth.v3.fine.1", &public.fine_bits)? != base.fine_digest
            || hash(b"gem.auth.v3.coarse.1", &public.coarse_bits)? != base.coarse_digest
            || hash(b"gem.auth.v3.entry.1", &public.entries)? != base.entry_digest
        {
            return Err(GemError::HashMismatch);
        }
        (
            fixed_fp16_v1(&public.fine_bits)?,
            fixed_coordinates_v1(
                &public
                    .coarse_bits
                    .iter()
                    .map(|&b| f32::from_bits(b))
                    .collect::<Vec<_>>(),
            )?,
        )
    } else {
        if p.raw_centroids.is_some() {
            return Err(GemError::InvalidManifest);
        }
        (vec![], vec![])
    };
    Ok(AuthenticatedSchemePublicV3 {
        entries: p.entries.clone(),
        fine,
        coarse,
    })
}
pub fn scheme_public_payload_v3(
    s: &PreparedSchemeSnapshotV3,
    backend: SchemeBackendV3,
) -> SchemePublicPayloadV3 {
    SchemePublicPayloadV3 {
        entries: s.public.entries.clone(),
        raw_centroids: raw_backend(backend).then(|| s.public.clone()),
    }
}
/// Only the authenticated verifier path constructs this capability.
pub struct AuthenticatedMetricTablesFixedV3 {
    tables: FixedMetricTablesV3,
}
impl AuthenticatedMetricTablesFixedV3 {
    pub fn selected_clusters(&self) -> &[u32] {
        self.tables.selected_clusters()
    }
}
#[derive(Debug)]
pub struct SchemeServerSnapshotV3 {
    prepared: PreparedSchemeSnapshotV3,
    centroid_proofs: std::sync::Mutex<Option<PreparedCentroidProofs>>,
}
#[derive(Clone, Debug)]
struct PreparedCentroidProofs {
    coarse: std::sync::Arc<PreparedProjectionWitnessV1>,
    fine: std::sync::Arc<PreparedProjectionWitnessV1>,
}
impl SchemeServerSnapshotV3 {
    pub fn into_prepared(self) -> PreparedSchemeSnapshotV3 {
        self.prepared
    }
    fn centroid_proofs(&self) -> Result<PreparedCentroidProofs> {
        let mut cache = self
            .centroid_proofs
            .lock()
            .map_err(|_| GemError::InvalidManifest)?;
        if let Some(value) = cache.as_ref() {
            return Ok(value.clone());
        }
        let prepare = |coordinates: &[Coordinate]| {
            PreparedProjectionWitnessV1::new(
                coordinates
                    .par_iter()
                    .copied()
                    .map(scalar_coordinate)
                    .collect(),
            )
            .map(std::sync::Arc::new)
        };
        let (coarse, fine) =
            rayon::join(|| prepare(&self.coarse_fixed), || prepare(&self.fine_fixed));
        let value = PreparedCentroidProofs {
            coarse: coarse?,
            fine: fine?,
        };
        *cache = Some(value.clone());
        Ok(value)
    }
}
/// Server-only local initialization. It does not change the persisted snapshot or VO.
pub fn prepare_scheme_server_proofs_v3(s: &SchemeServerSnapshotV3) -> Result<f64> {
    let start = Instant::now();
    s.centroid_proofs()?;
    Ok(start.elapsed().as_secs_f64() * 1000.)
}
impl std::ops::Deref for SchemeServerSnapshotV3 {
    type Target = PreparedSchemeSnapshotV3;
    fn deref(&self) -> &Self::Target {
        &self.prepared
    }
}
pub fn initialize_scheme_server_snapshot_v3(
    s: PreparedSchemeSnapshotV3,
) -> Result<SchemeServerSnapshotV3> {
    validate_scheme_structure(&s)?;
    Ok(SchemeServerSnapshotV3 {
        prepared: s,
        centroid_proofs: std::sync::Mutex::new(None),
    })
}
fn prove_metric_argument(
    server: &SchemeServerSnapshotV3,
    request: &SchemeRequestV3,
    stage: ProjectionStageV1,
    table: &[Similarity],
    prepared: Option<&PreparedCentroidProofs>,
) -> Result<(gem_matrix_proof::ProjectionArgumentV1, SchemeTimingsV3)> {
    let (coordinates, cached, name) = match stage {
        ProjectionStageV1::Coarse => (&server.coarse_fixed, prepared.map(|p| &p.coarse), "coarse"),
        ProjectionStageV1::Fine => (&server.fine_fixed, prepared.map(|p| &p.fine), "fine"),
        _ => return Err(GemError::InvalidManifest),
    };
    let mut timings = SchemeTimingsV3::default();
    let context = metric_context(&server.trusted, request, stage, table)?;
    let (proof, pt) = if let Some(cached) = cached {
        prove_projection_with_prepared_witness_v1(PROFILE_ID, &context, cached, &mut OsRng)?
    } else {
        let start = Instant::now();
        let witness: Vec<_> = coordinates
            .par_iter()
            .copied()
            .map(scalar_coordinate)
            .collect();
        timings.record(&format!("{name}_witness"), start);
        prove_projection_v1(&context, &witness, &mut OsRng)?
    };
    add_projection_timings(&mut timings, name, pt);
    Ok((proof, timings))
}
fn metric_context(
    t: &TrustedSchemeSnapshotV3,
    r: &SchemeRequestV3,
    stage: ProjectionStageV1,
    table: &[Similarity],
) -> Result<ProjectionContextV1> {
    let m = &t.signed.manifest;
    let (rows, commitment) = match stage {
        ProjectionStageV1::Coarse => (m.source().coarse_count as usize, m.coarse_commitment),
        ProjectionStageV1::Fine => (m.source().fine_count as usize, m.fine_commitment),
        _ => return Err(GemError::InvalidManifest),
    };
    let binding = hash(
        METRIC_DOMAIN,
        &(
            t.expected_manifest_digest,
            scheme_request_digest_v3(r)?,
            stage,
            rows,
            m.source().dimension,
            &m.numeric_profile,
            table,
            commitment,
        ),
    )?;
    Ok(ProjectionContextV1 {
        binding,
        stage,
        rows,
        columns: usize::from(m.source().dimension),
        commitment,
    })
}
fn aggregation_binding(
    t: &TrustedSchemeSnapshotV3,
    r: &SchemeRequestV3,
    boundaries: &[TokenBoundaryV3],
    y: &[Similarity],
    commitments: &[[u8; 32]],
) -> Result<Hash> {
    hash(
        RERANKING_DOMAIN,
        &(
            t.expected_manifest_digest,
            scheme_request_digest_v3(r)?,
            ProjectionStageV1::Reranking,
            &t.signed.manifest.numeric_profile,
            t.signed.manifest.document_rows,
            t.signed.manifest.source().dimension,
            boundaries,
            y,
            commitments,
        ),
    )
}
fn doc_context(
    t: &TrustedSchemeSnapshotV3,
    binding: Hash,
    commitment: [u8; 32],
) -> ProjectionContextV1 {
    ProjectionContextV1 {
        binding,
        stage: ProjectionStageV1::Reranking,
        rows: usize::from(t.signed.manifest.document_rows),
        columns: usize::from(t.signed.manifest.source().dimension),
        commitment,
    }
}
fn add_projection_timings(t: &mut SchemeTimingsV3, name: &str, pt: ProjectionTimingsV1) {
    t.phases
        .insert(format!("{name}_projection"), pt.projection_ms);
    t.phases
        .insert(format!("{name}_public_inputs"), pt.public_inputs_ms);
    t.phases.insert(format!("{name}_ipa"), pt.ipa_ms);
}
fn pack_y(matrices: &[(u32, usize, Vec<Similarity>)], m: usize) -> Vec<Similarity> {
    let mut y = Vec::new();
    for j in 0..m {
        for (_, n, a) in matrices {
            y.extend_from_slice(&a[j * n..(j + 1) * n]);
        }
    }
    y
}
fn unpack_y(
    boundaries: &[TokenBoundaryV3],
    y: &[Similarity],
    m: usize,
) -> Result<Vec<(u32, usize, Vec<Similarity>)>> {
    let total = boundaries.iter().try_fold(0usize, |sum, b| {
        sum.checked_add(usize::from(b.token_count))
            .ok_or(GemError::NumericOverflow)
    })?;
    if boundaries.iter().any(|b| b.token_count == 0)
        || y.len() != total.checked_mul(m).ok_or(GemError::NumericOverflow)?
    {
        return Err(GemError::InvalidTokenCount);
    }
    let mut out = vec![];
    let mut offset = 0;
    for b in boundaries {
        let n = usize::from(b.token_count);
        let mut a = Vec::with_capacity(m * n);
        for j in 0..m {
            a.extend_from_slice(&y[j * total + offset..j * total + offset + n]);
        }
        out.push((b.doc_id, n, a));
        offset += n;
    }
    Ok(out)
}
fn aggregated_y(
    matrices: &[(u32, usize, Vec<Similarity>)],
    weights: &[Scalar],
    m: usize,
    rows: usize,
) -> Result<Vec<Scalar>> {
    if matrices.len() != weights.len() {
        return Err(GemError::InvalidManifest);
    }
    let length = m.checked_mul(rows).ok_or(GemError::NumericOverflow)?;
    for (_, n, y) in matrices {
        if *n > rows || y.len() != m.checked_mul(*n).ok_or(GemError::NumericOverflow)? {
            return Err(GemError::InvalidTokenCount);
        }
    }
    let mut out = vec![Scalar::ZERO; length];
    if rows != 0
        && m > 1
        && rayon::current_num_threads() > 1
        && length.saturating_mul(matrices.len()) >= 32_768
    {
        out.par_chunks_mut(rows).enumerate().for_each(|(j, row)| {
            for ((_, n, y), alpha) in matrices.iter().zip(weights) {
                for (sum, &value) in row.iter_mut().zip(&y[j * n..(j + 1) * n]) {
                    *sum += alpha * scalar_similarity(value);
                }
            }
        });
        return Ok(out);
    }
    for ((_, n, y), alpha) in matrices.iter().zip(weights) {
        for j in 0..m {
            for token in 0..*n {
                out[j * rows + token] += alpha * scalar_similarity(y[j * n + token]);
            }
        }
    }
    Ok(out)
}

// Two byte windows per random document weight. Rebuild for every query: weights
// are transcript challenges, so a previous query's tables cannot be reused.
const I16_WEIGHT_TABLE_SIZE: usize = 512;
const I16_WEIGHT_BATCH: usize = 1024;
const I16_WEIGHT_MIN_COORDINATES: usize = 1024;

fn i16_weight_tables(weights: &[Scalar]) -> Vec<Scalar> {
    // Each batch uses at most 1024 * 512 * 32 = 16 MiB of temporary tables.
    let mut tables = vec![Scalar::ZERO; weights.len() * I16_WEIGHT_TABLE_SIZE];
    tables
        .par_chunks_mut(I16_WEIGHT_TABLE_SIZE)
        .zip(weights.par_iter())
        .for_each(|(table, alpha)| {
            let high_step = alpha * Scalar::from(256u64);
            for byte in 1..256 {
                table[byte] = table[byte - 1] + alpha;
                table[256 + byte] = table[255 + byte] + high_step;
            }
        });
    tables
}

fn i16_weight_product(table: &[Scalar], value: i16) -> Scalar {
    // unsigned_abs handles i16::MIN without signed overflow.
    let magnitude = usize::from(value.unsigned_abs());
    let product = table[magnitude & 255] + table[256 + (magnitude >> 8)];
    if value < 0 { -product } else { product }
}

fn aggregated_document_witness(
    documents: &[&[Coordinate]],
    weights: &[Scalar],
    dimension: usize,
) -> Result<Vec<Scalar>> {
    if documents.len() != weights.len() || documents.iter().any(|d| d.len() > dimension) {
        return Err(GemError::InvalidTokenCount);
    }
    let mut out = vec![Scalar::ZERO; dimension];
    if IS_COMPACT {
        for (batch, alphas) in documents
            .chunks(I16_WEIGHT_BATCH)
            .zip(weights.chunks(I16_WEIGHT_BATCH))
        {
            let coordinates = batch.iter().fold(0usize, |n, d| n.saturating_add(d.len()));
            // Small/empty batches keep direct multiplication, avoiding setup
            // when the lookup table cannot amortize its construction.
            let tables = (coordinates >= batch.len() * I16_WEIGHT_MIN_COORDINATES)
                .then(|| i16_weight_tables(alphas));
            out.par_chunks_mut(128)
                .enumerate()
                .for_each(|(tile, sums)| {
                    let start = tile * 128;
                    for (doc, (document, alpha)) in batch.iter().zip(alphas).enumerate() {
                        if let Some(values) = document.get(start..) {
                            if let Some(tables) = &tables {
                                let table = &tables[doc * I16_WEIGHT_TABLE_SIZE
                                    ..(doc + 1) * I16_WEIGHT_TABLE_SIZE];
                                for (sum, &value) in sums.iter_mut().zip(values) {
                                    // This branch is instantiated only for the
                                    // compact i16 profile; wide i32 stays below.
                                    *sum += i16_weight_product(table, i64::from(value) as i16);
                                }
                            } else {
                                for (sum, &value) in sums.iter_mut().zip(values) {
                                    *sum += alpha * scalar_coordinate(value);
                                }
                            }
                        }
                    }
                });
        }
        return Ok(out);
    }
    // One token row per tile, contiguous input reads, no zero-padding products.
    out.par_chunks_mut(128)
        .enumerate()
        .for_each(|(tile, sums)| {
            let start = tile * 128;
            for (document, alpha) in documents.iter().zip(weights) {
                if let Some(values) = document.get(start..) {
                    for (sum, &value) in sums.iter_mut().zip(values) {
                        *sum += alpha * scalar_coordinate(value);
                    }
                }
            }
        });
    Ok(out)
}
// Similarities already have a fixed-width signed integer encoding. Validate only
// the matrix shape here; correctness is checked by the matrix proof and Freivalds.
fn validate_table_shape(query: &FixedQueryV3, table: &[Similarity], rows: usize) -> Result<()> {
    let expected = rows
        .checked_mul(usize::from(query.source.token_count))
        .ok_or(GemError::NumericOverflow)?;
    if table.len() != expected {
        return Err(GemError::InvalidTokenCount);
    }
    Ok(())
}
pub fn execute_scheme_retrieval_v3(
    s: &SchemeServerSnapshotV3,
    r: &SchemeRequestV3,
) -> Result<SchemeRetrievalVoV3> {
    Ok(execute_scheme_retrieval_measured_v3(s, r)?.0)
}
pub fn execute_scheme_retrieval_measured_v3(
    s: &SchemeServerSnapshotV3,
    r: &SchemeRequestV3,
) -> Result<(SchemeRetrievalVoV3, FixedExecutionV3, SchemeTimingsV3)> {
    let total = Instant::now();
    let mut timings = SchemeTimingsV3::default();
    let q = validate_scheme_request_v3(&s.trusted, r)?;
    let m = &s.trusted.signed.manifest;
    let now = Instant::now();
    let coarse = fixed_similarity_table_v3(&q, &s.coarse_fixed)?;
    let clusters = select_fixed_clusters_v3(&coarse, &q, s.public.entries.len())?;
    let entries = clusters
        .iter()
        .any(|&c| s.public.entries[c as usize].is_some());
    let fine = if entries {
        fixed_similarity_table_v3(&q, &s.fine_fixed)?
    } else {
        vec![]
    };
    timings.record("tables", now);
    let now = Instant::now();
    let tables = FixedMetricTablesV3::from_tables(
        &coarse,
        fine.clone(),
        m.source().fine_count as usize,
        &q,
        &s.public.entries,
    )?;
    let execution = replay_fixed_search_v3(&s.index, &s.public.entries, &q, &tables)?;
    timings.record("search", now);
    let now = Instant::now();
    let matrices = execution
        .component_usage
        .raw
        .par_iter()
        .map(|&id| {
            Ok((
                id,
                usize::from(s.metadata[id as usize].token_count),
                fixed_similarity_table_serial_v3(&q, &s.fixed_documents[id as usize])?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    timings.record("complete_y", now);
    let now = Instant::now();
    let results = rerank_fixed_matrices_v3(&q, &matrices)?;
    timings.record("maxsim", now);
    let now = Instant::now();
    let prepared = if r.backend == SchemeBackendV3::MatrixScheme {
        s.centroid_proofs
            .lock()
            .map_err(|_| GemError::InvalidManifest)?
            .clone()
    } else {
        None
    };
    if prepared.is_some() {
        timings.record("centroid_cache_lookup", now);
    }
    let parallel_start = Instant::now();
    let (metric_result, reranking_result) = rayon::join(
        || -> Result<_> {
            let mut timings = SchemeTimingsV3::default();
            let metrics = if r.backend == SchemeBackendV3::MatrixScheme {
                let (coarse_result, fine_result) = rayon::join(
                    || {
                        prove_metric_argument(
                            s,
                            r,
                            ProjectionStageV1::Coarse,
                            &coarse,
                            prepared.as_ref(),
                        )
                    },
                    || -> Result<_> {
                        if entries {
                            Ok(Some(prove_metric_argument(
                                s,
                                r,
                                ProjectionStageV1::Fine,
                                &fine,
                                prepared.as_ref(),
                            )?))
                        } else {
                            Ok(None)
                        }
                    },
                );
                let (coarse_argument, ct) = coarse_result?;
                timings.phases.extend(ct.phases);
                let fine_argument = if let Some((p, ft)) = fine_result? {
                    timings.phases.extend(ft.phases);
                    Some(p)
                } else {
                    None
                };
                Some(MetricPayloadFixedV3 {
                    coarse,
                    fine,
                    coarse_argument,
                    fine_argument,
                })
            } else {
                None
            };
            Ok((metrics, timings))
        },
        || -> Result<_> {
            let mut timings = SchemeTimingsV3::default();
            let reranking = if r.backend == SchemeBackendV3::MatrixScheme && !matrices.is_empty() {
                let now = Instant::now();
                let boundaries: Vec<_> = matrices
                    .iter()
                    .map(|(id, n, _)| TokenBoundaryV3 {
                        doc_id: *id,
                        token_count: *n as u16,
                    })
                    .collect();
                let y = pack_y(&matrices, usize::from(q.source.token_count));
                let commitments = matrices
                    .iter()
                    .map(|(id, _, _)| s.commitments[*id as usize])
                    .collect::<Vec<_>>();
                let binding = aggregation_binding(&s.trusted, r, &boundaries, &y, &commitments)?;
                let weights = document_weights_v1(binding, matrices.len())?;
                let commitment = aggregate_commitments_v1(&commitments, &weights)?;
                let n = usize::from(m.document_rows) * usize::from(m.source().dimension);
                // Shared positional basis: document padding is exactly zero, never a MaxSim candidate.
                let documents: Vec<_> = matrices
                    .iter()
                    .map(|(id, _, _)| s.fixed_documents[*id as usize].as_slice())
                    .collect();
                let a = aggregated_document_witness(&documents, &weights, n)?;
                timings.record("aggregate_witness", now);
                let (argument, pt) = prove_projection_v1(
                    &doc_context(&s.trusted, binding, commitment),
                    &a,
                    &mut OsRng,
                )?;
                add_projection_timings(&mut timings, "reranking", pt);
                Some(RerankingPayloadFixedV3 {
                    similarities: y,
                    argument,
                })
            } else {
                None
            };
            Ok((reranking, timings))
        },
    );
    let (metrics, mt) = metric_result?;
    let (reranking, rt) = reranking_result?;
    let work_ms = mt.phases.values().chain(rt.phases.values()).sum::<f64>();
    timings.parallel_overlap_ms +=
        (work_ms - parallel_start.elapsed().as_secs_f64() * 1000.).max(0.);
    timings.phases.extend(mt.phases);
    timings.phases.extend(rt.phases);
    let now = Instant::now();
    let u = &execution.component_usage;
    let documents = u
        .membership
        .iter()
        .map(|&id| {
            let d = &s.index.documents[id as usize];
            let h = if raw_backend(r.backend) {
                s.raw_component_hashes[id as usize]
            } else {
                s.component_hashes[id as usize]
            };
            let vector = if raw_backend(r.backend) {
                DocumentVectorOpeningV3::Raw(if u.raw.contains(&id) {
                    ComponentOpening::Revealed(match r.backend {
                        SchemeBackendV3::FixedRawFp16 => {
                            RawOpeningV3::Fp16(s.raw_bits[id as usize].clone())
                        }
                        SchemeBackendV3::FixedRawFp32 => RawOpeningV3::Fp32(
                            s.raw_bits[id as usize]
                                .iter()
                                .map(|&b| half::f16::from_bits(b).to_f32().to_bits())
                                .collect(),
                        ),
                        _ => unreachable!(),
                    })
                } else {
                    ComponentOpening::Digest(h[4])
                })
            } else {
                DocumentVectorOpeningV3::Commitment(if u.raw.contains(&id) {
                    ComponentOpening::Revealed(DocumentMatrixCommitmentV3::new(
                        s.commitments[id as usize],
                    ))
                } else {
                    ComponentOpening::Digest(h[4])
                })
            };
            SchemeDocumentOpeningV3 {
                metadata: s.metadata[id as usize].clone(),
                membership: ComponentOpening::Revealed(d.cluster_ids.clone()),
                codes: if u.codes.contains(&id) {
                    ComponentOpening::Revealed(d.compact_codes.clone())
                } else {
                    ComponentOpening::Digest(h[2])
                },
                adjacency: if u.adjacency.contains(&id) {
                    ComponentOpening::Revealed(d.adjacency.clone())
                } else {
                    ComponentOpening::Digest(h[3])
                },
                vector,
            }
        })
        .collect();
    let tree = if raw_backend(r.backend) {
        &s.raw_tree
    } else {
        &s.tree
    };
    let proof = tree.prove(&u.membership.iter().copied().collect::<Vec<_>>())?;
    timings.record("openings_multiproof", now);
    let vo = SchemeRetrievalVoV3 {
        backend: r.backend,
        public_mode: r.public_mode,
        public: Some(scheme_public_payload_v3(s, r.backend)),
        documents,
        proof,
        metrics,
        reranking,
        results,
    };
    timings.finish(total);
    Ok((vo, execution, timings))
}
struct SparseAccess<'a> {
    docs: BTreeMap<u32, &'a SchemeDocumentOpeningV3>,
}
impl SparseAccess<'_> {
    fn doc(&self, id: u32) -> Result<&SchemeDocumentOpeningV3> {
        self.docs.get(&id).copied().ok_or(GemError::InvalidManifest)
    }
}
impl SearchAccessV3 for SparseAccess<'_> {
    fn metadata(&self, id: u32) -> Result<u16> {
        Ok(self.doc(id)?.metadata.token_count)
    }
    fn membership(&self, id: u32) -> Result<&[u32]> {
        Ok(self.doc(id)?.membership.revealed()?)
    }
    fn codes(&self, id: u32) -> Result<&[u32]> {
        Ok(self.doc(id)?.codes.revealed()?)
    }
    fn adjacency(&self, id: u32) -> Result<&[u32]> {
        Ok(self.doc(id)?.adjacency.revealed()?)
    }
}
fn open_hash<T: serde::Serialize>(
    backend: SchemeBackendV3,
    meta: &MetadataV3,
    kind: u8,
    o: &ComponentOpening<T>,
) -> Result<Hash> {
    match o {
        ComponentOpening::Digest(h) => Ok(*h),
        ComponentOpening::Revealed(v) => backend_component_hash_v3(backend, meta, kind, v),
    }
}
fn ordered(ids: &[u32], max: u32) -> bool {
    ids.iter().all(|&id| id < max) && !ids.windows(2).any(|w| w[0] >= w[1])
}
fn verify_matrix_metric_tables(
    t: &TrustedSchemeSnapshotV3,
    r: &SchemeRequestV3,
    q: &FixedQueryV3,
    public: &AuthenticatedSchemePublicV3,
    v: &SchemeRetrievalVoV3,
) -> Result<(AuthenticatedMetricTablesFixedV3, SchemeTimingsV3)> {
    let base = t.signed.manifest.source();
    let metric = v.metrics.as_ref().ok_or(GemError::InvalidManifest)?;
    validate_table_shape(q, &metric.coarse, base.coarse_count as usize)?;
    let started = Instant::now();
    // Each statement has its own transcript. Speculative fine verification is
    // usable only after the authenticated coarse table establishes its need.
    let (coarse, fine) = rayon::join(
        || {
            let mut timings = SchemeTimingsV3::default();
            let ctx = metric_context(t, r, ProjectionStageV1::Coarse, &metric.coarse)?;
            let (proof, pt) = verify_projection_v1(&ctx, &metric.coarse_argument)?;
            add_projection_timings(&mut timings, "coarse", pt);
            let now = Instant::now();
            verify_freivalds_v1(
                &q.coordinates,
                &metric.coarse,
                usize::from(base.dimension),
                &proof,
            )?;
            let selected = select_fixed_clusters_v3(&metric.coarse, q, base.coarse_count as usize)?;
            timings.record("coarse_freivalds_selection", now);
            Ok::<_, GemError>((selected, timings))
        },
        || {
            let Some(argument) = metric.fine_argument.as_ref() else {
                return Ok(None);
            };
            validate_table_shape(q, &metric.fine, base.fine_count as usize)?;
            let mut timings = SchemeTimingsV3::default();
            let ctx = metric_context(t, r, ProjectionStageV1::Fine, &metric.fine)?;
            let (proof, pt) = verify_projection_v1(&ctx, argument)?;
            add_projection_timings(&mut timings, "fine", pt);
            let now = Instant::now();
            verify_freivalds_v1(
                &q.coordinates,
                &metric.fine,
                usize::from(base.dimension),
                &proof,
            )?;
            timings.record("fine_freivalds", now);
            Ok::<_, GemError>(Some(timings))
        },
    );
    let (selected, mut timings) = coarse?;
    let fine = fine?;
    let entries = selected
        .iter()
        .any(|&c| public.entries[c as usize].is_some());
    if entries {
        timings
            .phases
            .extend(fine.ok_or(GemError::InvalidManifest)?.phases);
    } else if !metric.fine.is_empty() || fine.is_some() || v.reranking.is_some() {
        return Err(GemError::InvalidManifest);
    }
    timings.parallel_overlap_ms =
        (timings.phases.values().sum::<f64>() - started.elapsed().as_secs_f64() * 1000.).max(0.);
    let tables = AuthenticatedMetricTablesFixedV3 {
        tables: FixedMetricTablesV3::from_tables(
            &metric.coarse,
            metric.fine.clone(),
            base.fine_count as usize,
            q,
            &public.entries,
        )?,
    };
    Ok((tables, timings))
}

type CandidateMatricesV3 = Vec<(u32, usize, Vec<Similarity>)>;

fn verify_disclosed_matrix_reranking(
    t: &TrustedSchemeSnapshotV3,
    r: &SchemeRequestV3,
    q: &FixedQueryV3,
    v: &SchemeRetrievalVoV3,
) -> Result<(CandidateMatricesV3, SchemeTimingsV3)> {
    let m = &t.signed.manifest;
    let base = m.source();
    // Metadata and commitments have already passed the document multiproof.
    // The caller must still match every disclosure to the independent replay
    // before any matrices or results are accepted.
    let disclosed: Vec<_> = v
        .documents
        .iter()
        .filter(|d| d.vector.is_revealed())
        .collect();
    let mut timings = SchemeTimingsV3::default();
    if disclosed.is_empty() {
        if v.reranking.is_some() {
            return Err(GemError::InvalidManifest);
        }
        return Ok((vec![], timings));
    }
    let y = v.reranking.as_ref().ok_or(GemError::InvalidManifest)?;
    let expected: Vec<_> = disclosed
        .iter()
        .map(|d| TokenBoundaryV3 {
            doc_id: d.metadata.doc_id,
            token_count: d.metadata.token_count,
        })
        .collect();
    let token_count = expected.iter().map(|b| usize::from(b.token_count)).sum();
    validate_table_shape(q, &y.similarities, token_count)?;
    let matrices = unpack_y(&expected, &y.similarities, usize::from(base.query_tokens))?;
    let now = Instant::now();
    let commitments = disclosed
        .iter()
        .map(|d| Ok(d.vector.commitment()?.point))
        .collect::<Result<Vec<_>>>()?;
    let binding = aggregation_binding(t, r, &expected, &y.similarities, &commitments)?;
    let weights = document_weights_v1(binding, expected.len())?;
    let commitment = aggregate_commitments_v1(&commitments, &weights)?;
    let aggregate = aggregated_y(
        &matrices,
        &weights,
        usize::from(base.query_tokens),
        usize::from(m.document_rows),
    )?;
    timings.record("document_aggregation", now);
    let (proof, pt) = verify_projection_v1(&doc_context(t, binding, commitment), &y.argument)?;
    add_projection_timings(&mut timings, "reranking", pt);
    let now = Instant::now();
    verify_aggregated_freivalds_v1(
        &q.coordinates,
        &aggregate,
        usize::from(base.dimension),
        &proof,
    )?;
    timings.record("reranking_freivalds", now);
    Ok((matrices, timings))
}

pub fn verify_scheme_retrieval_v3(
    t: &TrustedSchemeSnapshotV3,
    r: &SchemeRequestV3,
    bytes: &[u8],
) -> Result<VerifiedFixedRetrievalV3> {
    let total = Instant::now();
    let mut timings = SchemeTimingsV3::default();
    let now = Instant::now();
    let q = validate_scheme_request_v3(t, r)?;
    let v = decode_scheme_vo_v3(bytes, t)?;
    if v.backend != r.backend || v.public_mode != r.public_mode {
        return Err(GemError::HashMismatch);
    }
    timings.record("decode_signature_request", now);
    let now = Instant::now();
    let public = authenticate_scheme_public_data_v3(
        t,
        r.backend,
        v.public.as_ref().ok_or(GemError::InvalidManifest)?,
    )?;
    timings.record("public_auth", now);
    let now = Instant::now();
    let m = &t.signed.manifest;
    let base = m.source();
    let mut leaves = vec![];
    let mut raws = BTreeMap::new();
    if v.documents
        .windows(2)
        .any(|w| w[0].metadata.doc_id >= w[1].metadata.doc_id)
    {
        return Err(GemError::NonCanonicalOrder);
    }
    for d in &v.documents {
        let meta = &d.metadata;
        let id = meta.doc_id;
        if id >= base.document_count
            || meta.token_count == 0
            || meta.token_count > base.max_doc_tokens
        {
            return Err(GemError::InvalidManifest);
        }
        let membership = d.membership.revealed()?;
        if membership.is_empty()
            || membership.len() > base.coarse_count as usize
            || !ordered(membership, base.coarse_count)
        {
            return Err(GemError::InvalidManifest);
        }
        if let ComponentOpening::Revealed(c) = &d.codes
            && (c.len() != usize::from(meta.token_count) || c.iter().any(|&x| x >= base.fine_count))
        {
            return Err(GemError::InvalidTokenCount);
        }
        if let ComponentOpening::Revealed(a) = &d.adjacency
            && (a.len() > usize::from(base.graph_params.m0)
                || a.iter().any(|&neighbor| neighbor >= base.document_count)
                || !base.semantic_profile.is_published_fixed_graph()
                    && !ordered(a, base.document_count)
                || a.contains(&id))
        {
            return Err(GemError::InvalidManifest);
        }
        if !d.vector.matches_backend(r.backend) {
            return Err(GemError::InvalidManifest);
        }
        let vector_hash = match &d.vector {
            DocumentVectorOpeningV3::Raw(ComponentOpening::Digest(h)) => *h,
            DocumentVectorOpeningV3::Raw(ComponentOpening::Revealed(value)) => {
                let bits = match (r.backend, value) {
                    (SchemeBackendV3::FixedRawFp16, RawOpeningV3::Fp16(b)) => {
                        fixed_fp16_v1(b)?;
                        b.clone()
                    }
                    (SchemeBackendV3::FixedRawFp32, RawOpeningV3::Fp32(b)) => {
                        fp32_to_canonical_fp16_v3(b)?
                    }
                    _ => return Err(GemError::InvalidManifest),
                };
                if bits.len() != usize::from(meta.token_count) * usize::from(base.dimension) {
                    return Err(GemError::InvalidTokenCount);
                }
                let h = backend_component_hash_v3(r.backend, meta, 4, &bits)?;
                raws.insert(id, bits);
                h
            }
            DocumentVectorOpeningV3::Commitment(o) => {
                if let ComponentOpening::Revealed(c) = o {
                    canonical_point_v1(c.point)?;
                }
                open_hash(r.backend, meta, 5, o)?
            }
        };
        let hashes = [
            backend_component_hash_v3(r.backend, meta, 0, meta)?,
            open_hash(r.backend, meta, 1, &d.membership)?,
            open_hash(r.backend, meta, 2, &d.codes)?,
            open_hash(r.backend, meta, 3, &d.adjacency)?,
            vector_hash,
        ];
        leaves.push((id, backend_document_leaf_v3(r.backend, &hashes)));
    }
    timings.record("component_hashes", now);
    let now = Instant::now();
    verify_document_multiproof_v3(
        base.document_count,
        m.document_root_for(r.backend),
        &leaves,
        &v.proof,
    )?;
    timings.record("multiproof", now);
    let (tables, verified_matrices) = if r.backend == SchemeBackendV3::MatrixScheme {
        let started = Instant::now();
        let (metrics, reranking) = rayon::join(
            || verify_matrix_metric_tables(t, r, &q, &public, &v),
            || verify_disclosed_matrix_reranking(t, r, &q, &v),
        );
        let (tables, mt) = metrics?;
        let (matrices, rt) = reranking?;
        // This outer interval includes the nested coarse/fine overlap.
        let work_ms = mt.phases.values().sum::<f64>() + rt.phases.values().sum::<f64>();
        timings.parallel_overlap_ms += (work_ms - started.elapsed().as_secs_f64() * 1000.).max(0.);
        timings.phases.extend(mt.phases);
        timings.phases.extend(rt.phases);
        (tables, Some(matrices))
    } else {
        if v.metrics.is_some() || v.reranking.is_some() {
            return Err(GemError::InvalidManifest);
        }
        let now = Instant::now();
        let coarse = fixed_similarity_table_v3(&q, &public.coarse)?;
        let selected = select_fixed_clusters_v3(&coarse, &q, base.coarse_count as usize)?;
        let fine = if selected
            .iter()
            .any(|&c| public.entries[c as usize].is_some())
        {
            fixed_similarity_table_v3(&q, &public.fine)?
        } else {
            vec![]
        };
        let tables = AuthenticatedMetricTablesFixedV3 {
            tables: FixedMetricTablesV3::from_tables(
                &coarse,
                fine,
                base.fine_count as usize,
                &q,
                &public.entries,
            )?,
        };
        timings.record("raw_tables", now);
        (tables, None)
    };
    let now = Instant::now();
    let access = SparseAccess {
        docs: v.documents.iter().map(|d| (d.metadata.doc_id, d)).collect(),
    };
    let execution = replay_fixed_search_v3(&access, &public.entries, &q, &tables.tables)?;
    timings.record("replay", now);
    let now = Instant::now();
    let u = &execution.component_usage;
    if v.documents
        .iter()
        .map(|d| d.metadata.doc_id)
        .collect::<BTreeSet<_>>()
        != u.membership
    {
        return Err(GemError::InvalidManifest);
    }
    for d in &v.documents {
        let id = d.metadata.doc_id;
        if !d.membership.is_revealed()
            || d.codes.is_revealed() != u.codes.contains(&id)
            || d.adjacency.is_revealed() != u.adjacency.contains(&id)
            || d.vector.is_revealed() != u.raw.contains(&id)
        {
            return Err(GemError::InvalidManifest);
        }
    }
    timings.record("exact_disclosures", now);
    let matrices = if r.backend == SchemeBackendV3::MatrixScheme {
        verified_matrices.ok_or(GemError::InvalidManifest)?
    } else {
        let now = Instant::now();
        let matrices = u
            .raw
            .par_iter()
            .map(|&id| {
                let meta = &access.doc(id)?.metadata;
                Ok((
                    id,
                    usize::from(meta.token_count),
                    fixed_similarity_table_serial_v3(
                        &q,
                        &fixed_fp16_v1(raws.get(&id).ok_or(GemError::InvalidManifest)?)?,
                    )?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        timings.record("raw_complete_y", now);
        matrices
    };
    let now = Instant::now();
    let results = rerank_fixed_matrices_v3(&q, &matrices)?;
    timings.record("maxsim", now);
    let now = Instant::now();
    if results != v.results {
        return Err(GemError::HashMismatch);
    }
    timings.record("result_check", now);
    timings.finish(total);
    Ok(VerifiedFixedRetrievalV3 {
        execution,
        results,
        timings,
    })
}

#[cfg(test)]
mod optimization_tests {
    use super::*;
    use gem_auth_v3::PublicModeV3;

    #[test]
    fn valid_speculative_reranking_still_requires_exact_replay_disclosures() {
        let (s, source_query) = super::super::tests::fixture(7);
        let r = super::super::tests::req(
            &s,
            &source_query,
            SchemeBackendV3::MatrixScheme,
            PublicModeV3::Cold,
        );
        let q = FixedQueryV3::new(source_query).unwrap();
        let mut vo = execute_scheme_retrieval_v3(&s, &r).unwrap();
        let required_id = vo
            .documents
            .iter()
            .find(|d| d.vector.is_revealed())
            .unwrap()
            .metadata
            .doc_id;
        let extra = vo
            .documents
            .iter_mut()
            .find(|d| !d.vector.is_revealed())
            .unwrap();
        extra.vector = DocumentVectorOpeningV3::Commitment(ComponentOpening::Revealed(
            DocumentMatrixCommitmentV3::new(s.commitments[extra.metadata.doc_id as usize]),
        ));
        let required = vo
            .documents
            .iter_mut()
            .find(|d| d.metadata.doc_id == required_id)
            .unwrap();
        required.vector = DocumentVectorOpeningV3::Commitment(ComponentOpening::Digest(
            s.component_hashes[required_id as usize][4],
        ));
        let disclosed: Vec<_> = vo
            .documents
            .iter()
            .filter(|d| d.vector.is_revealed())
            .collect();
        let boundaries: Vec<_> = disclosed
            .iter()
            .map(|d| TokenBoundaryV3 {
                doc_id: d.metadata.doc_id,
                token_count: d.metadata.token_count,
            })
            .collect();
        let matrices: Vec<_> = boundaries
            .iter()
            .map(|b| {
                (
                    b.doc_id,
                    usize::from(b.token_count),
                    fixed_similarity_table_v3(&q, &s.fixed_documents[b.doc_id as usize]).unwrap(),
                )
            })
            .collect();
        let similarities = pack_y(&matrices, usize::from(q.source.token_count));
        let commitments: Vec<_> = disclosed
            .iter()
            .map(|d| d.vector.commitment().unwrap().point)
            .collect();
        let binding =
            aggregation_binding(&s.trusted, &r, &boundaries, &similarities, &commitments).unwrap();
        let weights = document_weights_v1(binding, boundaries.len()).unwrap();
        let commitment = aggregate_commitments_v1(&commitments, &weights).unwrap();
        let documents: Vec<_> = boundaries
            .iter()
            .map(|b| s.fixed_documents[b.doc_id as usize].as_slice())
            .collect();
        let witness = aggregated_document_witness(
            &documents,
            &weights,
            usize::from(s.trusted.signed.manifest.document_rows) * usize::from(r.query.dimension),
        )
        .unwrap();
        let argument = prove_projection_v1(
            &doc_context(&s.trusted, binding, commitment),
            &witness,
            &mut OsRng,
        )
        .unwrap()
        .0;
        let reranking = vo.reranking.as_mut().unwrap();
        reranking.similarities = similarities;
        reranking.argument = argument;
        let bytes = encode_scheme_vo_v3(&vo).unwrap().0;
        decode_scheme_vo_v3(&bytes, &s.trusted).unwrap();
        for workers in [1, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .build()
                .unwrap();
            pool.install(|| {
                // All extra document coordinates and the forged aggregate proof
                // are authentic. Membership alone must never grant candidacy.
                verify_disclosed_matrix_reranking(&s.trusted, &r, &q, &vo).unwrap();
                assert!(verify_scheme_retrieval_v3(&s.trusted, &r, &bytes).is_err());
            });
        }
    }

    #[test]
    fn i16_windows_cover_every_signed_coordinate() {
        let weights = [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::from_bytes_mod_order_wide(&[197; 64]),
        ];
        let tables = i16_weight_tables(&weights);
        for (doc, alpha) in weights.iter().enumerate() {
            let table = &tables[doc * I16_WEIGHT_TABLE_SIZE..(doc + 1) * I16_WEIGHT_TABLE_SIZE];
            for value in i16::MIN..=i16::MAX {
                assert_eq!(
                    i16_weight_product(table, value),
                    alpha * gem_matrix_proof::scalar_i32_v1(i32::from(value))
                );
            }
        }
    }

    #[test]
    #[ignore = "batched million-coordinate witness: run explicitly with --release --ignored"]
    fn batched_witness_matches_scalar_reference_and_preserves_padding() {
        let dimension = 1280;
        let documents: Vec<Vec<Coordinate>> = (0..I16_WEIGHT_BATCH + 1)
            .map(|doc| {
                let length = if doc % 67 == 0 { 0 } else { 1024 + doc % 130 };
                (0..length)
                    .map(|i| match i % 11 {
                        0 => Coordinate::MIN,
                        1 => Coordinate::MAX,
                        2 => 0,
                        _ => (doc * 8191 + i * 127) as i16 as i64 as Coordinate,
                    })
                    .collect()
            })
            .collect();
        let weights: Vec<_> = (0..documents.len())
            .map(|i| match i % 13 {
                0 => Scalar::ZERO,
                1 => Scalar::ONE,
                _ => Scalar::from_bytes_mod_order_wide(&[i as u8; 64]),
            })
            .collect();
        let views: Vec<_> = documents.iter().map(Vec::as_slice).collect();
        let mut expected = vec![Scalar::ZERO; dimension];
        for (document, alpha) in documents.iter().zip(&weights) {
            for (sum, &value) in expected.iter_mut().zip(document) {
                *sum += alpha * scalar_coordinate(value);
            }
        }
        for threads in [1, 8, 16, 32] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            assert_eq!(
                pool.install(|| aggregated_document_witness(&views, &weights, dimension))
                    .unwrap(),
                expected
            );
        }
        assert!(expected[1153..].iter().all(|x| *x == Scalar::ZERO));
        assert!(
            aggregated_document_witness(&views, &weights[..I16_WEIGHT_BATCH], dimension).is_err()
        );
        assert_eq!(
            aggregated_document_witness(&[], &[], 7).unwrap(),
            vec![Scalar::ZERO; 7]
        );
    }

    #[test]
    fn tiled_aggregations_match_independent_scalar_loops() {
        let weights: Vec<_> = (0..64)
            .map(|i| Scalar::from_bytes_mod_order([i + 17; 32]))
            .collect();
        let m = 32;
        let rows = 20;
        let matrices: Vec<_> = (0..64)
            .map(|id| {
                let n = id % 21;
                (
                    id as u32,
                    n,
                    (0..m * n)
                        .map(|i| (i as i64 - 1000) as Similarity)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let mut expected_y = vec![Scalar::ZERO; m * rows];
        for ((_, n, y), alpha) in matrices.iter().zip(&weights) {
            for j in 0..m {
                for token in 0..*n {
                    expected_y[j * rows + token] += alpha * scalar_similarity(y[j * n + token]);
                }
            }
        }
        let documents: Vec<Vec<_>> = (0..64)
            .map(|id| {
                (0..(id * 17) % 1025)
                    .map(|i| (i as i64 % 101 - 50) as Coordinate)
                    .collect()
            })
            .collect();
        let views: Vec<_> = documents.iter().map(Vec::as_slice).collect();
        let expected_a: Vec<_> = (0..1024)
            .map(|pos| {
                documents
                    .iter()
                    .zip(&weights)
                    .fold(Scalar::ZERO, |sum, (d, a)| {
                        sum + a * scalar_coordinate(d.get(pos).copied().unwrap_or(0))
                    })
            })
            .collect();
        for threads in [1, 8] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            assert_eq!(
                pool.install(|| aggregated_y(&matrices, &weights, m, rows))
                    .unwrap(),
                expected_y
            );
            assert_eq!(
                pool.install(|| aggregated_document_witness(&views, &weights, 1024))
                    .unwrap(),
                expected_a
            );
        }
        assert!(aggregated_y(&matrices, &weights[..63], m, rows).is_err());
        assert!(aggregated_y(&matrices, &weights, usize::MAX, rows).is_err());
        assert!(aggregated_y(&matrices, &weights, m, 3).is_err());
        assert!(aggregated_document_witness(&views, &weights, 128).is_err());
        let malformed = vec![(0, 2, vec![0 as Similarity])];
        assert!(aggregated_y(&malformed, &weights[..1], 2, 2).is_err());
    }
}
