use super::*;

pub(super) const E_VERSION: u32 = 1;
pub(super) const E_LIMIT: u64 = 1 << 30;
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct EManifest {
    pub(super) version: u32,
    pub(super) source: Hash,
    pub(super) profile: String,
    pub(super) generator: String,
    pub(super) stage: u8,
    pub(super) h: usize,
    pub(super) dimension: usize,
    pub(super) leaf_count: u32,
    pub(super) root: Hash,
    pub(super) representation: u8,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct EAuth {
    pub(super) manifest: EManifest,
    pub(super) signature: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct EMaterial {
    pub(super) id: u32,
    pub(super) rows: usize,
    pub(super) raw: Vec<i16>,
    pub(super) fp16: Vec<u16>,
    pub(super) fp32: Vec<u32>,
    pub(super) points: Vec<[u8; 32]>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct EOpening {
    pub(super) index: u32,
    pub(super) value: EMaterial,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct EResponse {
    pub(super) version: u32,
    pub(super) request_hash: Hash,
    pub(super) auth: Option<EAuth>,
    pub(super) openings: Vec<EOpening>,
    pub(super) path: gem_auth_v3::MerkleProofV3,
    pub(super) table: Vec<i32>,
    pub(super) direct: Vec<[u8; 32]>,
    pub(super) projection: Option<gem_matrix_proof::ProjectionArgumentV1>,
    pub(super) arguments: Vec<Vec<u8>>,
    pub(super) claims: Vec<[u8; 32]>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ERequest {
    pub(super) request: SchemeRequestV3,
    pub(super) stage: u8,
    pub(super) method: u8,
    pub(super) h: usize,
    pub(super) cache: bool,
    pub(super) ids: Vec<(u32, usize)>,
    pub(super) snapshot: Hash,
}
pub(super) struct ECache {
    pub(super) auth: EAuth,
    pub(super) material: Vec<EMaterial>,
    pub(super) points: Vec<curve25519_dalek::ristretto::RistrettoPoint>,
    pub(super) converted: Vec<Vec<i16>>,
}
pub(super) struct EServer {
    pub(super) work: FairWork,
    pub(super) source16: Vec<Vec<u16>>,
    pub(super) source32: Vec<Vec<u32>>,
    pub(super) cases: BTreeMap<usize, FairCase>,
    pub(super) auth: BTreeMap<(usize, u8), EAuth>,
    pub(super) materials: BTreeMap<(usize, u8), Vec<EMaterial>>,
    pub(super) trees: BTreeMap<(usize, u8), std::sync::Arc<gem_auth_v3::DocumentTreeV3>>,
    pub(super) key: [u8; 32],
    pub(super) indices: BTreeMap<(usize, u8), Vec<u32>>,
}
pub(super) fn e_encode<T: Serialize>(v: &T) -> anyhow::Result<Vec<u8>> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(E_LIMIT)
        .reject_trailing_bytes()
        .serialize(v)?)
}
pub(super) fn e_decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> anyhow::Result<T> {
    anyhow::ensure!((b.len() as u64) <= E_LIMIT, "wire limit");
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(E_LIMIT)
        .reject_trailing_bytes()
        .deserialize(b)?)
}
pub(super) fn e_leaf(m: &EMaterial) -> Result<Hash> {
    hash(b"four-method.material.v1", m)
}
pub(super) fn e_auth(a: &EAuth, key: [u8; 32]) -> anyhow::Result<()> {
    let m = &a.manifest;
    anyhow::ensure!(
        m.version == E_VERSION
            && m.profile == numeric::PROFILE_ID
            && m.generator == gem_matrix_proof::GENERATOR_ID_V1
            && m.dimension > 0
            && m.dimension <= 4096
            && m.h > 0
            && m.h <= 65536,
        "owner profile/layout"
    );
    VerifyingKey::from_bytes(&key)?
        .verify_strict(&e_encode(m)?, &Signature::from_slice(&a.signature)?)?;
    Ok(())
}
pub(super) fn e_repr(method: u8) -> u8 {
    if method == 0 {
        0
    } else if method == 4 {
        2
    } else {
        1
    }
}
pub(super) fn e_name(method: u8) -> &'static str {
    match method {
        0 => "strawman_raw_compact",
        1 => "vida_shared_query",
        2 => "vida_query_batched",
        BLOCK_POWER_METHOD => "ours_block_powers",
        _ => "invalid",
    }
}
pub(super) fn e_stage(stage: u8) -> anyhow::Result<(String, ProjectionStageV1)> {
    Ok(match stage {
        0 => ("coarse".into(), ProjectionStageV1::Coarse),
        1 => ("fine".into(), ProjectionStageV1::Fine),
        2 => ("rerank".into(), ProjectionStageV1::Reranking),
        _ => anyhow::bail!("stage"),
    })
}
pub(super) fn e_request(
    s: &EServer,
    method: u8,
    h: usize,
    cache: bool,
) -> anyhow::Result<ERequest> {
    let a = &s.auth[&(h, e_repr(method))];
    Ok(ERequest {
        request: s.work.request.clone(),
        stage: if s.work.name == "coarse" {
            0
        } else if s.work.name == "fine" {
            1
        } else {
            2
        },
        method,
        h,
        cache: cache && s.work.name != "rerank",
        ids: s.work.matrices.iter().map(|(id, n, _)| (*id, *n)).collect(),
        snapshot: hash(b"four-method.snapshot.v1", &a.manifest)?,
    })
}
pub(super) fn e_case(
    w: &FairWork,
    h: usize,
    points: Vec<[u8; 32]>,
    decoded: Vec<curve25519_dalek::ristretto::RistrettoPoint>,
    snapshot: Hash,
) -> anyhow::Result<FairCase> {
    anyhow::ensure!(h > 0 && h <= 65536, "height");
    let blocks: Vec<_> = w
        .matrices
        .iter()
        .enumerate()
        .flat_map(|(doc, (id, n, _))| {
            (0..*n).step_by(h).map(move |offset| PilotBlock {
                doc,
                id: *id,
                offset,
                len: h.min(n - offset),
            })
        })
        .collect();
    anyhow::ensure!(
        blocks.len() == points.len() && decoded.len() == points.len(),
        "commitment count"
    );
    let catalog = hash(b"four-method.catalog.v1", &(snapshot, &blocks, &points))?;
    Ok(FairCase {
        h,
        blocks,
        commitments: points,
        catalog,
        points: decoded,
        prepared: None,
    })
}
// An owner is built before timing. The caller supplies one fixed experiment key.
pub(super) fn e_prepare(
    s: &mut EServer,
    hs: &[usize],
    seed: [u8; 32],
) -> anyhow::Result<Vec<serde_json::Value>> {
    let sk = SigningKey::from_bytes(&seed);
    s.key = sk.verifying_key().to_bytes();
    let mut stats = vec![];
    let mut heights = hs.to_vec();
    heights.push(1);
    heights.sort();
    heights.dedup();
    for h in heights {
        let started = Instant::now();
        let c = fair_prepare_selected(&s.work, &[h])?.remove(0);
        s.cases.insert(h, c);
        stats.push(serde_json::json!({"kind":"commitment_build","stage":s.work.name,"h":h,"offline_ms":db_ms(started),"commitment_bytes":s.cases[&h].commitments.len()*32}));
        for repr in if h == 1 { vec![0, 1] } else { vec![1] } {
            let started = Instant::now();
            let c = &s.cases[&h];
            let mut cursor = 0;
            let material: Vec<_> = s
                .work
                .matrices
                .iter()
                .enumerate()
                .map(|(i, (id, n, _))| {
                    let b = n.div_ceil(h);
                    let points = if repr == 1 {
                        c.commitments[cursor..cursor + b].to_vec()
                    } else {
                        vec![]
                    };
                    cursor += b;
                    EMaterial {
                        id: *id,
                        rows: *n,
                        raw: if repr == 0 {
                            s.work.documents[i].clone()
                        } else {
                            vec![]
                        },
                        fp16: if repr == 2 {
                            s.source16[i].clone()
                        } else {
                            vec![]
                        },
                        fp32: if repr == 2 {
                            s.source32[i].clone()
                        } else {
                            vec![]
                        },
                        points,
                    }
                })
                .collect();
            let tree = gem_auth_v3::DocumentTreeV3::build(
                &material.iter().map(e_leaf).collect::<Result<Vec<_>>>()?,
            )?;
            let stage = if s.work.name == "coarse" {
                0
            } else if s.work.name == "fine" {
                1
            } else {
                2
            };
            let manifest = EManifest {
                version: E_VERSION,
                source: s.work.source,
                profile: numeric::PROFILE_ID.into(),
                generator: gem_matrix_proof::GENERATOR_ID_V1.into(),
                stage,
                h,
                dimension: usize::from(s.work.request.query.dimension),
                leaf_count: tree.document_count,
                root: tree.root()?,
                representation: repr,
            };
            let signature = sk.sign(&e_encode(&manifest)?).to_bytes().to_vec();
            let auth = EAuth {
                manifest,
                signature,
            };
            let indices: Vec<u32> = (0..material.len() as u32).collect();
            let bytes =
                e_encode(&material)?.len() + e_encode(&tree)?.len() + e_encode(&auth)?.len();
            stats.push(serde_json::json!({"kind":"owner_build","stage":s.work.name,"h":h,"representation":repr,"offline_ms":db_ms(started),"storage_bytes":bytes,"scope":"fixed_fixture_working_set"}));
            s.auth.insert((h, repr), auth);
            s.materials.insert((h, repr), material);
            s.trees.insert((h, repr), std::sync::Arc::new(tree));
            s.indices.insert((h, repr), indices);
        }
    }
    Ok(stats)
}
pub(super) fn e_matrices(
    q: &FixedQueryV3,
    docs: &[Vec<i16>],
    ids: &[(u32, usize)],
) -> anyhow::Result<CandidateMatricesV3> {
    anyhow::ensure!(docs.len() == ids.len(), "matrix count");
    Ok(docs
        .par_iter()
        .zip(ids.par_iter())
        .map(|(a, (id, n))| {
            Ok((
                *id,
                *n,
                if docs.len() == 1 {
                    fixed_similarity_table_v3(q, a)?
                } else {
                    fixed_similarity_table_serial_v3(q, a)?
                },
            ))
        })
        .collect::<Result<_>>()?)
}
pub(super) fn e_prove(
    w: &FairWork,
    c: &FairCase,
    r: &ERequest,
    vo: &mut EResponse,
    prepared: Option<&PreparedProjectionWitnessV1>,
) -> anyhow::Result<serde_json::Value> {
    let q = FixedQueryV3::new(r.request.query.clone())?;
    let t = Instant::now();
    let b = hash(b"four-method.statement.v1", &(r, &vo.table, c.catalog))?;
    if r.method == 1 || r.method == 2 {
        let mode = if r.method == 1 {
            VidaMode::SharedQuery
        } else {
            VidaMode::QueryBatched
        };
        let mut plans = vida_plans(w, c, &q, b, mode);
        let binding_ms = db_ms(t);
        let t = Instant::now();
        let (witnesses, points, witness_ms, msm_ms) = match mode {
            VidaMode::SharedQuery => {
                anyhow::ensure!(c.h == 1, "VIDA row commitments require height one");
                let witnesses = vida_per_token_witnesses(
                    &w.documents,
                    &c.blocks,
                    usize::from(q.source.dimension),
                    &plans,
                );
                let witness_ms = db_ms(t);
                let t = Instant::now();
                // Com(sum_i alpha_i a_i) uses only the dimension-many public generators.
                let points = witnesses
                    .par_iter()
                    .map(|a| gem_matrix_proof::commit_scalars_v1(a))
                    .collect::<Result<Vec<_>>>()?;
                (witnesses, points, witness_ms, db_ms(t))
            }
            VidaMode::QueryBatched => {
                let points = plans
                    .par_iter()
                    .map(|p| fair_commitment(c, &p.alpha))
                    .collect::<Result<Vec<_>>>()?;
                let msm_ms = db_ms(t);
                let t = Instant::now();
                let witnesses = plans
                    .par_iter()
                    .map(|p| power_witness(w, c, &p.alpha, PowerKernel::Radix))
                    .collect();
                (witnesses, points, db_ms(t), msm_ms)
            }
        };
        let t = Instant::now();
        let bundle = vida_proofs(&mut plans, &points, witnesses)?;
        vo.arguments = bundle.arguments;
        vo.claims = bundle.claims;
        return Ok(
            serde_json::json!({"binding_ms":binding_ms,"commitment_msm_ms":msm_ms,"witness_aggregation_ms":witness_ms,"ipa_ms":db_ms(t)}),
        );
    }
    let wt = Instant::now();
    let weights = block_weights_for_request(r.method, c, b)?;
    let weight_ms = db_ms(wt);
    let binding_ms = db_ms(t);
    let t = Instant::now();
    let kernel = selected_power_kernel(r.method, false);
    // A direct opening transmits only the aggregate vector; its receiver still recomputes the MSM.
    let point = if c.h > 1 || kernel == PowerKernel::Reference {
        Some(fair_commitment(c, &weights)?)
    } else {
        None
    };
    let msm_ms = db_ms(t);
    let t = Instant::now();
    let a = if prepared.is_some() && c.h > 1 {
        vec![]
    } else {
        power_witness(w, c, &weights, kernel)
    };
    let witness_ms = db_ms(t);
    let t = Instant::now();
    if c.h == 1 {
        vo.direct = a.iter().map(Scalar::to_bytes).collect();
    } else {
        let ctx = fair_context(
            w,
            c,
            b,
            point.ok_or_else(|| anyhow::anyhow!("missing IPA commitment"))?,
        );
        vo.projection = Some(if let Some(prepared) = prepared {
            prove_projection_with_prepared_witness_v1(
                numeric::PROFILE_ID,
                &ctx,
                prepared,
                &mut OsRng,
            )?
            .0
        } else {
            prove_projection_v1(&ctx, &a, &mut OsRng)?.0
        });
    }
    Ok(
        serde_json::json!({"weight_ms":weight_ms,"binding_ms":binding_ms,"commitment_msm_ms":msm_ms,"witness_aggregation_ms":witness_ms,"projection_and_ipa_ms":db_ms(t)}),
    )
}
pub(super) fn e_server_tables(
    s: &EServer,
    request_bytes: &[u8],
    bad_table: bool,
    precomputed: Option<&CandidateMatricesV3>,
) -> anyhow::Result<(Vec<u8>, serde_json::Value, BTreeMap<String, usize>)> {
    let t = Instant::now();
    let r: ERequest = e_decode(request_bytes)?;
    let q = FixedQueryV3::new(r.request.query.clone())?;
    anyhow::ensure!(
        [0, 1, 2, 5].contains(&r.method)
            && !r.cache
            && r.ids
                == s.work
                    .matrices
                    .iter()
                    .map(|(id, n, _)| (*id, *n))
                    .collect::<Vec<_>>(),
        "request fields"
    );
    let k = (r.h, e_repr(r.method));
    let auth = s.auth.get(&k).ok_or_else(|| anyhow::anyhow!("layout"))?;
    anyhow::ensure!(
        hash(b"four-method.snapshot.v1", &auth.manifest)? == r.snapshot,
        "snapshot"
    );
    let parse_ms = db_ms(t);
    let t = Instant::now();
    let mut vo = EResponse {
        version: E_VERSION,
        request_hash: hash(b"four-method.request.v1", &r)?,
        auth: if r.cache { None } else { Some(auth.clone()) },
        openings: vec![],
        path: Default::default(),
        table: vec![],
        direct: vec![],
        projection: None,
        arguments: vec![],
        claims: vec![],
    };
    if !r.cache {
        vo.openings = s.materials[&k]
            .iter()
            .zip(&s.indices[&k])
            .map(|(i, &index)| EOpening {
                index,
                value: i.clone(),
            })
            .collect();
        vo.path = s.trees[&k].prove(&s.indices[&k])?;
    }
    let structure_ms = db_ms(t);
    let t = Instant::now();
    let mut phases = serde_json::json!({});
    if e_repr(r.method) == 1 {
        let computed;
        let matrices = if let Some(t) = precomputed {
            t
        } else {
            computed = e_matrices(&q, &s.work.documents, &r.ids)?;
            &computed
        };
        vo.table = pack_y(matrices, usize::from(q.source.token_count));
        if bad_table {
            vo.table[0] ^= 1;
        }
        phases["table_ms"] = serde_json::json!(db_ms(t));
        let old = &s.cases[&r.h];
        let c = e_case(
            &s.work,
            r.h,
            old.commitments.clone(),
            old.points.clone(),
            r.snapshot,
        )?;
        phases["proof"] = e_prove(&s.work, &c, &r, &mut vo, old.prepared.as_ref())?;
    }
    let t = Instant::now();
    let bytes = e_encode(&vo)?;
    let codec_ms = db_ms(t);
    let mut parts = BTreeMap::new();
    parts.insert(
        "raw_coordinate_bytes".into(),
        vo.openings
            .iter()
            .map(|o| o.value.raw.len() * 2 + o.value.fp16.len() * 2 + o.value.fp32.len() * 4)
            .sum(),
    );
    parts.insert("similarity_table_bytes".into(), vo.table.len() * 4);
    parts.insert(
        "row_or_block_commitment_bytes".into(),
        vo.openings.iter().map(|o| o.value.points.len() * 32).sum(),
    );
    parts.insert(
        "projection_or_direct_opening_bytes".into(),
        vo.direct.len() * 32
            + vo.projection
                .as_ref()
                .map_or(0, |p| p.projection.len() * 32),
    );
    parts.insert(
        "ipa_argument_bytes".into(),
        vo.arguments.iter().map(Vec::len).sum::<usize>()
            + vo.projection.as_ref().map_or(0, |p| p.argument.len()),
    );
    parts.insert("aggregated_claim_bytes".into(), vo.claims.len() * 32);
    parts.insert(
        "owner_signature_and_catalog_metadata_bytes".into(),
        if let Some(a) = &vo.auth {
            e_encode(a)?.len()
        } else {
            0
        },
    );
    parts.insert(
        "merkle_or_other_auth_path_bytes".into(),
        vo.path.siblings.len() * 32,
    );
    parts.insert(
        "document_ids_lengths_layout_bytes".into(),
        vo.openings.len() * 16,
    );
    let accounted: usize = parts.values().sum();
    anyhow::ensure!(accounted <= bytes.len(), "byte accounting");
    parts.insert("framing_and_other_bytes".into(), bytes.len() - accounted);
    phases["request_parse_ms"] = serde_json::json!(parse_ms);
    phases["structure_prepare_ms"] = serde_json::json!(structure_ms);
    phases["encode_ms"] = serde_json::json!(codec_ms);
    Ok((bytes, phases, parts))
}
// Independent receive path. No EServer, reference matrices, or server FairCase.
pub(super) fn e_client(
    r: &ERequest,
    key: [u8; 32],
    cache: Option<&ECache>,
    bytes: &[u8],
) -> anyhow::Result<(CandidateMatricesV3, serde_json::Value)> {
    e_client_inner(r, key, cache, bytes, true)
}
pub(super) fn e_client_inner(
    r: &ERequest,
    key: [u8; 32],
    cache: Option<&ECache>,
    bytes: &[u8],
    downstream: bool,
) -> anyhow::Result<(CandidateMatricesV3, serde_json::Value)> {
    let total = Instant::now();
    let t = Instant::now();
    let vo: EResponse = e_decode(bytes)?;
    anyhow::ensure!(
        [0, 1, 2, 5].contains(&r.method)
            && !r.cache
            && vo.version == E_VERSION
            && vo.request_hash == hash(b"four-method.request.v1", r)?,
        "request binding"
    );
    let q = FixedQueryV3::new(r.request.query.clone())?;
    let d = usize::from(q.source.dimension);
    let m = usize::from(q.source.token_count);
    let parse_ms = db_ms(t);
    let t = Instant::now();
    let (auth, material) = if r.cache {
        anyhow::ensure!(
            r.stage != 2
                && vo.auth.is_none()
                && vo.openings.is_empty()
                && vo.path.siblings.is_empty(),
            "cached payload"
        );
        let c = cache.ok_or_else(|| anyhow::anyhow!("cache missing"))?;
        (&c.auth, c.material.as_slice())
    } else {
        let a = vo
            .auth
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("owner missing"))?;
        e_auth(a, key)?;
        anyhow::ensure!(vo.openings.len() == r.ids.len(), "opening count");
        let leaves = vo
            .openings
            .iter()
            .map(|o| Ok((o.index, e_leaf(&o.value)?)))
            .collect::<Result<Vec<_>>>()?;
        verify_document_multiproof_v3(a.manifest.leaf_count, a.manifest.root, &leaves, &vo.path)?;
        // Below uses a separate material allocation containing only received bytes.
        (a, &[][..])
    };
    let received: Vec<_>;
    let material = if r.cache {
        material
    } else {
        received = vo.openings.iter().map(|o| o.value.clone()).collect();
        &received
    };
    let am = &auth.manifest;
    anyhow::ensure!(
        hash(b"four-method.snapshot.v1", am)? == r.snapshot
            && am.source == r.request.manifest_digest
            && am.stage == r.stage
            && am.h == r.h
            && am.dimension == d
            && am.representation == e_repr(r.method),
        "owner context"
    );
    anyhow::ensure!(
        material.len() == r.ids.len() && !material.is_empty(),
        "material count"
    );
    for (a, &(id, n)) in material.iter().zip(&r.ids) {
        anyhow::ensure!(
            a.id == id && a.rows == n && n > 0 && n <= 1_000_000,
            "ID/true length"
        );
        let size = n
            .checked_mul(d)
            .ok_or_else(|| anyhow::anyhow!("shape overflow"))?;
        match e_repr(r.method) {
            0 => anyhow::ensure!(
                a.raw.len() == size
                    && a.fp16.is_empty()
                    && a.fp32.is_empty()
                    && a.points.is_empty()
                    && a.raw.iter().all(|&x| x != i16::MIN),
                "raw shape/range"
            ),
            1 => anyhow::ensure!(
                a.points.len() == n.div_ceil(r.h)
                    && a.raw.is_empty()
                    && a.fp16.is_empty()
                    && a.fp32.is_empty(),
                "points shape"
            ),
            _ => anyhow::ensure!(
                a.raw.is_empty()
                    && a.points.is_empty()
                    && if r.stage == 0 {
                        a.fp32.len() == size && a.fp16.is_empty()
                    } else {
                        a.fp16.len() == size && a.fp32.is_empty()
                    },
                "source shape"
            ),
        }
    }
    let auth_ms = db_ms(t);
    let t = Instant::now();
    let mut phases = serde_json::json!({"parse_ms":parse_ms,"owner_path_hash_ms":auth_ms});
    let matrices = if e_repr(r.method) != 1 {
        anyhow::ensure!(
            vo.table.is_empty()
                && vo.direct.is_empty()
                && vo.projection.is_none()
                && vo.arguments.is_empty()
                && vo.claims.is_empty(),
            "raw redundant proof/table"
        );
        let matrices = if r.method == 0 {
            material
                .par_iter()
                .map(|a| {
                    Ok((
                        a.id,
                        a.rows,
                        if material.len() == 1 {
                            fixed_similarity_table_v3(&q, &a.raw)?
                        } else {
                            fixed_similarity_table_serial_v3(&q, &a.raw)?
                        },
                    ))
                })
                .collect::<Result<Vec<_>>>()?
        } else if r.cache {
            e_matrices(&q, &cache.unwrap().converted, &r.ids)?
        } else {
            let docs = material
                .iter()
                .map(|a| {
                    if r.stage == 0 {
                        fixed_coordinates_v1(
                            &a.fp32
                                .iter()
                                .map(|&x| f32::from_bits(x))
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        fixed_fp16_v1(&a.fp16)
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            e_matrices(&q, &docs, &r.ids)?
        };
        phases["raw_conversion_recompute_ms"] = serde_json::json!(db_ms(t));
        matrices
    } else {
        let boundaries = r
            .ids
            .iter()
            .map(|&(id, n)| {
                Ok(TokenBoundaryV3 {
                    doc_id: id,
                    token_count: u16::try_from(n)?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>();
        // Codebooks can exceed u16 row counts in endpoint studies; unpack directly.
        let rows = r.ids.iter().try_fold(0usize, |a, (_, n)| {
            a.checked_add(*n)
                .ok_or_else(|| anyhow::anyhow!("shape overflow"))
        })?;
        anyhow::ensure!(rows.checked_mul(m) == Some(vo.table.len()), "table shape");
        let mut offset = 0;
        let matrices: Vec<_> = r
            .ids
            .iter()
            .map(|&(id, n)| {
                let y = (0..m)
                    .flat_map(|t| {
                        vo.table[t * rows + offset..t * rows + offset + n]
                            .iter()
                            .copied()
                    })
                    .collect();
                offset += n;
                (id, n, y)
            })
            .collect();
        let _ = boundaries;
        let (name, stage) = e_stage(r.stage)?;
        let w = FairWork {
            name,
            stage,
            request: r.request.clone(),
            documents: vec![],
            matrices,
            source: am.source,
            global_rows: rows,
        };
        let encoded: Vec<_> = material
            .iter()
            .flat_map(|a| a.points.iter().copied())
            .collect();
        let decoded = if r.cache {
            cache.unwrap().points.clone()
        } else {
            decode_points(&encoded)?
        };
        phases["commitment_decode_ms"] = serde_json::json!(db_ms(t));
        let t = Instant::now();
        let c = e_case(&w, r.h, encoded, decoded, r.snapshot)?;
        let b = hash(b"four-method.statement.v1", &(r, &vo.table, c.catalog))?;
        if r.method == 1 || r.method == 2 {
            anyhow::ensure!(
                r.h == 1 && vo.direct.is_empty() && vo.projection.is_none(),
                "VIDA layout"
            );
            let mode = if r.method == 1 {
                VidaMode::SharedQuery
            } else {
                VidaMode::QueryBatched
            };
            let mut plans = vida_plans(&w, &c, &q, b, mode);
            phases["binding_ms"] = serde_json::json!(db_ms(t));
            let t = Instant::now();
            let points = plans
                .par_iter()
                .map(|p| fair_commitment(&c, &p.alpha))
                .collect::<Result<Vec<_>>>()?;
            phases["commitment_msm_ms"] = serde_json::json!(db_ms(t));
            let t = Instant::now();
            let claims = plans
                .par_iter()
                .map(|p| vida_fast_table_claim(&w, p))
                .collect::<Vec<_>>();
            phases["table_aggregation_ms"] = serde_json::json!(db_ms(t));
            let t = Instant::now();
            vida_verify_proofs(
                &mut plans,
                &points,
                &claims,
                &VidaBundle {
                    arguments: vo.arguments,
                    claims: vo.claims,
                },
            )?;
            phases["ipa_verify_ms"] = serde_json::json!(db_ms(t));
        } else {
            anyhow::ensure!(
                vo.arguments.is_empty() && vo.claims.is_empty(),
                "block proof format"
            );
            let wt = Instant::now();
            let weights = block_weights_for_request(r.method, &c, b)?;
            phases["weight_ms"] = serde_json::json!(db_ms(wt));
            phases["binding_ms"] = serde_json::json!(db_ms(t));
            let t = Instant::now();
            let point = fair_commitment(&c, &weights)?;
            phases["commitment_msm_ms"] = serde_json::json!(db_ms(t));
            let t = Instant::now();
            let y = power_table(&w, &c, &weights, selected_power_kernel(r.method, true));
            phases["table_aggregation_ms"] = serde_json::json!(db_ms(t));
            let t = Instant::now();
            if r.h == 1 {
                anyhow::ensure!(vo.projection.is_none(), "direct format");
                fair_direct(&q, point, &vo.direct, &y)?;
            } else {
                anyhow::ensure!(vo.direct.is_empty(), "IPA format");
                let (checked, _) = verify_projection_v1(
                    &fair_context(&w, &c, b, point),
                    vo.projection
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing projection"))?,
                )?;
                verify_aggregated_freivalds_v1(&q.coordinates, &y, d, &checked)?;
            }
            phases["projection_ipa_relation_ms"] = serde_json::json!(db_ms(t));
        }
        w.matrices
    };
    let t = Instant::now();
    if downstream && r.stage == 2 {
        let _ = rerank_fixed_matrices_v3(&q, &matrices)?;
    } else if downstream && r.stage == 0 {
        let _ = select_fixed_clusters_v3(&matrices[0].2, &q, matrices[0].1)?;
    }
    phases["downstream_ms"] = serde_json::json!(db_ms(t));
    phases["total_ms"] = serde_json::json!(db_ms(total));
    Ok((matrices, phases))
}
