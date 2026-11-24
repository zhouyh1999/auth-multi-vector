use super::*;

// Full-corpus service and independent receive path for the frozen LoTTE benchmark.
pub(super) type PopPoint = curve25519_dalek::ristretto::RistrettoPoint;
pub(super) struct PopCatalog {
    pub(super) auth: EAuth,
    pub(super) tree: PopArc<gem_auth_v3::DocumentTreeV3>,
    pub(super) encoded: Vec<Hash>,
    pub(super) decoded: Vec<PopPoint>,
}
pub struct PopulationService {
    pub(super) source: PreparedSchemeSnapshotV3,
    pub(super) offsets: Vec<u64>,
    pub(super) block_offsets: Vec<usize>,
    pub(super) fixed: Vec<i16>,
    pub(super) owners: BTreeMap<(usize, u8), PopCatalog>,
    pub(super) books: Vec<EServer>,
}
pub(super) fn pop_route(policy: u8, cached: bool) -> ([u8; 3], [usize; 3]) {
    debug_assert!(!cached);
    (
        [policy; 3],
        if policy == BLOCK_POWER_METHOD {
            [8, 32, 128]
        } else {
            [1; 3]
        },
    )
}
pub(super) fn pop_empty_server(work: FairWork) -> EServer {
    EServer {
        work,
        source16: vec![],
        source32: vec![],
        cases: BTreeMap::new(),
        auth: BTreeMap::new(),
        materials: BTreeMap::new(),
        trees: BTreeMap::new(),
        key: [0; 32],
        indices: BTreeMap::new(),
    }
}
impl PopulationService {
    pub fn open(
        root: &PopPath,
        source: PreparedSchemeSnapshotV3,
        trusted: &TrustedSchemeSnapshotV3,
        offsets: Vec<u64>,
        shards: &[PopulationShard],
        initial: gem_core::QueryV3,
        policies: &[u8],
    ) -> anyhow::Result<Self> {
        validate_trusted_scheme_snapshot_v3(trusted)?;
        anyhow::ensure!(
            &source.trusted == trusted
                && source.index.documents.len()
                    == trusted.signed.manifest.source().document_count as usize
        );
        let base = trusted.signed.manifest.source();
        let n = base.document_count as usize;
        anyhow::ensure!(
            source.raw_tree.root()? == base.document_root
                && source.index.cluster_entries == source.public.entries
        );
        anyhow::ensure!(
            source.raw_component_hashes.len() == n
                && source.metadata.len() == n
                && offsets.len() == n + 1
        );
        anyhow::ensure!(
            shards.first().map(|s| s.doc_start) == Some(0)
                && shards.last().map(|s| s.doc_end) == Some(n)
        );
        let mut block_offsets = Vec::with_capacity(n + 1);
        block_offsets.push(0usize);
        for (i, w) in offsets.windows(2).enumerate() {
            let rows = usize::try_from(
                w[1].checked_sub(w[0])
                    .ok_or_else(|| anyhow::anyhow!("document offsets"))?,
            )?;
            anyhow::ensure!(rows == source.metadata[i].token_count as usize && rows > 0);
            block_offsets.push(block_offsets[i] + rows.div_ceil(POP_HEIGHT));
        }
        let total = *offsets.last().unwrap() as usize;
        let mut fixed = Vec::with_capacity(total * POP_DIM);
        for s in shards {
            let packed = std::fs::read(pop_shard_file(root, s.doc_start, "fixed-i16.bin"))?;
            anyhow::ensure!(
                packed.len() == (offsets[s.doc_end] - offsets[s.doc_start]) as usize * POP_DIM * 2
            );
            fixed.extend(
                packed
                    .chunks_exact(2)
                    .map(|b| i16::from_le_bytes([b[0], b[1]])),
            );
        }
        anyhow::ensure!(fixed.len() == total * POP_DIM);
        let key = SigningKey::from_bytes(&[19; 32]).verifying_key().to_bytes();
        let representations = policies
            .iter()
            .map(|&p| {
                let (m, h) = pop_route(p, false);
                (h[2], e_repr(m[2]))
            })
            .collect::<BTreeSet<_>>();
        let mut owners = BTreeMap::new();
        for (h, repr) in representations {
            let prefix = root.join(format!("global-h{h}-r{repr}"));
            let auth: EAuth = e_decode(&std::fs::read(prefix.with_extension("auth"))?)?;
            e_auth(&auth, key)?;
            let tree: gem_auth_v3::DocumentTreeV3 =
                e_decode(&std::fs::read(prefix.with_extension("tree"))?)?;
            anyhow::ensure!(
                auth.manifest.source == trusted.expected_manifest_digest
                    && auth.manifest.stage == 2
                    && auth.manifest.h == h
                    && auth.manifest.representation == repr
                    && auth.manifest.leaf_count == base.document_count
                    && tree.document_count == base.document_count
                    && tree.root()? == auth.manifest.root
            );
            let mut encoded = Vec::new();
            let mut decoded = Vec::new();
            if repr == 1 {
                let count = if h == 1 { total } else { block_offsets[n] };
                encoded.reserve_exact(count);
                decoded.reserve_exact(count);
                for s in shards {
                    let points = pop_read_points(&pop_shard_file(
                        root,
                        s.doc_start,
                        &format!("points-{h}.bin"),
                    ))?;
                    let expected = if h == 1 {
                        (offsets[s.doc_end] - offsets[s.doc_start]) as usize
                    } else {
                        block_offsets[s.doc_end] - block_offsets[s.doc_start]
                    };
                    anyhow::ensure!(points.len() == expected);
                    decoded.extend(decode_points(&points)?);
                    encoded.extend(points);
                }
            }
            owners.insert(
                (h, repr),
                PopCatalog {
                    auth,
                    tree: PopArc::new(tree),
                    encoded,
                    decoded,
                },
            );
        }
        let request = SchemeRequestV3 {
            manifest_digest: trusted.expected_manifest_digest,
            query: initial,
            backend: SchemeBackendV3::FixedRawFp16,
            public_mode: gem_auth_v3::PublicModeV3::Cold,
        };
        let mut books = vec![];
        for (i, coords) in [&source.coarse_fixed, &source.fine_fixed]
            .into_iter()
            .enumerate()
        {
            let (name, stage) = e_stage(i as u8)?;
            let n = coords.len() / POP_DIM;
            let work = FairWork {
                name,
                stage,
                request: request.clone(),
                documents: vec![coords.clone()],
                matrices: vec![(0, n, vec![])],
                source: trusted.expected_manifest_digest,
                global_rows: n,
            };
            let mut book = pop_empty_server(work);
            book.source16 = vec![if i == 1 {
                source.public.fine_bits.clone()
            } else {
                vec![]
            }];
            book.source32 = vec![if i == 0 {
                source.public.coarse_bits.clone()
            } else {
                vec![]
            }];
            let hs = policies
                .iter()
                .map(|&p| pop_route(p, false).1[i])
                .collect::<Vec<_>>();
            e_prepare(&mut book, &hs, [19; 32])?;
            books.push(book);
        }
        Ok(Self {
            source,
            offsets,
            block_offsets,
            fixed,
            owners,
            books,
        })
    }

    pub(super) fn request(&self, q: &gem_core::QueryV3) -> SchemeRequestV3 {
        SchemeRequestV3 {
            manifest_digest: self.source.trusted.expected_manifest_digest,
            query: q.clone(),
            backend: SchemeBackendV3::FixedRawFp16,
            public_mode: gem_auth_v3::PublicModeV3::Cold,
        }
    }

    pub(super) fn book_tables(
        &mut self,
        r: &SchemeRequestV3,
        q: &FixedQueryV3,
    ) -> anyhow::Result<()> {
        for book in &mut self.books {
            book.work.request = r.clone();
            book.work.matrices[0].2 = fixed_similarity_table_v3(q, &book.work.documents[0])?;
        }
        Ok(())
    }

    pub(super) fn search(&self, q: &FixedQueryV3) -> anyhow::Result<FixedExecutionV3> {
        let coarse = &self.books[0].work.matrices[0].2;
        let fine = &self.books[1].work.matrices[0];
        let entries = &self.source.index.cluster_entries;
        let tables = FixedMetricTablesV3::from_tables(coarse, fine.2.clone(), fine.1, q, entries)?;
        Ok(replay_fixed_search_v3(
            &self.source.index,
            entries,
            q,
            &tables,
        )?)
    }

    pub(super) fn rerank_stage(
        &self,
        r: &SchemeRequestV3,
        q: &FixedQueryV3,
        ids: &[u32],
        method: u8,
        h: usize,
        score: bool,
    ) -> anyhow::Result<EServer> {
        let repr = e_repr(method);
        let owner = &self.owners[&(h, repr)];
        let bounds = ids
            .iter()
            .map(|&id| (id, self.source.metadata[id as usize].token_count as usize))
            .collect::<Vec<_>>();
        let docs = bounds
            .par_iter()
            .map(|&(id, n)| {
                let start = self.offsets[id as usize] as usize * POP_DIM;
                self.fixed[start..start + n * POP_DIM].to_vec()
            })
            .collect::<Vec<_>>();
        let matrices = if score {
            e_matrices(q, &docs, &bounds)?
        } else {
            bounds.iter().map(|&(id, n)| (id, n, Vec::new())).collect()
        };
        let work = FairWork {
            name: "rerank".into(),
            stage: ProjectionStageV1::Reranking,
            request: r.clone(),
            documents: docs,
            matrices,
            source: r.manifest_digest,
            global_rows: 180,
        };
        let mut stage = pop_empty_server(work);
        stage.key = owner_key_for_server();
        let mut material = Vec::with_capacity(ids.len());
        let mut points = vec![];
        let mut decoded = vec![];
        for (i, &(id, n)) in bounds.iter().enumerate() {
            if repr == 0 {
                material.push(pop_material(id, n, stage.work.documents[i].clone(), vec![]));
            } else {
                let start = if h == 1 {
                    self.offsets[id as usize] as usize
                } else {
                    self.block_offsets[id as usize]
                };
                let end = start + n.div_ceil(h);
                let local = &owner.encoded[start..end];
                material.push(pop_material(id, n, vec![], local.to_vec()));
                points.extend_from_slice(local);
                decoded.extend_from_slice(&owner.decoded[start..end]);
            }
        }
        if repr == 1 {
            let pin = hash(b"four-method.snapshot.v1", &owner.auth.manifest)?;
            stage
                .cases
                .insert(h, e_case(&stage.work, h, points, decoded, pin)?);
        }
        let k = (h, repr);
        stage.auth.insert(k, owner.auth.clone());
        stage.materials.insert(k, material);
        stage.indices.insert(k, ids.to_vec());
        stage.trees.insert(k, PopArc::clone(&owner.tree));
        Ok(stage)
    }

    pub(super) fn structure(
        &self,
        ex: &FixedExecutionV3,
        results: Vec<FixedNodeDistanceV3>,
    ) -> anyhow::Result<SchemeRetrievalVoV3> {
        let s = &self.source;
        let u = &ex.component_usage;
        let ids = u.membership.iter().copied().collect::<Vec<_>>();
        let documents = ids
            .iter()
            .map(|&id| {
                let i = id as usize;
                let d = &s.index.documents[i];
                let h = &s.raw_component_hashes[i];
                SchemeDocumentOpeningV3 {
                    metadata: s.metadata[i].clone(),
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
                    vector: DocumentVectorOpeningV3::Raw(ComponentOpening::Digest(h[4])),
                }
            })
            .collect();
        Ok(SchemeRetrievalVoV3 {
            backend: SchemeBackendV3::FixedRawFp16,
            public_mode: gem_auth_v3::PublicModeV3::Cold,
            public: Some(SchemePublicPayloadV3 {
                entries: s.index.cluster_entries.clone(),
                raw_centroids: None,
            }),
            documents,
            proof: s.raw_tree.prove(&ids)?,
            metrics: None,
            reranking: None,
            results,
        })
    }

    pub(super) fn server(
        &mut self,
        request: &[u8],
    ) -> anyhow::Result<(Vec<u8>, BTreeMap<String, usize>, serde_json::Value)> {
        let r: EFullRequest = e_decode(request)?;
        let q = validate_scheme_request_v3(&self.source.trusted, &r.request)?;
        let (methods, heights) = pop_route(r.method, r.cache);
        anyhow::ensure!(r.heights == heights && !r.cache && [0, 1, 2, 5].contains(&r.method));
        let t = Instant::now();
        self.book_tables(&r.request, &q)?;
        let codebook_ms = db_ms(t);
        let t = Instant::now();
        let ex = self.search(&q)?;
        let search_ms = db_ms(t);
        let t = Instant::now();
        let ids = ex.component_usage.raw.iter().copied().collect::<Vec<_>>();
        let rerank = self.rerank_stage(&r.request, &q, &ids, methods[2], heights[2], true)?;
        let results = rerank_fixed_matrices_v3(&q, &rerank.work.matrices)?;
        let rerank_ms = db_ms(t);
        let t = Instant::now();
        let structure = self.structure(&ex, results)?;
        let structure_ms = db_ms(t);
        let mut payloads = vec![];
        let mut requests = vec![];
        let mut parts = BTreeMap::new();
        let mut phases = vec![];
        for (i, stage) in self
            .books
            .iter()
            .chain(std::iter::once(&rerank))
            .enumerate()
        {
            let sr = e_request(stage, methods[i], heights[i], r.cache)?;
            let (bytes, times, cost) =
                e_server_tables(stage, &e_encode(&sr)?, false, Some(&stage.work.matrices))?;
            for (name, size) in cost {
                *parts.entry(name).or_default() += size;
            }
            requests.push(sr);
            payloads.push(bytes);
            phases.push(times);
        }
        let v = EFullResponse {
            version: E_VERSION,
            requests,
            stages: payloads,
            structure,
            source: self.source.trusted.clone(),
        };
        let t = Instant::now();
        let bytes = e_encode(&v)?;
        let stage_bytes = parts.values().sum::<usize>();
        parts.insert(
            "search_structure_source_signature_result_and_full_framing_bytes".into(),
            bytes.len() - stage_bytes,
        );
        let phase = serde_json::json!({"codebook_tables_ms":codebook_ms,"search_ms":search_ms,"rerank_and_material_ms":rerank_ms,
            "source_structure_ms":structure_ms,"full_encode_ms":db_ms(t),"stages":phases,"candidates":ids.len(),"ranked":v.structure.results.len()});
        Ok((bytes, parts, phase))
    }

    pub fn standalone_candidates(&mut self, q: &gem_core::QueryV3) -> anyhow::Result<Vec<u32>> {
        let r = self.request(q);
        let compact = validate_scheme_request_v3(&self.source.trusted, &r)?;
        self.book_tables(&r, &compact)?;
        Ok(self
            .search(&compact)?
            .component_usage
            .raw
            .into_iter()
            .collect())
    }
}
