use super::*;

#[derive(Serialize, Deserialize)]
pub(super) struct VisitStageRequest {
    pub(super) request: SchemeRequestV3,
    pub(super) stage: u8,
    pub(super) method: u8,
    pub(super) height: usize,
    pub(super) snapshot: Hash,
    pub(super) candidates: Vec<u32>,
}
pub(super) type VisitBill = BTreeMap<String, usize>;
impl PopulationService {
    pub fn reference_stage_hashes(
        &self,
        query: &gem_core::QueryV3,
        ids: &[u32],
    ) -> anyhow::Result<[Hash; 3]> {
        let q = FixedQueryV3::new(query.clone())?;
        let mut answer = [[0; 32]; 3];
        for (i, coords) in [&self.source.coarse_fixed, &self.source.fine_fixed]
            .into_iter()
            .enumerate()
        {
            let matrices: CandidateMatricesV3 = vec![(
                0,
                coords.len() / 128,
                fixed_similarity_table_v3(&q, coords)?,
            )];
            answer[i] = hash(b"four-method.stage-verified-matrices.v1", &matrices)?;
        }
        let bounds = ids
            .iter()
            .map(|&id| (id, self.source.metadata[id as usize].token_count as usize))
            .collect::<Vec<_>>();
        let docs = bounds
            .iter()
            .map(|&(id, n)| {
                let first = self.offsets[id as usize] as usize * 128;
                self.fixed[first..first + 128 * n].to_vec()
            })
            .collect::<Vec<_>>();
        answer[2] = hash(
            b"four-method.stage-verified-matrices.v1",
            &e_matrices(&q, &docs, &bounds)?,
        )?;
        Ok(answer)
    }

    pub(super) fn visit_stage_server(
        &mut self,
        wire: &[u8],
    ) -> anyhow::Result<(Vec<u8>, VisitBill, serde_json::Value)> {
        let req: VisitStageRequest = e_decode(wire)?;
        let q = validate_scheme_request_v3(&self.source.trusted, &req.request)?;
        let i = req.stage as usize;
        anyhow::ensure!(
            i < 3
                && [0, 1, 2, 5].contains(&req.method)
                && req.height == pop_route(req.method, false).1[i]
        );
        let start = Instant::now();
        let rerank;
        let stage = if i == 2 {
            anyhow::ensure!(
                !req.candidates.is_empty()
                    && req.candidates.len() <= q.source.params.rerank_k as usize
                    && req.candidates.windows(2).all(|x| x[0] < x[1])
                    && req.candidates.last().copied().unwrap() < (self.offsets.len() - 1) as u32
            );
            rerank = self.rerank_stage(
                &req.request,
                &q,
                &req.candidates,
                req.method,
                req.height,
                req.method != 0,
            )?;
            &rerank
        } else {
            anyhow::ensure!(req.candidates.is_empty());
            let book = &mut self.books[i];
            book.work.request = req.request.clone();
            if req.method == 0 {
                book.work.matrices[0].2.clear();
            } else {
                book.work.matrices[0].2 = fixed_similarity_table_v3(&q, &book.work.documents[0])?;
            }
            &*book
        };
        let inner = e_request(stage, req.method, req.height, false)?;
        anyhow::ensure!(
            inner.snapshot == req.snapshot
                && inner.stage == req.stage
                && inner.request == req.request
        );
        let prepare_ms = db_ms(start);
        let (mut bytes, phases, mut bill) =
            e_server_tables(stage, &e_encode(&inner)?, false, Some(&stage.work.matrices))?;
        if i == 2 {
            for &(_, n) in &inner.ids {
                bytes.extend_from_slice(&u32::try_from(n)?.to_le_bytes());
            }
            bill.insert(
                "standalone_candidate_length_bytes".into(),
                4 * inner.ids.len(),
            );
        }
        Ok((
            bytes,
            bill,
            serde_json::json!({"material_and_scoring_ms":prepare_ms,"proof_response":phases}),
        ))
    }

    pub fn measure_visit(
        &mut self,
        client: &VisitClient,
        query: &gem_core::QueryV3,
        policy: u8,
        scope: usize,
        candidates: &[u32],
        expected_stages: &[Hash; 3],
        expected_full: &str,
        capture: Option<&std::path::Path>,
    ) -> anyhow::Result<serde_json::Value> {
        let begin = Instant::now();
        let (trust, origin) = client.fetch(policy, scope)?;
        let digest_ms = db_ms(begin);
        let encode = Instant::now();
        let request = SchemeRequestV3 {
            manifest_digest: trust.index,
            query: query.clone(),
            backend: SchemeBackendV3::FixedRawFp16,
            public_mode: gem_auth_v3::PublicModeV3::Cold,
        };
        let (_, heights) = pop_route(policy, false);
        let (
            request_len,
            response_len,
            bill,
            sp,
            cp,
            encode_ms,
            server_ms,
            client_ms,
            transaction_ms,
            proof_digest,
            rows,
            n_candidates,
        ) = if scope == 3 {
            let r = EFullRequest {
                request,
                method: policy,
                heights,
                cache: false,
            };
            let wire = e_encode(&r)?;
            let encode_ms = db_ms(encode);
            let t = Instant::now();
            let (reply, bill, sp) = self.server(&wire)?;
            let server_ms = db_ms(t);
            let t = Instant::now();
            let (digest, cp) = e_full_client_pinned(
                &r,
                client.keys[1],
                trust.index,
                client.keys[0],
                &[None, None, None],
                &reply,
                Some(&trust.stages),
            )?;
            let client_ms = db_ms(t);
            let transaction_ms = db_ms(begin);
            let result = hex::encode(digest);
            anyhow::ensure!(
                result == expected_full,
                "native search, candidates, or top-100 disagreement"
            );
            if let Some(dir) = capture {
                let method = visit_method(policy)?;
                std::fs::write(dir.join(format!("{method}.request")), &wire)?;
                std::fs::write(dir.join(format!("{method}.response")), &reply)?;
            }
            (
                wire.len(),
                reply.len(),
                bill,
                sp,
                cp,
                encode_ms,
                server_ms,
                client_ms,
                transaction_ms,
                result,
                0,
                0,
            )
        } else {
            let r = VisitStageRequest {
                request,
                stage: scope as u8,
                method: policy,
                height: heights[scope],
                snapshot: trust.stages[scope],
                candidates: if scope == 2 {
                    candidates.to_vec()
                } else {
                    Vec::new()
                },
            };
            let wire = e_encode(&r)?;
            let encode_ms = db_ms(encode);
            let t = Instant::now();
            let (reply, bill, sp) = self.visit_stage_server(&wire)?;
            let server_ms = db_ms(t);
            let t = Instant::now();
            let length_bytes = 4 * r.candidates.len();
            anyhow::ensure!(reply.len() >= length_bytes);
            let (body, lengths) = reply.split_at(reply.len() - length_bytes);
            let ids = if scope == 2 {
                r.candidates
                    .iter()
                    .zip(lengths.chunks_exact(4))
                    .map(|(&id, n)| (id, u32::from_le_bytes(n.try_into().unwrap()) as usize))
                    .collect()
            } else {
                vec![(0, trust.book_sizes[scope])]
            };
            let native = ERequest {
                request: r.request,
                stage: r.stage,
                method: policy,
                h: r.height,
                cache: false,
                ids,
                snapshot: r.snapshot,
            };
            let (matrices, cp) = e_client(&native, client.keys[1], None, body)?;
            let client_ms = db_ms(t);
            let transaction_ms = db_ms(begin);
            let digest = hash(b"four-method.stage-verified-matrices.v1", &matrices)?;
            anyhow::ensure!(
                digest == expected_stages[scope],
                "authenticated stage result differs from native coordinates"
            );
            let row_count = matrices.iter().map(|(_, n, _)| *n).sum::<usize>();
            (
                wire.len(),
                reply.len(),
                bill,
                sp,
                cp,
                encode_ms,
                server_ms,
                client_ms,
                transaction_ms,
                hex::encode(digest),
                row_count,
                r.candidates.len(),
            )
        };
        let main_wire_ms = (request_len + response_len) as f64 / 37500.;
        let remainder = transaction_ms - (digest_ms + encode_ms + server_ms + client_ms);
        anyhow::ensure!(remainder >= -0.002 && bill.values().sum::<usize>() == response_len);
        Ok(
            serde_json::json!({"query_id":query.query_id,"scope":if scope==3{"query_e2e"}else{"stage_e2e"},
            "stage":VISIT_STAGES[scope],"method":e_name(policy),"stage_methods":vec![policy,policy,policy],"layout":heights,
            "height":if scope<3{heights[scope]}else{0},"cache_policy":"first_visit","candidate_count":n_candidates,
            "real_rows":rows,"digest_fetches":1,"digest_wall_ms":digest_ms,"digest":origin,"new_index_pin":hex::encode(trust.index),
            "new_stage_pins":trust.stages.iter().map(hex::encode).collect::<Vec<_>>(),
            "request_encode_ms":encode_ms,"server_wall_ms":server_ms,"client_wall_ms":client_ms,"orchestration_ms":remainder,
            "transaction_wall_ms":transaction_ms,"request_bytes":request_len,"response_bytes":response_len,"wire_parts":bill,
            "server_phases":sp,"client_phases":cp,"modeled_transfer_ms":main_wire_ms,"modeled_e2e_ms":transaction_ms+main_wire_ms,
            "verified":true,"reference_parity":true,"execution_digest":proof_digest,"owner_documents":self.offsets.len()-1,
            "threads":rayon::current_num_threads()}),
        )
    }
}
