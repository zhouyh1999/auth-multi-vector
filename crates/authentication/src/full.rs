use super::*;

// Complete serial request: actual search replay, selective disclosure, original
// source ADS, arithmetic payloads, codec, independent client replay and MaxSim.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct EFullRequest {
    pub(super) request: SchemeRequestV3,
    pub(super) method: u8,
    pub(super) heights: [usize; 3],
    pub(super) cache: bool,
}
#[derive(Serialize, Deserialize)]
pub(super) struct EFullResponse {
    pub(super) version: u32,
    pub(super) requests: Vec<ERequest>,
    pub(super) stages: Vec<Vec<u8>>,
    pub(super) structure: SchemeRetrievalVoV3,
    pub(super) source: TrustedSchemeSnapshotV3,
}
pub(super) fn e_source_structure(
    t: &TrustedSchemeSnapshotV3,
    v: &SchemeRetrievalVoV3,
) -> anyhow::Result<()> {
    validate_trusted_scheme_snapshot_v3(t)?;
    let base = t.signed.manifest.source();
    let p = v
        .public
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("public entries missing"))?;
    anyhow::ensure!(
        p.raw_centroids.is_none()
            && p.entries.len() == base.coarse_count as usize
            && scheme_entries_digest_v3(&p.entries)? == t.signed.manifest.entries_digest,
        "public structure"
    );
    anyhow::ensure!(
        v.documents
            .windows(2)
            .all(|a| a[0].metadata.doc_id < a[1].metadata.doc_id),
        "document order"
    );
    let mut leaves = vec![];
    for d in &v.documents {
        let meta = &d.metadata;
        let id = meta.doc_id;
        anyhow::ensure!(
            id < base.document_count
                && meta.token_count > 0
                && meta.token_count <= base.max_doc_tokens,
            "metadata"
        );
        let membership = d.membership.revealed()?;
        anyhow::ensure!(
            !membership.is_empty() && ordered(membership, base.coarse_count),
            "membership"
        );
        if let ComponentOpening::Revealed(c) = &d.codes {
            anyhow::ensure!(
                c.len() == usize::from(meta.token_count) && c.iter().all(|&x| x < base.fine_count),
                "codes"
            );
        }
        if let ComponentOpening::Revealed(a) = &d.adjacency {
            anyhow::ensure!(
                a.len() <= usize::from(base.graph_params.m0)
                    && a.iter().all(|&x| x < base.document_count)
                    && !a.contains(&id),
                "adjacency"
            );
        }
        let vector = if let DocumentVectorOpeningV3::Raw(ComponentOpening::Digest(h)) = &d.vector {
            *h
        } else {
            anyhow::bail!("source vector must be digest")
        };
        let backend = SchemeBackendV3::FixedRawFp16;
        let hashes = [
            backend_component_hash_v3(backend, meta, 0, meta)?,
            open_hash(backend, meta, 1, &d.membership)?,
            open_hash(backend, meta, 2, &d.codes)?,
            open_hash(backend, meta, 3, &d.adjacency)?,
            vector,
        ];
        leaves.push((id, backend_document_leaf_v3(backend, &hashes)));
    }
    verify_document_multiproof_v3(base.document_count, base.document_root, &leaves, &v.proof)?;
    Ok(())
}
pub(super) fn e_full_client_pinned(
    r: &EFullRequest,
    key: [u8; 32],
    source_pin: Hash,
    source_key: [u8; 32],
    caches: &[Option<ECache>],
    bytes: &[u8],
    pinned: Option<&[Hash; 3]>,
) -> anyhow::Result<(Hash, serde_json::Value)> {
    let t = Instant::now();
    let v: EFullResponse = e_decode(bytes)?;
    anyhow::ensure!(
        v.version == E_VERSION
            && v.stages.len() == 3
            && v.requests.len() == 3
            && v.source.expected_manifest_digest == source_pin
            && v.source.owner_public_key == source_key,
        "full envelope"
    );
    let q = validate_scheme_request_v3(&v.source, &r.request)?;
    let parse_ms = db_ms(t);
    let t = Instant::now();
    e_source_structure(&v.source, &v.structure)?;
    let structure_ms = db_ms(t);
    let mut matrices = vec![];
    let mut phase = vec![];
    for i in 0..3 {
        let sr = &v.requests[i];
        if let Some(roots) = pinned {
            anyhow::ensure!(sr.snapshot == roots[i], "unexpected campaign owner root");
        }
        anyhow::ensure!(
            sr.request == r.request
                && sr.stage == i as u8
                && sr.method == r.method
                && sr.h == r.heights[i]
                && sr.cache == (r.cache && i != 2),
            "stage request mismatch"
        );
        let (mat, p) = e_client_inner(sr, key, caches[i].as_ref(), &v.stages[i], false)?;
        matrices.push(mat);
        phase.push(p);
    }
    let t = Instant::now();
    let entries = &v.structure.public.as_ref().unwrap().entries;
    let base = v.source.signed.manifest.source();
    anyhow::ensure!(
        matrices[0].len() == 1
            && matrices[1].len() == 1
            && matrices[0][0].1 == base.coarse_count as usize
            && matrices[1][0].1 == base.fine_count as usize,
        "codebook shapes"
    );
    let tables = FixedMetricTablesV3::from_tables(
        &matrices[0][0].2,
        matrices[1][0].2.clone(),
        matrices[1][0].1,
        &q,
        entries,
    )?;
    let access = SparseAccess {
        docs: v
            .structure
            .documents
            .iter()
            .map(|d| (d.metadata.doc_id, d))
            .collect(),
    };
    let execution = replay_fixed_search_v3(&access, entries, &q, &tables)?;
    let u = &execution.component_usage;
    anyhow::ensure!(
        v.structure
            .documents
            .iter()
            .map(|d| d.metadata.doc_id)
            .collect::<BTreeSet<_>>()
            == u.membership,
        "membership disclosure"
    );
    for d in &v.structure.documents {
        anyhow::ensure!(
            d.codes.is_revealed() == u.codes.contains(&d.metadata.doc_id)
                && d.adjacency.is_revealed() == u.adjacency.contains(&d.metadata.doc_id),
            "exact structure disclosure"
        );
    }
    anyhow::ensure!(
        matrices[2].iter().map(|x| x.0).collect::<BTreeSet<_>>() == u.raw,
        "candidate replay"
    );
    for (id, n, _) in &matrices[2] {
        anyhow::ensure!(
            *n == usize::from(access.doc(*id)?.metadata.token_count),
            "true length versus source"
        );
    }
    let replay_ms = db_ms(t);
    let t = Instant::now();
    let results = rerank_fixed_matrices_v3(&q, &matrices[2])?;
    anyhow::ensure!(results == v.structure.results, "final results");
    let digest = hash(
        b"gem.csr38.execution-and-results.v1",
        &(&execution, &results),
    )?;
    Ok((
        digest,
        serde_json::json!({"full_decode_ms":parse_ms,"source_signature_paths_ms":structure_ms,"stages":phase,"replay_ms":replay_ms,"maxsim_result_check_ms":db_ms(t)}),
    ))
}
