use crate::snapshot::{component_hash_v3, public_digests};
use crate::*;
use gem_core::{GemError, RawDocumentF32V3, Result};
use gem_search::{
    NativeQueryResultV3, QueryMetricTablesV3, QueryPublicV3, RawVectorSourceV3, SearchAccessV3,
    replay_search_v3, rerank_from_source_v3,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
fn request(t: &TrustedSnapshotV3, r: &RawRequestV3) -> Result<()> {
    r.query.validate(t.signed.manifest.dimension)?;
    let m = &t.signed.manifest;
    if r.manifest_digest != t.expected_manifest_digest
        || r.query.params != m.params
        || r.query.token_count != m.query_tokens
        || !m.allowed_wire.contains(&r.raw_wire)
    {
        return Err(GemError::InvalidManifest);
    }
    Ok(())
}
#[derive(Clone, Debug)]
pub struct AuthenticatedPublicV3 {
    fine: Vec<f32>,
    coarse: Vec<f32>,
    data: PublicDataV3,
}
impl AuthenticatedPublicV3 {
    pub fn data(&self) -> &PublicDataV3 {
        &self.data
    }
    fn public(&self, d: u16) -> QueryPublicV3<'_> {
        QueryPublicV3 {
            dimension: d,
            fine_centroids: &self.fine,
            coarse_centroids: &self.coarse,
            cluster_entries: &self.data.entries,
        }
    }
}
pub fn authenticate_public_data_v3(
    t: &TrustedSnapshotV3,
    data: PublicDataV3,
) -> Result<AuthenticatedPublicV3> {
    validate_trusted_snapshot_v3(t)?;
    let m = &t.signed.manifest;
    if data.fine_bits.len() != m.fine_count as usize * usize::from(m.dimension)
        || data.coarse_bits.len() != m.coarse_count as usize * usize::from(m.dimension)
        || data.entries.len() != m.coarse_count as usize
        || data
            .entries
            .iter()
            .flatten()
            .any(|&id| id >= m.document_count)
        || public_digests(&data)? != [m.fine_digest, m.coarse_digest, m.entry_digest]
    {
        return Err(GemError::HashMismatch);
    }
    let fine = decode_fp16_v3(&data.fine_bits)?;
    let coarse: Vec<f32> = data
        .coarse_bits
        .iter()
        .map(|&b| f32::from_bits(b))
        .collect();
    if coarse.iter().any(|v| !v.is_finite()) {
        return Err(GemError::NonFinite);
    }
    Ok(AuthenticatedPublicV3 { fine, coarse, data })
}
// Orphan rules require this wrapper for the raw provider.
struct SparseRaw<'a>(&'a BTreeMap<u32, RawDocumentF32V3>);
impl RawVectorSourceV3 for SparseRaw<'_> {
    fn raw(&self, id: u32) -> Result<&RawDocumentF32V3> {
        self.0.get(&id).ok_or(GemError::InvalidManifest)
    }
}
struct SparseAccess<'a> {
    docs: BTreeMap<u32, &'a DocumentOpeningV3>,
}
impl SparseAccess<'_> {
    fn doc(&self, id: u32) -> Result<&DocumentOpeningV3> {
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
/// Validated immutable server state. Construction verifies persisted components once.
#[derive(Debug)]
pub struct ServerSnapshotV3 {
    prepared: PreparedRawSnapshotV3,
}
impl std::ops::Deref for ServerSnapshotV3 {
    type Target = PreparedRawSnapshotV3;
    fn deref(&self) -> &Self::Target {
        &self.prepared
    }
}
impl ServerSnapshotV3 {
    pub fn rerank_candidates_v3(
        &self,
        query: &gem_core::QueryV3,
        ids: &[u32],
    ) -> Result<gem_search::ExactRerankResultV3> {
        let raw = ids
            .iter()
            .map(|&id| {
                let m = self
                    .metadata
                    .get(id as usize)
                    .ok_or(GemError::InvalidManifest)?;
                Ok((
                    id,
                    RawDocumentF32V3 {
                        doc_id: id,
                        token_count: m.token_count,
                        dimension: self.trusted.signed.manifest.dimension,
                        coordinates: decode_fp16_v3(&self.raw_bits[id as usize])?,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        rerank_from_source_v3(query, &SparseRaw(&raw), ids)
    }
}
pub fn initialize_server_snapshot_v3(prepared: PreparedRawSnapshotV3) -> Result<ServerSnapshotV3> {
    validate_prepared_snapshot_v3(&prepared)?;
    Ok(ServerSnapshotV3 { prepared })
}
pub fn execute_raw_retrieval_v3(
    s: &ServerSnapshotV3,
    r: &RawRequestV3,
) -> Result<RawRetrievalVoV3> {
    Ok(execute_raw_retrieval_measured_v3(s, r)?.0)
}
/// Executes once against the immutable, validated server state.
pub fn execute_raw_retrieval_measured_v3(
    s: &ServerSnapshotV3,
    r: &RawRequestV3,
) -> Result<(
    RawRetrievalVoV3,
    gem_search::QueryExecutionV3,
    ServerTimingsV3,
)> {
    request(&s.trusted, r)?;
    let mut timings = ServerTimingsV3::default();
    let start = Instant::now();
    let tables = QueryMetricTablesV3::compute((&s.index).into(), &r.query)?;
    timings.tables_ms = ms(start);
    let start = Instant::now();
    let execution = replay_search_v3(&s.index, (&s.index).into(), &r.query, &tables)?;
    timings.search_ms = ms(start);
    let start = Instant::now();
    let ids: Vec<u32> = execution
        .trace
        .candidates
        .iter()
        .map(|r| r.doc_id)
        .collect();
    let exact = s.rerank_candidates_v3(&r.query, &ids)?;
    timings.rerank_ms = ms(start);
    let start = Instant::now();
    let u = &execution.component_usage;
    let mut documents = Vec::new();
    for &id in &u.membership {
        let d = &s.index.documents[id as usize];
        let h = &s.component_hashes[id as usize];
        let codes = if u.codes.contains(&id) {
            ComponentOpening::Revealed(d.compact_codes.clone())
        } else {
            ComponentOpening::Digest(h[2])
        };
        let adjacency = if u.adjacency.contains(&id) {
            ComponentOpening::Revealed(d.adjacency.clone())
        } else {
            ComponentOpening::Digest(h[3])
        };
        let raw = if u.raw.contains(&id) {
            ComponentOpening::Revealed(match r.raw_wire {
                RawWireV3::Fp16 => RawOpeningV3::Fp16(s.raw_bits[id as usize].clone()),
                RawWireV3::Fp32 => RawOpeningV3::Fp32(
                    decode_fp16_v3(&s.raw_bits[id as usize])?
                        .iter()
                        .map(|x| x.to_bits())
                        .collect(),
                ),
            })
        } else {
            ComponentOpening::Digest(h[4])
        };
        documents.push(DocumentOpeningV3 {
            metadata: s.metadata[id as usize].clone(),
            membership: ComponentOpening::Revealed(d.cluster_ids.clone()),
            codes,
            adjacency,
            raw,
        });
    }
    let proof = s
        .tree
        .prove(&u.membership.iter().copied().collect::<Vec<_>>())?;
    let public = Some(s.public.clone());
    let vo = RawRetrievalVoV3 {
        raw_wire: r.raw_wire,
        public_mode: r.public_mode,
        public,
        documents,
        proof,
        results: exact.results,
    };
    timings.opening_proof_ms = ms(start);
    Ok((vo, execution, timings))
}
fn hash_open<T: serde::Serialize>(
    m: &MetadataV3,
    k: u8,
    o: &ComponentOpening<T>,
) -> Result<gem_core::Hash> {
    match o {
        ComponentOpening::Digest(h) => Ok(*h),
        ComponentOpening::Revealed(v) => component_hash_v3(m, k, v),
    }
}
fn ordered(ids: &[u32], max: u32) -> bool {
    ids.iter().all(|&id| id < max) && ids.windows(2).all(|p| p[0] < p[1])
}
pub fn verify_raw_retrieval_v3(
    t: &TrustedSnapshotV3,
    r: &RawRequestV3,
    b: &[u8],
) -> Result<VerifiedRetrievalV3> {
    let mut timings = ClientTimingsV3::default();
    let start = Instant::now();
    let v = decode_raw_vo_v3(b, t)?;
    timings.decoding_ms = ms(start);
    let start = Instant::now();
    validate_trusted_snapshot_v3(t)?;
    request(t, r)?;
    if v.raw_wire != r.raw_wire || v.public_mode != r.public_mode {
        return Err(GemError::InvalidManifest);
    }
    // A new client authenticates the full VO payload for every request.
    let public =
        authenticate_public_data_v3(t, v.public.clone().ok_or(GemError::InvalidManifest)?)?;
    timings.public_auth_ms = ms(start);
    let start = Instant::now();
    let m = &t.signed.manifest;
    let mut leaves = Vec::new();
    let mut canonical_raw = BTreeMap::new();
    for d in &v.documents {
        let meta = &d.metadata;
        let id = meta.doc_id;
        let membership = d.membership.revealed()?;
        if membership.is_empty()
            || membership.len() > m.coarse_count as usize
            || !ordered(membership, m.coarse_count)
        {
            return Err(GemError::InvalidManifest);
        }
        if let ComponentOpening::Revealed(c) = &d.codes
            && (c.len() != usize::from(meta.token_count) || c.iter().any(|&id| id >= m.fine_count))
        {
            return Err(GemError::InvalidTokenCount);
        }
        if let ComponentOpening::Revealed(a) = &d.adjacency
            && (a.len() > usize::from(m.graph_params.m0)
                || a.iter().any(|&neighbor| neighbor >= m.document_count)
                || !m.semantic_profile.is_published_fixed_graph() && !ordered(a, m.document_count)
                || a.contains(&id))
        {
            return Err(GemError::InvalidManifest);
        }
        let raw_hash = match &d.raw {
            ComponentOpening::Digest(h) => *h,
            ComponentOpening::Revealed(raw) => {
                let bits = match (raw, r.raw_wire) {
                    (RawOpeningV3::Fp16(b), RawWireV3::Fp16) => {
                        decode_fp16_v3(b)?;
                        b.clone()
                    }
                    (RawOpeningV3::Fp32(b), RawWireV3::Fp32) => fp32_to_canonical_fp16_v3(b)?,
                    _ => return Err(GemError::NonCanonicalFrame),
                };
                if bits.len() != usize::from(meta.token_count) * usize::from(m.dimension) {
                    return Err(GemError::InvalidTokenCount);
                }
                let h = component_hash_v3(meta, 4, &bits)?;
                canonical_raw.insert(id, bits);
                h
            }
        };
        let h = [
            component_hash_v3(meta, 0, meta)?,
            hash_open(meta, 1, &d.membership)?,
            hash_open(meta, 2, &d.codes)?,
            hash_open(meta, 3, &d.adjacency)?,
            raw_hash,
        ];
        leaves.push((id, document_leaf_v3(&h)));
    }
    timings.component_hash_ms = ms(start);
    let start = Instant::now();
    verify_document_multiproof_v3(m.document_count, m.document_root, &leaves, &v.proof)?;
    timings.multiproof_ms = ms(start);
    let access = SparseAccess {
        docs: v.documents.iter().map(|d| (d.metadata.doc_id, d)).collect(),
    };
    let start = Instant::now();
    let tables = QueryMetricTablesV3::compute(public.public(m.dimension), &r.query)?;
    timings.lookup_ms = ms(start);
    let start = Instant::now();
    let execution = replay_search_v3(&access, public.public(m.dimension), &r.query, &tables)?;
    timings.replay_ms = ms(start);
    let start = Instant::now();
    let u = &execution.component_usage;
    let actual: BTreeSet<u32> = v.documents.iter().map(|d| d.metadata.doc_id).collect();
    if actual != u.membership {
        return Err(GemError::InvalidManifest);
    }
    for d in &v.documents {
        let id = d.metadata.doc_id;
        if !d.membership.is_revealed()
            || d.codes.is_revealed() != u.codes.contains(&id)
            || d.adjacency.is_revealed() != u.adjacency.contains(&id)
            || d.raw.is_revealed() != u.raw.contains(&id)
        {
            return Err(GemError::InvalidManifest);
        }
    }
    timings.result_check_ms += ms(start);
    let start = Instant::now();
    let mut raw = BTreeMap::new();
    for (id, bits) in canonical_raw {
        let meta = &access.doc(id)?.metadata;
        raw.insert(
            id,
            RawDocumentF32V3 {
                doc_id: id,
                token_count: meta.token_count,
                dimension: m.dimension,
                coordinates: decode_fp16_v3(&bits)?,
            },
        );
    }
    let ids: Vec<u32> = execution
        .trace
        .candidates
        .iter()
        .map(|r| r.doc_id)
        .collect();
    let exact = rerank_from_source_v3(&r.query, &SparseRaw(&raw), &ids)?;
    timings.raw_maxsim_ms = ms(start);
    let start = Instant::now();
    if exact.results != v.results {
        return Err(GemError::HashMismatch);
    }
    timings.result_check_ms += ms(start);
    Ok(VerifiedRetrievalV3 {
        result: NativeQueryResultV3 {
            trace: execution.trace.clone(),
            exact,
        },
        execution,
        timings,
    })
}
