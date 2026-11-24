use crate::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use gem_core::{
    GemError, Hash, RawDocumentV3, RepairPolicyV3, Result, SEMANTIC_PROFILE_REPO_V3,
    SearchParamsV3, hash_bytes,
};
use gem_search::SearchIndexV3;
use half::f16;
use std::collections::BTreeSet;

pub(crate) fn canonical<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    bincode::serialize(v).map_err(|e| GemError::Serialization(e.to_string()))
}
pub fn manifest_digest_v3(m: &ManifestV3) -> Result<Hash> {
    Ok(hash_bytes(b"gem.auth.v3.manifest.2", &canonical(m)?))
}
pub fn request_digest_v3(q: &RawRequestV3) -> Result<Hash> {
    Ok(hash_bytes(b"gem.auth.v3.request.2", &canonical(q)?))
}
pub(crate) fn hash_value<T: serde::Serialize>(domain: &[u8], v: &T) -> Result<Hash> {
    gem_core::hash_serialized(domain, v)
}
pub fn component_hash_v3<T: serde::Serialize>(
    meta: &MetadataV3,
    kind: u8,
    value: &T,
) -> Result<Hash> {
    let mut bytes = AUTH_SCHEMA_V3.to_le_bytes().to_vec();
    bytes.push(kind);
    bytes.extend(canonical(meta)?);
    bytes.extend(canonical(value)?);
    Ok(hash_bytes(b"gem.auth.v3.component.2", &bytes))
}
pub fn document_leaf_v3(hashes: &[Hash; 5]) -> Hash {
    let mut bytes = AUTH_SCHEMA_V3.to_le_bytes().to_vec();
    for h in hashes {
        bytes.extend(h)
    }
    hash_bytes(b"gem.auth.v3.leaf.2", &bytes)
}
pub fn fp32_to_canonical_fp16_v3(bits: &[u32]) -> Result<Vec<u16>> {
    bits.iter()
        .map(|&b| {
            let x = f32::from_bits(b);
            if !x.is_finite() {
                return Err(GemError::NonFinite);
            }
            let h = f16::from_f32(x);
            if !h.is_finite() || h.to_f32().to_bits() != b {
                return Err(GemError::NonCanonicalFrame);
            }
            Ok(h.to_bits())
        })
        .collect()
}
pub fn decode_fp16_v3(bits: &[u16]) -> Result<Vec<f32>> {
    bits.iter()
        .map(|&b| {
            let x = f16::from_bits(b).to_f32();
            if !x.is_finite() {
                Err(GemError::NonFinite)
            } else {
                Ok(x)
            }
        })
        .collect()
}
pub fn validate_trusted_snapshot_v3(t: &TrustedSnapshotV3) -> Result<()> {
    let m = &t.signed.manifest;
    if manifest_digest_v3(m)? != t.expected_manifest_digest {
        return Err(GemError::HashMismatch);
    }
    VerifyingKey::from_bytes(&t.owner_public_key)
        .map_err(|_| GemError::InvalidSignature)?
        .verify_strict(
            &t.expected_manifest_digest,
            &Signature::from_slice(&t.signed.signature).map_err(|_| GemError::InvalidSignature)?,
        )
        .map_err(|_| GemError::InvalidSignature)?;
    m.semantic_profile.validate()?;
    m.graph_params.validate_repo_profile()?;
    m.params.validate()?;
    if m.authentication_schema != AUTH_SCHEMA_V3
        || m.semantic_profile.profile_id != SEMANTIC_PROFILE_REPO_V3
        || !m.semantic_profile.is_published_fixed_graph()
            && m.semantic_profile.repair_policy()? != RepairPolicyV3::RepoFaithful
        || m.semantic_profile.wave_size != m.graph_params.wave_size
        || m.dimension == 0
        || m.max_doc_tokens == 0
        || m.query_tokens == 0
        || m.document_count == 0
        || m.document_count > u32::MAX / 2
        || m.fine_count == 0
        || m.coarse_count == 0
        || m.params.cluster_top_t > m.coarse_count
        || m.token_count < u64::from(m.document_count)
        || m.token_count > u64::from(m.document_count) * u64::from(m.max_doc_tokens)
        || m.canonical_raw != "finite-fp16-bits-token-major-v1"
        || m.allowed_wire != vec![RawWireV3::Fp16, RawWireV3::Fp32]
    {
        return Err(GemError::InvalidManifest);
    }
    if usize::from(m.dimension)
        .checked_mul(m.fine_count as usize)
        .and_then(|n| n.checked_mul(2))
        .filter(|&n| n <= MAX_VO_BYTES)
        .is_none()
    {
        return Err(GemError::FrameTooLarge);
    }
    Ok(())
}
pub(crate) fn public_digests(p: &PublicDataV3) -> Result<[Hash; 3]> {
    Ok([
        hash_value(b"gem.auth.v3.fine.1", &p.fine_bits)?,
        hash_value(b"gem.auth.v3.coarse.1", &p.coarse_bits)?,
        hash_value(b"gem.auth.v3.entry.1", &p.entries)?,
    ])
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SnapshotBuildTimingsV3 {
    pub index_public_validation_ms: f64,
    pub component_hashing_ms: f64,
    pub mht_build_ms: f64,
    pub provenance_signing_ms: f64,
}
pub fn prepare_raw_snapshot_v3(
    index: SearchIndexV3,
    raw: &[RawDocumentV3],
    source_ids: &[u64],
    query_tokens: u16,
    params: SearchParamsV3,
    provenance_digest: Hash,
    key: &SigningKey,
) -> Result<PreparedRawSnapshotV3> {
    Ok(prepare_raw_snapshot_measured_v3(
        index,
        raw,
        source_ids,
        query_tokens,
        params,
        provenance_digest,
        key,
    )?
    .0)
}
pub fn prepare_raw_snapshot_measured_v3(
    index: SearchIndexV3,
    raw: &[RawDocumentV3],
    source_ids: &[u64],
    query_tokens: u16,
    params: SearchParamsV3,
    provenance_digest: Hash,
    key: &SigningKey,
) -> Result<(PreparedRawSnapshotV3, SnapshotBuildTimingsV3)> {
    let started = std::time::Instant::now();
    index.validate_policy()?;
    params.validate()?;
    if raw.len() != index.documents.len()
        || source_ids.len() != raw.len()
        || source_ids.iter().copied().collect::<BTreeSet<_>>().len() != raw.len()
    {
        return Err(GemError::InvalidManifest);
    }
    let fine_bits = fp32_to_canonical_fp16_v3(
        &index
            .fine_centroids
            .iter()
            .map(|v| v.to_bits())
            .collect::<Vec<_>>(),
    )?;
    let public = PublicDataV3 {
        fine_bits,
        coarse_bits: index.coarse_centroids.iter().map(|v| v.to_bits()).collect(),
        entries: index.cluster_entries.clone(),
    };
    let digests = public_digests(&public)?;
    let index_public_validation_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = std::time::Instant::now();
    let mut metadata = Vec::new();
    let mut raw_bits = Vec::new();
    let mut component_hashes = Vec::new();
    let mut leaves = Vec::new();
    let mut tokens = 0u64;
    for (id, (r, d)) in raw.iter().zip(&index.documents).enumerate() {
        r.validate(index.dimension, index.max_doc_tokens)?;
        if r.doc_id as usize != id || r.token_count != d.token_count {
            return Err(GemError::InvalidManifest);
        }
        decode_fp16_v3(&r.coordinate_bits)?;
        tokens = tokens
            .checked_add(u64::from(r.token_count))
            .ok_or(GemError::NumericOverflow)?;
        let m = MetadataV3 {
            doc_id: r.doc_id,
            token_count: r.token_count,
        };
        let h = [
            component_hash_v3(&m, 0, &m)?,
            component_hash_v3(&m, 1, &d.cluster_ids)?,
            component_hash_v3(&m, 2, &d.compact_codes)?,
            component_hash_v3(&m, 3, &d.adjacency)?,
            component_hash_v3(&m, 4, &r.coordinate_bits)?,
        ];
        leaves.push(document_leaf_v3(&h));
        metadata.push(m);
        raw_bits.push(r.coordinate_bits.clone());
        component_hashes.push(h);
    }
    let component_hashing_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = std::time::Instant::now();
    let tree = DocumentTreeV3::build(&leaves)?;
    let mht_build_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = std::time::Instant::now();
    let index_digest = hash_value(b"gem.auth.v3.index-provenance.1", &index)?;
    let raw_digest = hash_value(b"gem.auth.v3.raw-provenance.1", &raw_bits)?;
    let source_ids_digest = hash_value(b"gem.auth.v3.source-ids.1", &source_ids)?;
    let snapshot_id = hash_value(
        b"gem.auth.v3.snapshot.1",
        &(
            index_digest,
            raw_digest,
            source_ids_digest,
            provenance_digest,
        ),
    )?;
    let manifest = ManifestV3 {
        authentication_schema: AUTH_SCHEMA_V3,
        semantic_profile: index.semantic_profile.clone(),
        graph_params: index.graph_params,
        snapshot_id,
        document_count: raw.len() as u32,
        token_count: tokens,
        dimension: index.dimension,
        max_doc_tokens: index.max_doc_tokens,
        query_tokens,
        params,
        fine_count: (index.fine_centroids.len() / usize::from(index.dimension)) as u32,
        coarse_count: index.cluster_entries.len() as u32,
        document_root: tree.root()?,
        fine_digest: digests[0],
        coarse_digest: digests[1],
        entry_digest: digests[2],
        index_digest,
        raw_digest,
        source_ids_digest,
        provenance_digest,
        canonical_raw: "finite-fp16-bits-token-major-v1".into(),
        allowed_wire: vec![RawWireV3::Fp16, RawWireV3::Fp32],
    };
    let expected_manifest_digest = manifest_digest_v3(&manifest)?;
    let signature = key.sign(&expected_manifest_digest).to_bytes().to_vec();
    let trusted = TrustedSnapshotV3 {
        owner_public_key: key.verifying_key().to_bytes(),
        expected_manifest_digest,
        signed: SignedManifestV3 {
            manifest,
            signature,
        },
    };
    validate_trusted_snapshot_v3(&trusted)?;
    let timings = SnapshotBuildTimingsV3 {
        index_public_validation_ms,
        component_hashing_ms,
        mht_build_ms,
        provenance_signing_ms: started.elapsed().as_secs_f64() * 1000.,
    };
    Ok((
        PreparedRawSnapshotV3 {
            trusted,
            public,
            index,
            metadata,
            source_ids: source_ids.to_vec(),
            raw_bits,
            component_hashes,
            tree,
        },
        timings,
    ))
}
/// Borrowed offline validation view: no full-corpus clone during scheme loading.
pub struct RawSnapshotViewV3<'a> {
    pub trusted: &'a TrustedSnapshotV3,
    pub public: &'a PublicDataV3,
    pub index: &'a SearchIndexV3,
    pub metadata: &'a [MetadataV3],
    pub source_ids: &'a [u64],
    pub raw_bits: &'a [Vec<u16>],
    pub component_hashes: &'a [[Hash; 5]],
    pub tree: &'a DocumentTreeV3,
}
pub fn validate_prepared_snapshot_v3(s: &PreparedRawSnapshotV3) -> Result<()> {
    validate_raw_snapshot_view_v3(RawSnapshotViewV3 {
        trusted: &s.trusted,
        public: &s.public,
        index: &s.index,
        metadata: &s.metadata,
        source_ids: &s.source_ids,
        raw_bits: &s.raw_bits,
        component_hashes: &s.component_hashes,
        tree: &s.tree,
    })
}
/// Rebuild all authenticated state; no serialized "validated" flag is trusted.
pub fn validate_raw_snapshot_view_v3(s: RawSnapshotViewV3<'_>) -> Result<()> {
    validate_trusted_snapshot_v3(&s.trusted)?;
    s.index.validate_policy()?;
    let m = &s.trusted.signed.manifest;
    if s.metadata.len() != m.document_count as usize
        || s.source_ids.len() != s.metadata.len()
        || s.raw_bits.len() != s.metadata.len()
        || s.component_hashes.len() != s.metadata.len()
        || s.index.documents.len() != s.metadata.len()
    {
        return Err(GemError::InvalidManifest);
    }
    let sources = &s.source_ids;
    if sources.iter().copied().collect::<BTreeSet<_>>().len() != sources.len()
        || hash_value(b"gem.auth.v3.index-provenance.1", &s.index)? != m.index_digest
        || hash_value(b"gem.auth.v3.raw-provenance.1", &s.raw_bits)? != m.raw_digest
        || hash_value(b"gem.auth.v3.source-ids.1", &sources)? != m.source_ids_digest
        || hash_value(
            b"gem.auth.v3.snapshot.1",
            &(
                m.index_digest,
                m.raw_digest,
                m.source_ids_digest,
                m.provenance_digest,
            ),
        )? != m.snapshot_id
    {
        return Err(GemError::HashMismatch);
    }
    if s.index.dimension != m.dimension
        || s.index.max_doc_tokens != m.max_doc_tokens
        || s.index.semantic_profile != m.semantic_profile
        || s.index.graph_params != m.graph_params
        || public_digests(&s.public)? != [m.fine_digest, m.coarse_digest, m.entry_digest]
        || s.public.entries != s.index.cluster_entries
        || decode_fp16_v3(&s.public.fine_bits)?
            .iter()
            .map(|v| v.to_bits())
            .collect::<Vec<_>>()
            != s.index
                .fine_centroids
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>()
        || s.public.coarse_bits
            != s.index
                .coarse_centroids
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>()
    {
        return Err(GemError::InvalidManifest);
    }
    let mut leaves = Vec::new();
    let mut tokens = 0u64;
    for (id, (meta, d)) in s.metadata.iter().zip(&s.index.documents).enumerate() {
        if meta.doc_id as usize != id
            || meta.token_count != d.token_count
            || s.raw_bits[id].len() != usize::from(meta.token_count) * usize::from(m.dimension)
        {
            return Err(GemError::InvalidManifest);
        }
        decode_fp16_v3(&s.raw_bits[id])?;
        tokens += u64::from(meta.token_count);
        let h = [
            component_hash_v3(meta, 0, meta)?,
            component_hash_v3(meta, 1, &d.cluster_ids)?,
            component_hash_v3(meta, 2, &d.compact_codes)?,
            component_hash_v3(meta, 3, &d.adjacency)?,
            component_hash_v3(meta, 4, &s.raw_bits[id])?,
        ];
        if h != s.component_hashes[id] {
            return Err(GemError::HashMismatch);
        }
        leaves.push(document_leaf_v3(&h));
    }
    if tokens != m.token_count
        || DocumentTreeV3::build(&leaves)? != *s.tree
        || s.tree.root()? != m.document_root
    {
        return Err(GemError::MerkleRootMismatch);
    }
    authenticate_public_data_v3(&s.trusted, (*s.public).clone())?;
    Ok(())
}
