use super::numeric::*;
use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use gem_auth_v3::{
    DocumentTreeV3, MetadataV3, PreparedRawSnapshotV3, TrustedSnapshotV3, manifest_digest_v3,
    validate_prepared_snapshot_v3, validate_trusted_snapshot_v3,
};
use gem_core::{GemError, Hash, Result, hash_bytes};
use gem_matrix_proof::{
    GENERATOR_ID_V1, canonical_point_v1, generators_v1, supported_spring_source_hash_v1,
};
use rayon::prelude::*;
use std::time::Instant;
pub(crate) fn canonical<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    bincode::serialize(v).map_err(|e| GemError::Serialization(e.to_string()))
}
pub(crate) fn hash<T: serde::Serialize>(domain: &[u8], v: &T) -> Result<Hash> {
    gem_core::hash_serialized(domain, v)
}
pub fn scheme_manifest_digest_v3(m: &SchemeManifestV3) -> Result<Hash> {
    hash(MANIFEST_DOMAIN, m)
}
pub fn scheme_request_digest_v3(r: &SchemeRequestV3) -> Result<Hash> {
    hash(REQUEST_DOMAIN, r)
}
pub fn scheme_component_hash_v3<T: serde::Serialize>(
    meta: &MetadataV3,
    kind: u8,
    value: &T,
) -> Result<Hash> {
    let mut b = SCHEME_AUTH_SCHEMA_V3.to_le_bytes().to_vec();
    b.extend(canonical(&NumericProfile::default())?);
    b.push(kind);
    b.extend(canonical(meta)?);
    b.extend(canonical(value)?);
    Ok(hash_bytes(COMPONENT_DOMAIN, &b))
}
pub fn scheme_document_leaf_v3(hashes: &[Hash; 5]) -> Hash {
    let mut b = SCHEME_AUTH_SCHEMA_V3.to_le_bytes().to_vec();
    for h in hashes {
        b.extend(h);
    }
    hash_bytes(LEAF_DOMAIN, &b)
}
pub fn backend_component_hash_v3<T: serde::Serialize>(
    backend: SchemeBackendV3,
    meta: &MetadataV3,
    kind: u8,
    value: &T,
) -> Result<Hash> {
    match backend {
        SchemeBackendV3::MatrixScheme => scheme_component_hash_v3(meta, kind, value),
        SchemeBackendV3::FixedRawFp16 | SchemeBackendV3::FixedRawFp32 => {
            gem_auth_v3::component_hash_v3(meta, kind, value)
        }
    }
}
pub fn backend_document_leaf_v3(backend: SchemeBackendV3, hashes: &[Hash; 5]) -> Hash {
    match backend {
        SchemeBackendV3::MatrixScheme => scheme_document_leaf_v3(hashes),
        SchemeBackendV3::FixedRawFp16 | SchemeBackendV3::FixedRawFp32 => {
            gem_auth_v3::document_leaf_v3(hashes)
        }
    }
}
pub fn scheme_entries_digest_v3(entries: &[Option<u32>]) -> Result<Hash> {
    hash(ENTRIES_DOMAIN, &entries)
}
pub fn validate_trusted_scheme_snapshot_v3(t: &TrustedSchemeSnapshotV3) -> Result<()> {
    let m = &t.signed.manifest;
    let digest = scheme_manifest_digest_v3(m)?;
    if digest != t.expected_manifest_digest {
        return Err(GemError::HashMismatch);
    }
    VerifyingKey::from_bytes(&t.owner_public_key)
        .map_err(|_| GemError::InvalidSignature)?
        .verify_strict(
            &digest,
            &Signature::from_slice(&t.signed.signature).map_err(|_| GemError::InvalidSignature)?,
        )
        .map_err(|_| GemError::InvalidSignature)?;
    validate_trusted_snapshot_v3(&TrustedSnapshotV3 {
        owner_public_key: t.owner_public_key,
        expected_manifest_digest: manifest_digest_v3(m.source())?,
        signed: m.source.clone(),
    })?;
    m.numeric_profile.validate()?;
    if m.authentication_schema != SCHEME_AUTH_SCHEMA_V3
        || m.document_rows != m.source().max_doc_tokens
        || m.generator_id != GENERATOR_ID_V1
        || !supported_spring_source_hash_v1(&m.spring_source_hash)
    {
        return Err(GemError::InvalidManifest);
    }
    for rows in [
        usize::from(m.document_rows),
        m.source().fine_count as usize,
        m.source().coarse_count as usize,
    ] {
        let n = rows
            .checked_mul(usize::from(m.source().dimension))
            .ok_or(GemError::NumericOverflow)?;
        gem_matrix_proof::projection_argument_bytes_v1(n)?;
        if n > gem_matrix_proof::MAX_PROJECTION_DIMENSION_V1 {
            return Err(GemError::FrameTooLarge);
        }
    }
    canonical_point_v1(m.coarse_commitment)?;
    canonical_point_v1(m.fine_commitment)?;
    Ok(())
}
pub(crate) fn padded_document(s: &PreparedSchemeSnapshotV3, id: usize) -> Result<Vec<Coordinate>> {
    let m = &s.trusted.signed.manifest;
    let n = usize::from(m.document_rows) * usize::from(m.source().dimension);
    let a = s.fixed_documents.get(id).ok_or(GemError::InvalidManifest)?;
    if a.len() != usize::from(s.metadata[id].token_count) * usize::from(m.source().dimension)
        || a.len() > n
    {
        return Err(GemError::InvalidTokenCount);
    }
    let mut out = a.clone();
    out.resize(n, 0);
    Ok(out)
}
pub fn prepare_scheme_snapshot_v3(
    raw: PreparedRawSnapshotV3,
    key: &SigningKey,
) -> Result<(PreparedSchemeSnapshotV3, SchemeTimingsV3)> {
    let total = Instant::now();
    let mut timings = SchemeTimingsV3::default();
    let now = Instant::now();
    validate_prepared_snapshot_v3(&raw)?;
    if raw.trusted.owner_public_key != key.verifying_key().to_bytes() {
        return Err(GemError::InvalidSignature);
    }
    timings.record("source_validation", now);
    let now = Instant::now();
    let fixed_documents = raw
        .raw_bits
        .par_iter()
        .map(|bits| fixed_fp16_v1(bits))
        .collect::<Result<Vec<_>>>()?;
    let fine_fixed = fixed_fp16_v1(&raw.public.fine_bits)?;
    let coarse_fixed = fixed_coordinates_v1(
        &raw.public
            .coarse_bits
            .iter()
            .map(|&b| f32::from_bits(b))
            .collect::<Vec<_>>(),
    )?;
    let d = usize::from(raw.index.dimension);
    let fixed_documents_digest = hash(DOCUMENTS_DOMAIN, &fixed_documents)?;
    timings.record("fixed_conversion", now);
    let now = Instant::now();
    for n in [
        usize::from(raw.index.max_doc_tokens) * d,
        fine_fixed.len(),
        coarse_fixed.len(),
    ] {
        generators_v1(n)?;
    }
    timings.record("generators", now);
    let now = Instant::now();
    let commitments = fixed_documents
        .par_iter()
        .map(|a| {
            let mut padded = a.clone();
            padded.resize(usize::from(raw.index.max_doc_tokens) * d, 0);
            commit_matrix(&padded)
        })
        .collect::<Result<Vec<_>>>()?;
    timings.record("document_commitments", now);
    let now = Instant::now();
    let coarse_commitment = commit_matrix(&coarse_fixed)?;
    let fine_commitment = commit_matrix(&fine_fixed)?;
    timings.record("centroid_commitments", now);
    let now = Instant::now();
    let component_hashes = raw
        .metadata
        .par_iter()
        .enumerate()
        .map(|(id, m)| {
            let doc = &raw.index.documents[id];
            Ok([
                scheme_component_hash_v3(m, 0, m)?,
                scheme_component_hash_v3(m, 1, &doc.cluster_ids)?,
                scheme_component_hash_v3(m, 2, &doc.compact_codes)?,
                scheme_component_hash_v3(m, 3, &doc.adjacency)?,
                scheme_component_hash_v3(m, 5, &DocumentMatrixCommitmentV3::new(commitments[id]))?,
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    let tree = DocumentTreeV3::build(
        &component_hashes
            .iter()
            .map(scheme_document_leaf_v3)
            .collect::<Vec<_>>(),
    )?;
    timings.record("components_mht", now);
    let now = Instant::now();
    let manifest = SchemeManifestV3::new(
        raw.trusted.signed.clone(),
        tree.root()?,
        fixed_documents_digest,
        raw.index.max_doc_tokens,
        [coarse_commitment, fine_commitment],
        scheme_entries_digest_v3(&raw.public.entries)?,
    );
    let digest = scheme_manifest_digest_v3(&manifest)?;
    let trusted = TrustedSchemeSnapshotV3 {
        owner_public_key: key.verifying_key().to_bytes(),
        expected_manifest_digest: digest,
        signed: SignedSchemeManifestV3 {
            manifest,
            signature: key.sign(&digest).to_bytes().to_vec(),
        },
    };
    validate_trusted_scheme_snapshot_v3(&trusted)?;
    timings.record("signing", now);
    timings.finish(total);
    Ok((
        PreparedSchemeSnapshotV3::from_parts(
            trusted,
            raw,
            fixed_documents,
            [coarse_fixed, fine_fixed],
            commitments,
            (component_hashes, tree),
        ),
        timings,
    ))
}
/// Rebuild signed components and source provenance without redoing every offline MSM.
/// Online loading trusts the pinned owner's matrix commitments, never serialized validation flags.
pub(crate) fn validate_scheme_structure(s: &PreparedSchemeSnapshotV3) -> Result<()> {
    validate_trusted_scheme_snapshot_v3(&s.trusted)?;
    let m = &s.trusted.signed.manifest;
    let n = m.source().document_count as usize;
    if [
        s.metadata.len(),
        s.source_ids.len(),
        s.raw_bits.len(),
        s.fixed_documents.len(),
        s.commitments.len(),
        s.component_hashes.len(),
        s.raw_component_hashes.len(),
        s.index.documents.len(),
    ]
    .iter()
    .any(|&x| x != n)
    {
        return Err(GemError::InvalidManifest);
    }
    let raw_components = s
        .metadata
        .iter()
        .enumerate()
        .map(|(id, meta)| {
            let doc = &s.index.documents[id];
            Ok([
                gem_auth_v3::component_hash_v3(meta, 0, meta)?,
                gem_auth_v3::component_hash_v3(meta, 1, &doc.cluster_ids)?,
                gem_auth_v3::component_hash_v3(meta, 2, &doc.compact_codes)?,
                gem_auth_v3::component_hash_v3(meta, 3, &doc.adjacency)?,
                gem_auth_v3::component_hash_v3(meta, 4, &s.raw_bits[id])?,
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    let raw_tree = DocumentTreeV3::build(
        &raw_components
            .iter()
            .map(gem_auth_v3::document_leaf_v3)
            .collect::<Vec<_>>(),
    )?;
    if raw_components != s.raw_component_hashes || raw_tree != s.raw_tree {
        return Err(GemError::MerkleRootMismatch);
    }
    let trusted = TrustedSnapshotV3 {
        owner_public_key: s.trusted.owner_public_key,
        expected_manifest_digest: manifest_digest_v3(m.source())?,
        signed: m.source.clone(),
    };
    gem_auth_v3::validate_raw_snapshot_view_v3(gem_auth_v3::RawSnapshotViewV3 {
        trusted: &trusted,
        public: &s.public,
        index: &s.index,
        metadata: &s.metadata,
        source_ids: &s.source_ids,
        raw_bits: &s.raw_bits,
        component_hashes: &raw_components,
        tree: &raw_tree,
    })?;
    if hash(DOCUMENTS_DOMAIN, &s.fixed_documents)? != m.fixed_documents_digest
        || scheme_entries_digest_v3(&s.public.entries)? != m.entries_digest
    {
        return Err(GemError::HashMismatch);
    }
    if s.fine_fixed != fixed_fp16_v1(&s.public.fine_bits)?
        || s.coarse_fixed
            != fixed_coordinates_v1(
                &s.public
                    .coarse_bits
                    .iter()
                    .map(|&b| f32::from_bits(b))
                    .collect::<Vec<_>>(),
            )?
    {
        return Err(GemError::HashMismatch);
    }
    for (id, meta) in s.metadata.iter().enumerate() {
        padded_document(s, id)?;
        canonical_point_v1(s.commitments[id])?;
        let doc = &s.index.documents[id];
        let hashes = [
            scheme_component_hash_v3(meta, 0, meta)?,
            scheme_component_hash_v3(meta, 1, &doc.cluster_ids)?,
            scheme_component_hash_v3(meta, 2, &doc.compact_codes)?,
            scheme_component_hash_v3(meta, 3, &doc.adjacency)?,
            scheme_component_hash_v3(meta, 5, &DocumentMatrixCommitmentV3::new(s.commitments[id]))?,
        ];
        if hashes != s.component_hashes[id] {
            return Err(GemError::HashMismatch);
        }
    }
    let tree = DocumentTreeV3::build(
        &s.component_hashes
            .iter()
            .map(scheme_document_leaf_v3)
            .collect::<Vec<_>>(),
    )?;
    if tree != s.tree || tree.root()? != m.document_root {
        return Err(GemError::MerkleRootMismatch);
    }
    Ok(())
}
/// Deep offline acceptance: independently recompute fixed conversions and every commitment.
pub fn validate_scheme_snapshot_v3(s: &PreparedSchemeSnapshotV3) -> Result<()> {
    validate_scheme_structure(s)?;
    let checks = s
        .fixed_documents
        .par_iter()
        .enumerate()
        .map(|(id, a)| {
            if *a != fixed_fp16_v1(&s.raw_bits[id])?
                || commit_matrix(&padded_document(s, id)?)? != s.commitments[id]
            {
                return Err(GemError::HashMismatch);
            }
            Ok(())
        })
        .collect::<Result<Vec<_>>>()?;
    drop(checks);
    let m = &s.trusted.signed.manifest;
    if commit_matrix(&s.coarse_fixed)? != m.coarse_commitment
        || commit_matrix(&s.fine_fixed)? != m.fine_commitment
    {
        return Err(GemError::HashMismatch);
    }
    Ok(())
}
