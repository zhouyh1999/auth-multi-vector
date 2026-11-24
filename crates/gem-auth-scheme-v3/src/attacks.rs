//! Directed attacks against actual serialized VOs; independent from acceptance status markers.
use super::*;
use gem_auth_v3::{ComponentOpening, RawOpeningV3};
use gem_core::{GemError, Result};
use serde::Serialize;
#[derive(Clone, Debug, Serialize)]
pub struct SchemeAttackOutcomeV3 {
    pub name: String,
    pub rejected: bool,
    pub error: String,
}
pub fn attack_scheme_retrieval_v3(
    t: &TrustedSchemeSnapshotV3,
    r: &SchemeRequestV3,
    bytes: &[u8],
) -> Result<Vec<SchemeAttackOutcomeV3>> {
    verify_scheme_retrieval_v3(t, r, bytes)?;
    let v = decode_scheme_vo_v3(bytes, t)?;
    let mut variants = Vec::new();
    let mut b = bytes.to_vec();
    b.pop();
    variants.push(("truncation", b));
    b = bytes.to_vec();
    b.push(0);
    variants.push(("trailing_bytes", b));
    b = bytes.to_vec();
    b[8] = 255;
    variants.push(("unknown_schema", b));
    b = bytes.to_vec();
    b[10..18].fill(255);
    variants.push(("malicious_frame_length", b));
    b = bytes.to_vec();
    b[18] = 255;
    variants.push(("unknown_backend", b));
    b = bytes.to_vec();
    b[19] = 255;
    variants.push(("unknown_mode", b));
    let mut bad;
    if !v.documents.is_empty() {
        bad = v.clone();
        bad.documents[0].metadata.token_count ^= 1;
        let tokens = usize::from(bad.documents[0].metadata.token_count);
        if let ComponentOpening::Revealed(codes) = &mut bad.documents[0].codes {
            codes.resize(tokens, 0);
        }
        variants.push(("metadata_context", encode_scheme_vo_v3(&bad)?.0));
        bad = v.clone();
        bad.documents.pop();
        variants.push(("missing_document", encode_scheme_vo_v3(&bad)?.0));
        bad = v.clone();
        bad.documents.push(v.documents[0].clone());
        variants.push((
            "duplicate_or_unsorted_document",
            encode_scheme_vo_v3(&bad)?.0,
        ));
        if let Some((i, doc)) = v
            .documents
            .iter()
            .enumerate()
            .find(|(_, d)| d.codes.is_revealed())
        {
            bad = v.clone();
            bad.documents[i].codes = ComponentOpening::Digest(backend_component_hash_v3(
                r.backend,
                &doc.metadata,
                2,
                doc.codes.revealed()?,
            )?);
            variants.push(("valid_hidden_required_codes", encode_scheme_vo_v3(&bad)?.0));
        }
        if let Some((i, doc)) = v
            .documents
            .iter()
            .enumerate()
            .find(|(_, d)| d.adjacency.is_revealed())
        {
            bad = v.clone();
            bad.documents[i].adjacency = ComponentOpening::Digest(backend_component_hash_v3(
                r.backend,
                &doc.metadata,
                3,
                doc.adjacency.revealed()?,
            )?);
            variants.push((
                "valid_hidden_required_adjacency",
                encode_scheme_vo_v3(&bad)?.0,
            ));
        }
    }
    if v.metrics.is_some() {
        bad = v.clone();
        bad.metrics
            .as_mut()
            .ok_or(GemError::InvalidManifest)?
            .coarse[0] ^= 1;
        variants.push(("coarse_table", encode_scheme_vo_v3(&bad)?.0));
        bad = v.clone();
        bad.metrics
            .as_mut()
            .ok_or(GemError::InvalidManifest)?
            .coarse_argument
            .projection[0] = [255; 32];
        variants.push(("noncanonical_projection", encode_scheme_vo_v3(&bad)?.0));
        if v.metrics.as_ref().is_some_and(|m| !m.fine.is_empty()) {
            bad = v.clone();
            bad.metrics.as_mut().ok_or(GemError::InvalidManifest)?.fine[0] ^= 1;
            variants.push(("fine_table", encode_scheme_vo_v3(&bad)?.0));
            bad = v.clone();
            let metric = bad.metrics.as_mut().ok_or(GemError::InvalidManifest)?;
            metric.fine_argument = Some(metric.coarse_argument.clone());
            variants.push(("cross_phase_proof", encode_scheme_vo_v3(&bad)?.0));
        }
    }
    if v.reranking.is_some() {
        bad = v.clone();
        bad.reranking
            .as_mut()
            .ok_or(GemError::InvalidManifest)?
            .similarities[0] ^= 1;
        variants.push(("complete_y", encode_scheme_vo_v3(&bad)?.0));
        bad = v.clone();
        bad.reranking
            .as_mut()
            .ok_or(GemError::InvalidManifest)?
            .argument
            .argument
            .push(0);
        variants.push(("argument_length_or_rounds", encode_scheme_vo_v3(&bad)?.0));
        let candidate_positions: Vec<_> = v
            .documents
            .iter()
            .enumerate()
            .filter_map(|(i, d)| d.vector.is_revealed().then_some(i))
            .collect();
        if candidate_positions.len() > 1 {
            bad = v.clone();
            // Candidate order now comes from canonical document openings, not a second list.
            bad.documents
                .swap(candidate_positions[0], candidate_positions[1]);
            variants.push(("candidate_order", encode_scheme_vo_v3(&bad)?.0));
        }
        bad = v.clone();
        bad.reranking = None;
        variants.push(("false_empty_candidates", encode_scheme_vo_v3(&bad)?.0));
        if let Some(i) = v.documents.iter().position(|d| d.vector.is_revealed()) {
            bad = v.clone();
            if let DocumentVectorOpeningV3::Commitment(ComponentOpening::Revealed(c)) =
                &mut bad.documents[i].vector
            {
                c.point = (gem_matrix_proof::canonical_point_v1(c.point)?
                    + curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT)
                    .compress()
                    .to_bytes();
            }
            variants.push(("document_commitment_binding", encode_scheme_vo_v3(&bad)?.0));
            bad = v.clone();
            if let DocumentVectorOpeningV3::Commitment(ComponentOpening::Revealed(c)) =
                &mut bad.documents[i].vector
            {
                c.point = [255; 32];
            }
            variants.push(("invalid_commitment_point", encode_scheme_vo_v3(&bad)?.0));
        }
    } else if let Some(i) = v.documents.iter().position(|d| d.vector.is_revealed()) {
        bad = v.clone();
        if let DocumentVectorOpeningV3::Raw(ComponentOpening::Revealed(raw)) =
            &mut bad.documents[i].vector
        {
            match raw {
                RawOpeningV3::Fp16(a) => a[0] ^= 1,
                RawOpeningV3::Fp32(a) => a[0] ^= 1,
            }
        }
        variants.push(("raw_coordinate", encode_scheme_vo_v3(&bad)?.0));
    }
    if !v.results.is_empty() {
        bad = v.clone();
        bad.results[0].distance.0 ^= 1;
        variants.push(("integer_result", encode_scheme_vo_v3(&bad)?.0));
    }
    // Full published-graph acceptance also exercises shared graph components,
    // complete candidate disclosure and malformed token boundaries.
    if !v.documents.is_empty() {
        let count = t.signed.manifest.source().document_count;
        bad = v.clone();
        bad.documents[0].metadata.doc_id = count;
        variants.push(("out_of_range_id", encode_scheme_vo_v3(&bad)?.0));
        bad = v.clone();
        if let ComponentOpening::Revealed(m) = &mut bad.documents[0].membership {
            if !m.is_empty() {
                m[0] = (m[0] + 1) % t.signed.manifest.source().coarse_count;
            }
        }
        variants.push(("tampered_membership", encode_scheme_vo_v3(&bad)?.0));
        if let Some(i) = v.documents.iter().position(|d| d.codes.is_revealed()) {
            bad = v.clone();
            if let ComponentOpening::Revealed(c) = &mut bad.documents[i].codes {
                if !c.is_empty() {
                    c[0] = t.signed.manifest.source().fine_count;
                }
            }
            variants.push(("tampered_codes", encode_scheme_vo_v3(&bad)?.0));
        }
        if let Some(i) = v
            .documents
            .iter()
            .position(|d| matches!(&d.adjacency,ComponentOpening::Revealed(a) if !a.is_empty()))
        {
            bad = v.clone();
            if let ComponentOpening::Revealed(a) = &mut bad.documents[i].adjacency {
                a[0] = (a[0] + 1) % count;
            }
            variants.push(("tampered_ordered_adjacency", encode_scheme_vo_v3(&bad)?.0));
        }
        if let Some(i) = v.documents.iter().position(|d| d.vector.is_revealed()) {
            bad = v.clone();
            bad.documents.remove(i);
            variants.push(("deleted_candidate", encode_scheme_vo_v3(&bad)?.0));
        }
        bad = v.clone();
        if let Some(y) = &mut bad.reranking {
            let queries = usize::from(r.query.token_count);
            let cols = y.similarities.len() / queries;
            if cols > 0 {
                for q in (0..queries).rev() {
                    y.similarities.remove(q * cols + cols - 1);
                }
            }
        } else if let Some(d) = bad.documents.iter_mut().find(|d| d.vector.is_revealed()) {
            let dim = usize::from(r.query.dimension);
            match &mut d.vector {
                DocumentVectorOpeningV3::Raw(ComponentOpening::Revealed(RawOpeningV3::Fp16(a))) => {
                    a.truncate(a.len().saturating_sub(dim))
                }
                DocumentVectorOpeningV3::Raw(ComponentOpening::Revealed(RawOpeningV3::Fp32(a))) => {
                    a.truncate(a.len().saturating_sub(dim))
                }
                _ => {}
            }
        }
        variants.push(("lost_token_row", encode_scheme_vo_v3(&bad)?.0));
    }
    bad = v.clone();
    if let Some(h) = bad.proof.siblings.first_mut() {
        h[0] ^= 1
    } else {
        bad.proof.siblings.push([0; 32])
    }
    variants.push(("bad_merkle_proof", encode_scheme_vo_v3(&bad)?.0));
    if v.results.len() > 1 {
        bad = v.clone();
        bad.results.reverse();
        variants.push(("forged_top_k", encode_scheme_vo_v3(&bad)?.0));
    }
    let mut out = Vec::new();
    for (name, bytes) in variants {
        record_rejection(&mut out, name, verify_scheme_retrieval_v3(t, r, &bytes))?;
    }
    // Global configuration is supplied outside the VO, but remains authenticated.
    let mut bad_trust = t.clone();
    bad_trust.owner_public_key[0] ^= 1;
    record_rejection(
        &mut out,
        "wrong_owner",
        verify_scheme_retrieval_v3(&bad_trust, r, bytes),
    )?;
    bad_trust = t.clone();
    bad_trust.signed.manifest.document_root[0] ^= 1;
    record_rejection(
        &mut out,
        "wrong_root",
        verify_scheme_retrieval_v3(&bad_trust, r, bytes),
    )?;
    let mut substituted = r.clone();
    substituted
        .query
        .coordinates
        .iter_mut()
        .for_each(|x| *x = -*x);
    if r.query.coordinates.iter().any(|&x| x != 0.) {
        record_rejection(
            &mut out,
            "query_substitution",
            verify_scheme_retrieval_v3(t, &substituted, bytes),
        )?;
    }
    bad_trust = t.clone();
    bad_trust.signed.manifest.numeric_profile.scale += 1;
    record_rejection(
        &mut out,
        "numeric_profile",
        verify_scheme_retrieval_v3(&bad_trust, r, bytes),
    )?;
    bad_trust = t.clone();
    bad_trust.signed.manifest.document_rows += 1;
    record_rejection(
        &mut out,
        "matrix_shape",
        verify_scheme_retrieval_v3(&bad_trust, r, bytes),
    )?;
    bad_trust = t.clone();
    bad_trust.signed.signature[0] ^= 1;
    record_rejection(
        &mut out,
        "signature",
        verify_scheme_retrieval_v3(&bad_trust, r, bytes),
    )?;
    let mut wrong = r.clone();
    wrong.manifest_digest[0] ^= 1;
    record_rejection(
        &mut out,
        "request_manifest_digest",
        verify_scheme_retrieval_v3(t, &wrong, bytes),
    )?;
    wrong = r.clone();
    wrong.query.params.ef_search = wrong.query.params.ef_search.wrapping_add(1);
    record_rejection(
        &mut out,
        "request_parameters",
        verify_scheme_retrieval_v3(t, &wrong, bytes),
    )?;
    if r.backend == SchemeBackendV3::MatrixScheme {
        // Matrix transcripts bind the original request bits even if quantization is unchanged.
        // Raw backends instead recompute the answer for the supplied query; equivalent
        // quantized queries can legitimately share an authenticated payload.
        wrong = r.clone();
        wrong.query.coordinates[0] = f32::from_bits(wrong.query.coordinates[0].to_bits() ^ 1);
        record_rejection(
            &mut out,
            "original_query_bits",
            verify_scheme_retrieval_v3(t, &wrong, bytes),
        )?;
    }
    Ok(out)
}
fn record_rejection(
    out: &mut Vec<SchemeAttackOutcomeV3>,
    name: &str,
    result: Result<VerifiedFixedRetrievalV3>,
) -> Result<()> {
    match result {
        Ok(_) => Err(GemError::InvalidMatrixProof(format!(
            "attack accepted: {name}"
        ))),
        Err(error) => {
            out.push(SchemeAttackOutcomeV3 {
                name: name.into(),
                rejected: true,
                error: error.to_string(),
            });
            Ok(())
        }
    }
}
