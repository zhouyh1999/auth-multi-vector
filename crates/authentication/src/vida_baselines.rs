use super::*;

// Controlled protocol port on the same arithmetic, Spring backend and thread pool.
// SharedQuery preserves VIDA's shared-public-query restriction: one independent
// row-compression challenge and one d-dimensional proof per query token.
// QueryBatched is our rectangular-table extension, NOT the original VIDA protocol.
// Common statement hashing, cached generators, parallel MSM and i16 lookup-table
// accumulation are deliberately shared with the block benchmark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VidaMode {
    SharedQuery,
    QueryBatched,
}
impl VidaMode {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::SharedQuery => "vida_shared_query",
            Self::QueryBatched => "vida_query_batched",
        }
    }
}
pub(super) struct VidaPlan {
    pub(super) transcript: merlin::Transcript,
    pub(super) alpha: Vec<Scalar>,
    pub(super) beta: Vec<Scalar>,
    pub(super) coefficients: Vec<Scalar>,
    pub(super) token: usize,
}
pub(super) struct VidaBundle {
    pub(super) arguments: Vec<Vec<u8>>,
    pub(super) claims: Vec<[u8; 32]>,
}
pub(super) fn vida_powers(z: Scalar, n: usize) -> Vec<Scalar> {
    geometric_sequence(z, n, true)
}
pub(super) fn vida_challenge(t: &mut merlin::Transcript, label: &'static [u8]) -> Scalar {
    loop {
        let value = gem_matrix_proof::challenge_scalar_v1(t, label);
        if value != Scalar::ZERO {
            return value;
        }
        t.append_message(b"zero-retry", label);
    }
}
pub(super) fn vida_plans(
    w: &FairWork,
    c: &FairCase,
    q: &FixedQueryV3,
    binding: Hash,
    mode: VidaMode,
) -> Vec<VidaPlan> {
    let d = usize::from(q.source.dimension);
    let m = usize::from(q.source.token_count);
    let count = if mode == VidaMode::SharedQuery { m } else { 1 };
    (0..count)
        .into_par_iter()
        .map(|token| {
            let mut t = merlin::Transcript::new(b"gem.vida-adaptation.v1");
            // The digest fixes the entire ordered catalog, Q, table and numeric profile.
            // Compression of these public inputs changes the transcript encoding only.
            t.append_message(b"statement", &binding);
            t.append_message(b"mode", mode.label().as_bytes());
            t.append_message(b"stage", &[w.stage as u8]);
            t.append_u64(b"dimension", d as u64);
            t.append_u64(b"query-token", token as u64);
            let alpha = vida_powers(vida_challenge(&mut t, b"row-compression"), c.blocks.len());
            let beta = if mode == VidaMode::QueryBatched {
                // Independent challenge domain; never reuse row weights for this axis.
                vida_powers(vida_challenge(&mut t, b"query-compression"), m)
            } else {
                Vec::new()
            };
            let coefficients = if beta.is_empty() {
                q.coordinates[token * d..(token + 1) * d]
                    .iter()
                    .copied()
                    .map(scalar_coordinate)
                    .collect()
            } else {
                (0..d)
                    .map(|j| {
                        (0..m).fold(Scalar::ZERO, |sum, i| {
                            sum + beta[i] * scalar_coordinate(q.coordinates[i * d + j])
                        })
                    })
                    .collect()
            };
            VidaPlan {
                transcript: t,
                alpha,
                beta,
                coefficients,
                token,
            }
        })
        .collect()
}
/// Each token retains its own row weights. Four tokens share reads of each coordinate row.
pub(super) fn vida_per_token_witnesses(
    documents: &[Vec<Coordinate>],
    rows: &[PilotBlock],
    dimension: usize,
    plans: &[VidaPlan],
) -> Vec<Vec<Scalar>> {
    const TOKENS_PER_GROUP: usize = 4;
    const ROWS_PER_TILE: usize = 2048;
    let weights: Vec<_> = plans
        .par_iter()
        .map(|p| narrow_digits::<8>(&p.alpha))
        .collect();
    let groups = plans.len().div_ceil(TOKENS_PER_GROUP);
    let jobs = rows.len().div_ceil(ROWS_PER_TILE) * groups;
    let partials: Vec<_> = (0..jobs)
        .into_par_iter()
        .map(|job| {
            let start_row = (job / groups) * ROWS_PER_TILE;
            let first_token = (job % groups) * TOKENS_PER_GROUP;
            let tokens = TOKENS_PER_GROUP.min(plans.len() - first_token);
            // Each i64 accumulates at most 2048 products of a signed i16 and a u32.
            let mut sums = vec![[0_i64; 8]; tokens * dimension];
            for (offset, row) in rows[start_row..].iter().take(ROWS_PER_TILE).enumerate() {
                let start = row.offset * dimension;
                let coordinates = &documents[row.doc][start..start + dimension];
                for (token, output) in sums.chunks_exact_mut(dimension).enumerate() {
                    let digits = &weights[first_token + token][start_row + offset];
                    for (acc, &value) in output.iter_mut().zip(coordinates) {
                        for (limb, &digit) in acc.iter_mut().zip(digits) {
                            *limb += i64::from(value) * i64::from(digit);
                        }
                    }
                }
            }
            (first_token, sums)
        })
        .collect();
    let mut witnesses = vec![vec![Scalar::ZERO; dimension]; plans.len()];
    for (first_token, sums) in partials {
        for (witness, partial) in witnesses[first_token..]
            .iter_mut()
            .zip(sums.chunks_exact(dimension))
        {
            for (coordinate, digits) in witness.iter_mut().zip(partial) {
                *coordinate += reduce_signed_digits(digits);
            }
        }
    }
    witnesses
}

// A VIDA opening has exactly one genuine row per commitment. The authenticated
// catalog enumerates the documents and offsets in the same order as the received table.
pub(super) fn vida_fast_table_claim(w: &FairWork, plan: &VidaPlan) -> Scalar {
    let weights = wide_digits(&plan.alpha);
    let token_claim = |token: usize| {
        let mut sums = [0_i128; 4];
        let mut offset = 0;
        for (_, rows, table) in &w.matrices {
            let values = &table[token * rows..(token + 1) * rows];
            for (&value, weight) in values.iter().zip(&weights[offset..offset + rows]) {
                for (sum, limb) in sums.iter_mut().zip(weight) {
                    *sum += i128::from(value) * i128::from(*limb);
                }
            }
            offset += rows;
        }
        reduce_signed_digits(&sums)
    };
    if plan.beta.is_empty() {
        token_claim(plan.token)
    } else {
        plan.beta
            .par_iter()
            .enumerate()
            .map(|(token, beta)| beta * token_claim(token))
            .sum()
    }
}
pub(super) fn vida_inputs(
    point: [u8; 32],
    claim: Scalar,
    coefficients: &[Scalar],
) -> anyhow::Result<(
    bulletproofs::SpringLinearPublicInputs,
    curve25519_dalek::ristretto::CompressedRistretto,
)> {
    let ped = bulletproofs::PedersenGens::default();
    let statement = (canonical_point_v1(point)? + claim * ped.B).compress();
    let inputs = gem_matrix_proof::prepare_projection_generators_v1(coefficients.len())?
        .with_coefficients(coefficients)
        .map_err(|e| anyhow::anyhow!("VIDA inputs: {e:?}"))?;
    Ok((inputs, statement))
}
pub(super) fn vida_proofs(
    plans: &mut [VidaPlan],
    points: &[[u8; 32]],
    witnesses: Vec<Vec<Scalar>>,
) -> anyhow::Result<VidaBundle> {
    let pairs = plans
        .par_iter_mut()
        .zip(points.par_iter())
        .zip(witnesses.into_par_iter())
        .map(|((p, point), a)| -> anyhow::Result<(Vec<u8>, [u8; 32])> {
            // For an honest table this equals the weighted claims in VIDA.
            // Computing it from the aggregate avoids an unnecessary second table scan.
            // The verifier ALWAYS derives its claim independently from the supplied table.
            let claim = a.iter().zip(&p.coefficients).map(|(a, b)| a * b).sum();
            let (inputs, statement) = vida_inputs(*point, claim, &p.coefficients)?;
            let proof = bulletproofs::SpringLinearProof::create_with_public_inputs(
                &mut p.transcript,
                &mut OsRng,
                &statement,
                Scalar::ZERO,
                a,
                &inputs,
            )
            .map_err(|e| anyhow::anyhow!("VIDA prove: {e:?}"))?;
            Ok((proof.to_bytes(), claim.to_bytes()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let (arguments, claims) = pairs.into_iter().unzip();
    Ok(VidaBundle { arguments, claims })
}
pub(super) fn vida_verify_proofs(
    plans: &mut [VidaPlan],
    points: &[[u8; 32]],
    claims: &[Scalar],
    bundle: &VidaBundle,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        plans.len() == bundle.arguments.len()
            && bundle.claims.len() == plans.len()
            && points.len() == plans.len()
            && claims.len() == plans.len(),
        "VIDA proof count"
    );
    // Keep the scalar claim carried by VIDA's AggregatedIpaProof record and
    // account for all 32 bytes per proof, even though the table determines it.
    for (encoded, expected) in bundle.claims.iter().zip(claims) {
        anyhow::ensure!(
            gem_matrix_proof::canonical_scalar_v1(*encoded)? == *expected,
            "VIDA claimed scalar mismatch"
        );
    }
    plans
        .par_iter_mut()
        .zip(points.par_iter())
        .zip(claims.par_iter())
        .zip(bundle.arguments.par_iter())
        .try_for_each(|(((p, point), claim), bytes)| -> anyhow::Result<()> {
            let (inputs, statement) = vida_inputs(*point, *claim, &p.coefficients)?;
            let proof = bulletproofs::SpringLinearProof::from_bytes_for_dimension(
                bytes,
                p.coefficients.len(),
            )
            .map_err(|e| anyhow::anyhow!("VIDA proof encoding: {e:?}"))?;
            proof
                .verify_with_public_inputs(&mut p.transcript, &statement, &inputs)
                .map_err(|e| anyhow::anyhow!("VIDA verify: {e:?}"))?;
            Ok(())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_token_witness_matches_field_sum_across_group_and_tile_tails() {
        let lengths = [1027, 1022];
        let mut documents = Vec::new();
        let mut rows = Vec::new();
        for (doc, &len) in lengths.iter().enumerate() {
            let mut coords = Vec::new();
            for offset in 0..len {
                coords.extend([i16::MIN, (doc * len + offset) as i16, i16::MAX]);
                rows.push(PilotBlock {
                    doc,
                    id: doc as u32,
                    offset,
                    len: 1,
                });
            }
            documents.push(coords);
        }
        let plans: Vec<_> = (0..5)
            .map(|token| VidaPlan {
                alpha: vida_powers(-Scalar::from(token as u64 + 2), rows.len()),
                transcript: merlin::Transcript::new(b"test"),
                beta: vec![],
                coefficients: vec![],
                token,
            })
            .collect();
        let witnesses = vida_per_token_witnesses(&documents, &rows, 3, &plans);
        assert_eq!(witnesses.len(), plans.len());
        for (plan, witness) in plans.iter().zip(witnesses) {
            let mut expected = [Scalar::ZERO; 3];
            for (row, weight) in rows.iter().zip(&plan.alpha) {
                let start = row.offset * 3;
                for (sum, &value) in expected
                    .iter_mut()
                    .zip(&documents[row.doc][start..start + 3])
                {
                    *sum += weight * scalar_coordinate(value);
                }
            }
            assert_eq!(witness, expected);
        }
    }
}
