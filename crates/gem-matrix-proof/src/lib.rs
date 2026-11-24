#![forbid(unsafe_code)]
//! Non-ZK projection arguments. Spring mathematics and internal transcript stay unchanged.
#[cfg(test)]
use bulletproofs::BulletproofGens;
use bulletproofs::{
    PedersenGens, SpringLinearPreparedWitness, SpringLinearProof, SpringLinearPublicInputs,
    spring_generators,
};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use gem_core::{FIXED_PROFILE_ID_V1, GemError, Hash, Result};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

#[cfg(test)]
mod parallel_tests;

/// Audited protocol reference, fixed in the v1 projection transcript. Exact
/// execution optimizations do not change this transcript domain identifier.
pub const SPRING_SOURCE_HASH_V1: &str =
    "404322911ead3b7b0aee331f9ee3eb45d4c4bbc25d21db00a0a111b08f5c88d1";
/// Current vendored execution source; new owner manifests bind this hash.
pub const SPRING_IMPLEMENTATION_HASH_V1: &str =
    "de7e0afba75555cee574af0cd3883c861e5e5bf54ee92e065f28c7b6484ae417";
/// First parallel implementation, retained for already signed owner snapshots.
pub const SPRING_PARALLEL_V1_SOURCE_HASH: &str =
    "80c48e32466cc12ebeedb7a126598c6a2145323f9eb4f9256dcc776b84d3285d";
/// Second execution implementation, retained for signed snapshots.
pub const SPRING_PARALLEL_V2_SOURCE_HASH: &str =
    "cd711035f35b8bed4a88b2a5ad14472cfa88f07179ec34183269854ce9618963";
/// Third execution implementation, retained for signed snapshots.
pub const SPRING_PARALLEL_V3_SOURCE_HASH: &str =
    "d736409e0a2b8f899ce53ef1226196ad67cd908e021deb4e699426e4de4a0d37";
/// Fourth execution implementation, retained for existing signed snapshots.
pub const SPRING_PARALLEL_V4_SOURCE_HASH: &str =
    "a374b3f0c133f423a85f23f03d4b809cff634894f8963f96d6b4ead1007fe7af";
/// Fifth execution implementation, retained for existing signed snapshots.
pub const SPRING_PARALLEL_V5_SOURCE_HASH: &str =
    "99798452340a9bc179671d6068c36dea63fa79fa5f8d14c8460918cdd27f7742";
pub fn supported_spring_source_hash_v1(hash: &str) -> bool {
    hash == SPRING_SOURCE_HASH_V1
        || hash == SPRING_PARALLEL_V1_SOURCE_HASH
        || hash == SPRING_PARALLEL_V2_SOURCE_HASH
        || hash == SPRING_PARALLEL_V3_SOURCE_HASH
        || hash == SPRING_PARALLEL_V4_SOURCE_HASH
        || hash == SPRING_PARALLEL_V5_SOURCE_HASH
        || hash == SPRING_IMPLEMENTATION_HASH_V1
}
pub const GENERATOR_ID_V1: &str = "bulletproofs5-shake256-generators-share0-G-prefix-row-major-v1";
type GeneratorCache = Mutex<BTreeMap<usize, Arc<Vec<RistrettoPoint>>>>;
static GENERATORS: OnceLock<GeneratorCache> = OnceLock::new();
type PublicGeneratorCache = Mutex<BTreeMap<usize, Arc<SpringLinearPublicInputs>>>;
static PUBLIC_GENERATORS: OnceLock<PublicGeneratorCache> = OnceLock::new();
/// Cache immutable points and encodings; coefficients remain request-specific.
pub fn prepare_projection_generators_v1(n: usize) -> Result<Arc<SpringLinearPublicInputs>> {
    let cache = PUBLIC_GENERATORS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut lock = cache.lock().map_err(proof_error)?;
    if let Some(inputs) = lock.get(&n) {
        return Ok(Arc::clone(inputs));
    }
    let g = generators_v1(n)?;
    let ped = PedersenGens::default();
    let template = Arc::new(
        SpringLinearPublicInputs::new_with_shared_generators(
            vec![Scalar::ZERO; n],
            Arc::clone(&g),
            &ped.B,
            &ped.B_blinding,
        )
        .map_err(proof_error)?,
    );
    lock.insert(n, Arc::clone(&template));
    Ok(template)
}
fn proof_error(e: impl std::fmt::Display) -> GemError {
    GemError::InvalidMatrixProof(e.to_string())
}
pub fn scalar_i32_v1(x: i32) -> Scalar {
    if x >= 0 {
        Scalar::from(x as u64)
    } else {
        -Scalar::from(u64::from(x.unsigned_abs()))
    }
}
pub fn scalar_i64_v1(x: i64) -> Scalar {
    if x >= 0 {
        Scalar::from(x as u64)
    } else {
        -Scalar::from(x.unsigned_abs())
    }
}
pub fn canonical_scalar_v1(b: [u8; 32]) -> Result<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(b))
        .ok_or_else(|| proof_error("noncanonical Scalar"))
}
pub fn canonical_point_v1(b: [u8; 32]) -> Result<RistrettoPoint> {
    CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| proof_error("invalid Ristretto encoding"))
}
pub fn projection_argument_bytes_v1(dimension: usize) -> Result<usize> {
    Ok((2 * SpringLinearProof::expected_rounds(dimension).map_err(proof_error)? + 3) * 32)
}
pub fn validate_projection_argument_v1(bytes: &[u8], dimension: usize) -> Result<()> {
    SpringLinearProof::from_bytes_for_dimension(bytes, dimension).map_err(proof_error)?;
    Ok(())
}
/// Offline and online allocations are bounded independently of VO byte limits.
/// Full published fine codebook: 262144 rows times 128 coordinates.
pub const MAX_PROJECTION_DIMENSION_V1: usize = 1 << 25;
pub fn generators_v1(n: usize) -> Result<Arc<Vec<RistrettoPoint>>> {
    projection_argument_bytes_v1(n)?;
    // Protocol/owner dimension limit: also bound locally constructed generator allocations.
    if n > MAX_PROJECTION_DIMENSION_V1 {
        return Err(GemError::FrameTooLarge);
    }
    let cache = GENERATORS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut lock = cache.lock().map_err(proof_error)?;
    if let Some(g) = lock.get(&n) {
        return Ok(Arc::clone(g));
    }
    let g = Arc::new(spring_generators(n));
    lock.insert(n, Arc::clone(&g));
    Ok(g)
}
pub fn commit_scalars_v1(a: &[Scalar]) -> Result<[u8; 32]> {
    let g = generators_v1(a.len())?;
    Ok(RistrettoPoint::vartime_multiscalar_mul(a.iter(), g.iter())
        .compress()
        .to_bytes())
}
pub fn commit_i32_matrix_v1(a: &[i32]) -> Result<[u8; 32]> {
    let g = generators_v1(a.len())?;
    Ok(
        RistrettoPoint::vartime_multiscalar_mul(a.iter().copied().map(scalar_i32_v1), g.iter())
            .compress()
            .to_bytes(),
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProjectionStageV1 {
    Coarse = 0,
    Fine = 1,
    Reranking = 2,
}
#[derive(Clone, Debug)]
pub struct ProjectionContextV1 {
    /// Digest of the complete protocol statement: request, table/Y, IDs, lengths and commitments.
    pub binding: Hash,
    pub stage: ProjectionStageV1,
    pub rows: usize,
    pub columns: usize,
    pub commitment: [u8; 32],
}
impl ProjectionContextV1 {
    pub fn dimension(&self) -> Result<usize> {
        if self.rows == 0 || self.columns == 0 {
            return Err(GemError::InvalidTokenCount);
        }
        let n = self
            .rows
            .checked_mul(self.columns)
            .ok_or(GemError::NumericOverflow)?;
        projection_argument_bytes_v1(n)?;
        if n > MAX_PROJECTION_DIMENSION_V1 {
            return Err(GemError::FrameTooLarge);
        }
        Ok(n)
    }
    #[cfg(test)]
    fn transcript(&self) -> Result<Transcript> {
        self.transcript_profile(FIXED_PROFILE_ID_V1)
    }
    fn transcript_profile(&self, profile: &str) -> Result<Transcript> {
        self.dimension()?;
        canonical_point_v1(self.commitment)?;
        let mut t = Transcript::new(b"gem.matrix-projection.non-zk.v1");
        t.append_message(b"profile", profile.as_bytes());
        t.append_message(b"generator", GENERATOR_ID_V1.as_bytes());
        t.append_message(b"spring-source", SPRING_SOURCE_HASH_V1.as_bytes());
        t.append_message(b"stage", &[self.stage as u8]);
        t.append_message(b"statement-digest", &self.binding);
        t.append_u64(b"rows", self.rows as u64);
        t.append_u64(b"columns", self.columns as u64);
        t.append_message(b"matrix-commitment", &self.commitment);
        Ok(t)
    }
}
pub fn challenge_scalar_v1(t: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut bytes = [0u8; 64];
    t.challenge_bytes(label, &mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}
fn challenges(t: &mut Transcript, label: &'static [u8], n: usize) -> Vec<Scalar> {
    (0..n)
        .map(|i| {
            t.append_u64(b"challenge-index", i as u64);
            challenge_scalar_v1(t, label)
        })
        .collect()
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionArgumentV1 {
    pub projection: Vec<[u8; 32]>,
    pub argument: Vec<u8>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProjectionTimingsV1 {
    pub projection_ms: f64,
    pub public_inputs_ms: f64,
    pub ipa_ms: f64,
}
pub struct VerifiedProjectionV1 {
    rows: Vec<Scalar>,
    projection: Vec<Scalar>,
}
impl VerifiedProjectionV1 {
    pub fn row_challenges(&self) -> &[Scalar] {
        &self.rows
    }
    pub fn projection(&self) -> &[Scalar] {
        &self.projection
    }
}
fn public_inputs(
    ctx: &ProjectionContextV1,
    r: &[Scalar],
    s: &[Scalar],
    u: &[Scalar],
) -> Result<(SpringLinearPublicInputs, CompressedRistretto)> {
    let b: Vec<_> = r
        .par_iter()
        .flat_map_iter(|x| s.iter().map(move |y| x * y))
        .collect();
    let ped = PedersenGens::default();
    let v = u
        .iter()
        .zip(s)
        .fold(Scalar::ZERO, |sum, (x, y)| sum + x * y);
    let statement = (canonical_point_v1(ctx.commitment)? + v * ped.B).compress();
    let inputs = prepare_projection_generators_v1(ctx.dimension()?)?
        .with_owned_coefficients(b)
        .map_err(proof_error)?;
    Ok((inputs, statement))
}
pub fn prove_projection_v1<R: RngCore + CryptoRng>(
    ctx: &ProjectionContextV1,
    witness: &[Scalar],
    rng: &mut R,
) -> Result<(ProjectionArgumentV1, ProjectionTimingsV1)> {
    prove_projection_with_profile_v1(FIXED_PROFILE_ID_V1, ctx, witness, rng)
}
pub fn prove_projection_with_profile_v1<R: RngCore + CryptoRng>(
    profile: &str,
    ctx: &ProjectionContextV1,
    witness: &[Scalar],
    rng: &mut R,
) -> Result<(ProjectionArgumentV1, ProjectionTimingsV1)> {
    prove_projection_internal(profile, ctx, witness, None, rng)
}
/// Immutable preprocessing for a fixed centroid matrix, local to its server snapshot.
#[derive(Debug)]
pub struct PreparedProjectionWitnessV1 {
    prepared: SpringLinearPreparedWitness,
    commitment: [u8; 32],
}
impl PreparedProjectionWitnessV1 {
    pub fn new(witness: Vec<Scalar>) -> Result<Self> {
        let inputs = prepare_projection_generators_v1(witness.len())?;
        let g = generators_v1(witness.len())?;
        let tasks = rayon::current_num_threads().saturating_mul(4).clamp(1, 32);
        let chunk = witness.len().div_ceil(tasks).max(8192);
        let commitment = witness
            .par_chunks(chunk)
            .zip(g.par_chunks(chunk))
            .map(|(a, g)| RistrettoPoint::vartime_multiscalar_mul(a.iter(), g.iter()))
            .reduce(RistrettoPoint::default, |a, b| a + b)
            .compress()
            .to_bytes();
        let prepared = SpringLinearPreparedWitness::new(witness, &inputs).map_err(proof_error)?;
        Ok(Self {
            prepared,
            commitment,
        })
    }
}
pub fn prove_projection_with_prepared_witness_v1<R: RngCore + CryptoRng>(
    profile: &str,
    ctx: &ProjectionContextV1,
    prepared: &PreparedProjectionWitnessV1,
    rng: &mut R,
) -> Result<(ProjectionArgumentV1, ProjectionTimingsV1)> {
    if ctx.commitment != prepared.commitment {
        return Err(proof_error("prepared witness commitment"));
    }
    prove_projection_internal(
        profile,
        ctx,
        prepared.prepared.witness(),
        Some(&prepared.prepared),
        rng,
    )
}
fn prove_projection_internal<R: RngCore + CryptoRng>(
    profile: &str,
    ctx: &ProjectionContextV1,
    witness: &[Scalar],
    prepared: Option<&SpringLinearPreparedWitness>,
    rng: &mut R,
) -> Result<(ProjectionArgumentV1, ProjectionTimingsV1)> {
    if witness.len() != ctx.dimension()? {
        return Err(proof_error("witness shape"));
    }
    let mut t = ctx.transcript_profile(profile)?;
    let r = challenges(&mut t, b"row-challenge", ctx.rows);
    let started = Instant::now();
    let u: Vec<_> = (0..ctx.columns)
        .into_par_iter()
        .map(|k| {
            (0..ctx.rows).fold(Scalar::ZERO, |sum, j| {
                sum + witness[j * ctx.columns + k] * r[j]
            })
        })
        .collect();
    let projection: Vec<_> = u.iter().map(Scalar::to_bytes).collect();
    // Every u coordinate is fixed before deriving the independent column compression.
    for value in &projection {
        t.append_message(b"projection-coordinate", value);
    }
    let s = challenges(&mut t, b"column-challenge", ctx.columns);
    let projection_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let (inputs, statement) = public_inputs(ctx, &r, &s, &u)?;
    let public_inputs_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let proof = if let Some(prepared) = prepared {
        SpringLinearProof::create_with_prepared_witness(
            &mut t,
            rng,
            &statement,
            Scalar::ZERO,
            prepared,
            &inputs,
        )
    } else {
        SpringLinearProof::create_with_public_inputs(
            &mut t,
            rng,
            &statement,
            Scalar::ZERO,
            witness.to_vec(),
            &inputs,
        )
    }
    .map_err(proof_error)?;
    Ok((
        ProjectionArgumentV1 {
            projection,
            argument: proof.to_bytes(),
        },
        ProjectionTimingsV1 {
            projection_ms,
            public_inputs_ms,
            ipa_ms: started.elapsed().as_secs_f64() * 1000.,
        },
    ))
}
pub fn verify_projection_v1(
    ctx: &ProjectionContextV1,
    p: &ProjectionArgumentV1,
) -> Result<(VerifiedProjectionV1, ProjectionTimingsV1)> {
    verify_projection_with_profile_v1(FIXED_PROFILE_ID_V1, ctx, p)
}
pub fn verify_projection_with_profile_v1(
    profile: &str,
    ctx: &ProjectionContextV1,
    p: &ProjectionArgumentV1,
) -> Result<(VerifiedProjectionV1, ProjectionTimingsV1)> {
    if p.projection.len() != ctx.columns {
        return Err(proof_error("projection length"));
    }
    let proof = SpringLinearProof::from_bytes_for_dimension(&p.argument, ctx.dimension()?)
        .map_err(proof_error)?;
    let started = Instant::now();
    let mut t = ctx.transcript_profile(profile)?;
    let r = challenges(&mut t, b"row-challenge", ctx.rows);
    let u = p
        .projection
        .iter()
        .copied()
        .map(canonical_scalar_v1)
        .collect::<Result<Vec<_>>>()?;
    for value in &p.projection {
        t.append_message(b"projection-coordinate", value);
    }
    let s = challenges(&mut t, b"column-challenge", ctx.columns);
    let projection_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let (inputs, statement) = public_inputs(ctx, &r, &s, &u)?;
    let public_inputs_ms = started.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    proof
        .verify_with_public_inputs(&mut t, &statement, &inputs)
        .map_err(proof_error)?;
    Ok((
        VerifiedProjectionV1 {
            rows: r,
            projection: u,
        },
        ProjectionTimingsV1 {
            projection_ms,
            public_inputs_ms,
            ipa_ms: started.elapsed().as_secs_f64() * 1000.,
        },
    ))
}
/// T is query-token-major (m by rows). Its integer values have already passed signed-range checks.
pub fn verify_freivalds_v1<Q: Copy + Into<i64> + Sync, T: Copy + Into<i64> + Sync>(
    query: &[Q],
    table: &[T],
    columns: usize,
    p: &VerifiedProjectionV1,
) -> Result<()> {
    if columns == 0
        || query.is_empty()
        || !query.len().is_multiple_of(columns)
        || table.len() != query.len() / columns * p.rows.len()
        || p.projection.len() != columns
    {
        return Err(proof_error("Freivalds shape"));
    }
    let check = |q: &[Q], row: &[T]| {
        let lhs = if row.len() >= 1024 && rayon::current_num_threads() > 1 {
            row.par_iter()
                .zip(p.rows.par_iter())
                .map(|(&x, r)| scalar_i64_v1(x.into()) * r)
                .reduce(|| Scalar::ZERO, |a, b| a + b)
        } else {
            row.iter().zip(&p.rows).fold(Scalar::ZERO, |sum, (&x, r)| {
                sum + scalar_i64_v1(x.into()) * r
            })
        };
        let rhs = q
            .iter()
            .zip(&p.projection)
            .fold(Scalar::ZERO, |sum, (&x, u)| {
                sum + scalar_i64_v1(x.into()) * u
            });
        if lhs != rhs {
            return Err(proof_error("Freivalds equality"));
        }
        Ok(())
    };
    if table.len() >= 1024 && rayon::current_num_threads() > 1 {
        query
            .par_chunks_exact(columns)
            .zip(table.par_chunks_exact(p.rows.len()))
            .try_for_each(|(q, row)| check(q, row))
    } else {
        query
            .chunks_exact(columns)
            .zip(table.chunks_exact(p.rows.len()))
            .try_for_each(|(q, row)| check(q, row))
    }
}
/// Independent document aggregation challenge space; binding includes all Yi and Ci before alpha.
pub fn document_weights_v1(binding: Hash, count: usize) -> Result<Vec<Scalar>> {
    document_weights_with_profile_v1(FIXED_PROFILE_ID_V1, binding, count)
}
pub fn document_weights_with_profile_v1(
    profile: &str,
    binding: Hash,
    count: usize,
) -> Result<Vec<Scalar>> {
    if count == 0 || count > u32::MAX as usize {
        return Err(proof_error("aggregation count"));
    }
    let mut t = Transcript::new(b"gem.document-aggregation.non-zk.v1");
    t.append_message(b"profile", profile.as_bytes());
    t.append_message(b"statement-digest", &binding);
    t.append_u64(b"document-count", count as u64);
    Ok(challenges(&mut t, b"document-weight", count))
}
pub fn aggregate_commitments_v1(commitments: &[[u8; 32]], weights: &[Scalar]) -> Result<[u8; 32]> {
    if commitments.is_empty() || commitments.len() != weights.len() {
        return Err(proof_error("aggregation length"));
    }
    let points = commitments
        .iter()
        .copied()
        .map(canonical_point_v1)
        .collect::<Result<Vec<_>>>()?;
    Ok(
        RistrettoPoint::vartime_multiscalar_mul(weights.iter(), points.iter())
            .compress()
            .to_bytes(),
    )
}
/// Aggregated Yi has field coefficients, so it must not pass through i64 serialization.
pub fn verify_aggregated_freivalds_v1<Q: Copy + Into<i64> + Sync>(
    query: &[Q],
    table: &[Scalar],
    columns: usize,
    p: &VerifiedProjectionV1,
) -> Result<()> {
    if columns == 0
        || query.is_empty()
        || !query.len().is_multiple_of(columns)
        || table.len() != query.len() / columns * p.rows.len()
        || p.projection.len() != columns
    {
        return Err(proof_error("aggregated shape"));
    }
    let check = |q: &[Q], row: &[Scalar]| {
        let lhs = if row.len() >= 1024 && rayon::current_num_threads() > 1 {
            row.par_iter()
                .zip(p.rows.par_iter())
                .map(|(x, r)| x * r)
                .reduce(|| Scalar::ZERO, |a, b| a + b)
        } else {
            row.iter()
                .zip(&p.rows)
                .fold(Scalar::ZERO, |sum, (x, r)| sum + x * r)
        };
        let rhs = q
            .iter()
            .zip(&p.projection)
            .fold(Scalar::ZERO, |sum, (&x, u)| {
                sum + scalar_i64_v1(x.into()) * u
            });
        if lhs != rhs {
            return Err(proof_error("aggregated Freivalds equality"));
        }
        Ok(())
    };
    if table.len() >= 1024 && rayon::current_num_threads() > 1 {
        query
            .par_chunks_exact(columns)
            .zip(table.par_chunks_exact(p.rows.len()))
            .try_for_each(|(q, row)| check(q, row))
    } else {
        query
            .chunks_exact(columns)
            .zip(table.chunks_exact(p.rows.len()))
            .try_for_each(|(q, row)| check(q, row))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    #[test]
    fn scalar_projection_and_strict_parser() {
        for (rows, cols) in [(1, 1), (3, 2), (7, 3), (8, 4)] {
            let a: Vec<_> = (0..rows * cols)
                .map(|x| scalar_i32_v1(x as i32 - 4))
                .collect();
            let ctx = ProjectionContextV1 {
                binding: [8; 32],
                stage: ProjectionStageV1::Fine,
                rows,
                columns: cols,
                commitment: commit_scalars_v1(&a).unwrap(),
            };
            let (p, _) = prove_projection_v1(&ctx, &a, &mut StdRng::seed_from_u64(99)).unwrap();
            verify_projection_v1(&ctx, &p).unwrap();
            assert_eq!(
                p.argument.len(),
                projection_argument_bytes_v1(rows * cols).unwrap()
            );
            let mut wrong = p.clone();
            wrong.projection[0] = Scalar::ONE.to_bytes();
            assert!(verify_projection_v1(&ctx, &wrong).is_err());
            for n in 0..p.argument.len() {
                assert!(validate_projection_argument_v1(&p.argument[..n], rows * cols).is_err());
            }
            wrong = p.clone();
            wrong.argument.push(0);
            assert!(verify_projection_v1(&ctx, &wrong).is_err());
            wrong = p.clone();
            wrong.projection[0] = [255; 32];
            assert!(verify_projection_v1(&ctx, &wrong).is_err());
            let mut c = ctx.clone();
            c.stage = ProjectionStageV1::Coarse;
            assert!(verify_projection_v1(&c, &p).is_err());
            c = ctx.clone();
            c.binding[0] ^= 1;
            assert!(verify_projection_v1(&c, &p).is_err());
        }
    }
    #[test]
    fn cancellation_using_old_column_challenge_is_rejected() {
        let a = (0..6).map(|x| scalar_i32_v1(x - 3)).collect::<Vec<_>>();
        let ctx = ProjectionContextV1 {
            binding: [3; 32],
            stage: ProjectionStageV1::Coarse,
            rows: 3,
            columns: 2,
            commitment: commit_scalars_v1(&a).unwrap(),
        };
        let (mut p, _) = prove_projection_v1(&ctx, &a, &mut StdRng::seed_from_u64(8)).unwrap();
        let mut t = ctx.transcript().unwrap();
        challenges(&mut t, b"row-challenge", ctx.rows);
        for value in &p.projection {
            t.append_message(b"projection-coordinate", value);
        }
        let old_s = challenges(&mut t, b"column-challenge", ctx.columns);
        let u0 = canonical_scalar_v1(p.projection[0]).unwrap();
        let u1 = canonical_scalar_v1(p.projection[1]).unwrap();
        p.projection[0] = (u0 + old_s[1]).to_bytes();
        p.projection[1] = (u1 - old_s[0]).to_bytes();
        assert_eq!(
            (canonical_scalar_v1(p.projection[0]).unwrap() - u0) * old_s[0]
                + (canonical_scalar_v1(p.projection[1]).unwrap() - u1) * old_s[1],
            Scalar::ZERO
        );
        assert!(verify_projection_v1(&ctx, &p).is_err());
    }
    #[test]
    fn cached_generator_encoding_preserves_original_spring_bytes() {
        for n in [3usize, 16, 23] {
            let g = generators_v1(n).unwrap();
            let ped = PedersenGens::default();
            let a = (0..n)
                .map(|i| scalar_i32_v1(i as i32 - 7))
                .collect::<Vec<_>>();
            let b = (0..n)
                .map(|i| scalar_i32_v1(3 - i as i32))
                .collect::<Vec<_>>();
            let v = a.iter().zip(&b).fold(Scalar::ZERO, |s, (x, y)| s + x * y);
            let statement = (canonical_point_v1(commit_scalars_v1(&a).unwrap()).unwrap()
                + v * ped.B)
                .compress();
            let original = SpringLinearPublicInputs::new(&b, &g, &ped.B, &ped.B_blinding).unwrap();
            let cached = prepare_projection_generators_v1(n)
                .unwrap()
                .with_coefficients(&b)
                .unwrap();
            let p1 = SpringLinearProof::create_with_public_inputs(
                &mut Transcript::new(b"cache-equivalence-v1"),
                &mut StdRng::seed_from_u64(33),
                &statement,
                Scalar::ZERO,
                a.clone(),
                &original,
            )
            .unwrap();
            let p2 = SpringLinearProof::create_with_public_inputs(
                &mut Transcript::new(b"cache-equivalence-v1"),
                &mut StdRng::seed_from_u64(33),
                &statement,
                Scalar::ZERO,
                a,
                &cached,
            )
            .unwrap();
            assert_eq!(p1.to_bytes(), p2.to_bytes());
            p1.verify_with_public_inputs(
                &mut Transcript::new(b"cache-equivalence-v1"),
                &statement,
                &cached,
            )
            .unwrap();
        }
    }
    #[test]
    fn numeric_profile_bound_and_old_adapter_equivalence() {
        let a = (0..6).map(|x| scalar_i32_v1(x - 3)).collect::<Vec<_>>();
        let ctx = ProjectionContextV1 {
            binding: [7; 32],
            stage: ProjectionStageV1::Fine,
            rows: 3,
            columns: 2,
            commitment: commit_scalars_v1(&a).unwrap(),
        };
        let (old, _) = prove_projection_v1(&ctx, &a, &mut StdRng::seed_from_u64(4)).unwrap();
        let (explicit, _) = prove_projection_with_profile_v1(
            FIXED_PROFILE_ID_V1,
            &ctx,
            &a,
            &mut StdRng::seed_from_u64(4),
        )
        .unwrap();
        assert_eq!(old, explicit);
        assert!(
            verify_projection_with_profile_v1(gem_core::COMPACT_PROFILE_ID_V1, &ctx, &old).is_err()
        );
        let (compact, _) = prove_projection_with_profile_v1(
            gem_core::COMPACT_PROFILE_ID_V1,
            &ctx,
            &a,
            &mut StdRng::seed_from_u64(4),
        )
        .unwrap();
        verify_projection_with_profile_v1(gem_core::COMPACT_PROFILE_ID_V1, &ctx, &compact).unwrap();
        assert!(verify_projection_v1(&ctx, &compact).is_err());
        assert_ne!(
            document_weights_v1([1; 32], 2).unwrap(),
            document_weights_with_profile_v1(gem_core::COMPACT_PROFILE_ID_V1, [1; 32], 2).unwrap()
        );
    }
    #[test]
    fn dimension_formula() {
        for (n, s) in [(23040, 1056), (65536, 1120), (1048576, 1376)] {
            assert_eq!(projection_argument_bytes_v1(n).unwrap(), s);
        }
    }
    #[test]
    fn negative_and_zero_witness() {
        for a in [vec![Scalar::ZERO; 6], vec![-Scalar::ONE; 6]] {
            let ctx = ProjectionContextV1 {
                binding: [4; 32],
                stage: ProjectionStageV1::Reranking,
                rows: 3,
                columns: 2,
                commitment: commit_scalars_v1(&a).unwrap(),
            };
            let (p, _) = prove_projection_v1(&ctx, &a, &mut StdRng::seed_from_u64(4)).unwrap();
            verify_projection_v1(&ctx, &p).unwrap();
        }
    }
}
