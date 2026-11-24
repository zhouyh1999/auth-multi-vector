//! Springproofs-style linear inner-product proof (IPA) for arbitrary-length vectors.
//!
//! This module adapts the Bulletproofs `linear_proof` folding to handle non power-of-two lengths
//! using the Springproofs pre-compression schedule, avoiding external padding.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::borrow::Cow;
#[cfg(feature = "std")]
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

#[cfg(feature = "std")]
type SharedGeneratorVec<T> = Arc<Vec<T>>;
#[cfg(not(feature = "std"))]
type SharedGeneratorVec<T> = Vec<T>;

use core::iter;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "std")]
use rayon::prelude::*;

use crate::errors::ProofError;
use crate::inner_product_proof::inner_product;
use crate::transcript::TranscriptProtocol;

#[cfg(feature = "std")]
const SPRING_PAR_THRESHOLD: usize = 512;

// Split by witness size; small rounds keep dalek's single-call path. Each
// chunk computes an exact group sum, so thread scheduling cannot change the
// compressed point, the transcript, or the proof bytes.
#[cfg(feature = "std")]
const SPRING_MSM_PAR_THRESHOLD: usize = 16_384;
#[cfg(feature = "std")]
const SPRING_FIELD_PAR_THRESHOLD: usize = 32_768;

#[cfg(feature = "std")]
fn spring_msm_chunks(terms: usize, workers: usize) -> usize {
    static PILOT_THRESHOLD:std::sync::OnceLock<usize>=std::sync::OnceLock::new();
    let threshold=*PILOT_THRESHOLD.get_or_init(||std::env::var("PILOT_MSM_THRESHOLD")
        .ok().and_then(|x|x.parse().ok()).unwrap_or(SPRING_MSM_PAR_THRESHOLD));
    if workers <= 1 || terms < threshold {
        return 1;
    }
    // Document witnesses benefit from smaller chunks. Coarse-sized MSMs keep
    // one task per worker; over-partitioning these made the 8-worker case slower.
    // Keep the measured 32-task layout for small pools. At 24 or more workers,
    // align large MSM chunks with the pool to avoid a partial scheduling wave.
    // Bound concurrent Pippenger bucket sets even on larger machines.
    let (target, minimum_chunk) = if terms >= 262_144 {
        (
            if workers >= 24 {
                workers.min(64)
            } else {
                workers.saturating_mul(4).min(32)
            },
            8_192,
        )
    } else if terms >= 65_536 {
        (workers.min(64), 2_048)
    } else {
        (workers.saturating_mul(2).min(16), 1_024)
    };
    target.min(terms / minimum_chunk).max(1)
}

fn spring_multiscalar_mul(scalars: &[Scalar], points: &[RistrettoPoint]) -> RistrettoPoint {
    debug_assert_eq!(scalars.len(), points.len());
    #[cfg(feature = "std")]
    {
        let chunks = spring_msm_chunks(scalars.len(), rayon::current_num_threads());
        if chunks > 1 {
            let chunk_len = scalars.len().div_ceil(chunks);
            return scalars
                .par_chunks(chunk_len)
                .zip(points.par_chunks(chunk_len))
                .map(|(a, g)| RistrettoPoint::vartime_multiscalar_mul(a.iter(), g.iter()))
                .reduce(RistrettoPoint::default, |left, right| left + right);
        }
    }
    RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), points.iter())
}

fn round_commitment(
    scalars: &[Scalar],
    points: &[RistrettoPoint],
    blinding: &Scalar,
    cross_product: &Scalar,
    B: &RistrettoPoint,
    F: &RistrettoPoint,
) -> CompressedRistretto {
    #[cfg(feature = "std")]
    if spring_msm_chunks(scalars.len(), rayon::current_num_threads()) > 1 {
        let tail = RistrettoPoint::vartime_multiscalar_mul([blinding, cross_product], [B, F]);
        return (spring_multiscalar_mul(scalars, points) + tail).compress();
    }
    RistrettoPoint::vartime_multiscalar_mul(
        scalars
            .iter()
            .chain(iter::once(blinding))
            .chain(iter::once(cross_product)),
        points.iter().chain(iter::once(B)).chain(iter::once(F)),
    )
    .compress()
}

fn spring_inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    #[cfg(feature = "std")]
    if a.len() >= SPRING_FIELD_PAR_THRESHOLD && rayon::current_num_threads() > 1 {
        return a
            .par_iter()
            .zip(b.par_iter())
            .map(|(x, y)| x * y)
            .reduce(|| Scalar::ZERO, |left, right| left + right);
    }
    inner_product(a, b)
}

// Evaluate the original round commitment on an unmaterialized basis. Each
// basis block has one challenge product, so large independent MSMs can share
// the existing Rayon pool. All sums are exact in the same Ristretto group.
#[cfg(feature = "std")]
fn virtual_round_commitment(
    a: &[Scalar],
    original: &[RistrettoPoint],
    stride: usize,
    offset: usize,
    weights: &[Scalar],
    blinding: &Scalar,
    product: &Scalar,
    B: &RistrettoPoint,
    F: &RistrettoPoint,
) -> CompressedRistretto {
    let main = weights
        .par_iter()
        .enumerate()
        .map(|(block, weight)| {
            let start = block * stride + offset;
            let point = spring_multiscalar_mul(a, &original[start..start + a.len()]);
            if block == 0 {
                point
            } else {
                weight * point
            }
        })
        .reduce(RistrettoPoint::default, |a, b| a + b);
    (main + RistrettoPoint::vartime_multiscalar_mul([blinding, product], [B, F])).compress()
}

#[cfg(feature = "std")]
fn fold_scalar_halves(
    a_l: &[Scalar],
    a_r: &[Scalar],
    b_l: &[Scalar],
    b_r: &[Scalar],
    x: Scalar,
    x_inv: Scalar,
) -> (Vec<Scalar>, Vec<Scalar>) {
    (0..a_l.len())
        .into_par_iter()
        .map(|i| (a_l[i] + x_inv * a_r[i], b_l[i] + x * b_r[i]))
        .collect()
}

fn paired_inner_products(
    a_l: &[Scalar],
    b_r: &[Scalar],
    a_r: &[Scalar],
    b_l: &[Scalar],
) -> (Scalar, Scalar) {
    #[cfg(feature = "std")]
    {
        if a_l.len() + a_r.len() >= SPRING_PAR_THRESHOLD {
            return rayon::join(
                || spring_inner_product(a_l, b_r),
                || spring_inner_product(a_r, b_l),
            );
        }
    }
    (
        spring_inner_product(a_l, b_r),
        spring_inner_product(a_r, b_l),
    )
}

fn fold_halves(
    a_l: &[Scalar],
    a_r: &[Scalar],
    b_l: &[Scalar],
    b_r: &[Scalar],
    g_l: &[RistrettoPoint],
    g_r: &[RistrettoPoint],
    x: Scalar,
    x_inv: Scalar,
) -> (Vec<Scalar>, Vec<Scalar>, Vec<RistrettoPoint>) {
    let n = a_l.len();
    #[cfg(feature = "std")]
    {
        if n >= SPRING_PAR_THRESHOLD {
            // Indexed parallel unzip writes the three output vectors directly,
            // avoiding an equally large intermediate tuple vector and serial copy.
            let (a_new, (b_new, g_new)): (Vec<_>, (Vec<_>, Vec<_>)) = (0..n)
                .into_par_iter()
                .map(|i| {
                    (
                        a_l[i] + x_inv * a_r[i],
                        (b_l[i] + x * b_r[i], g_l[i] + x * g_r[i]),
                    )
                })
                .collect();
            return (a_new, b_new, g_new);
        }
    }

    let mut a_new = Vec::with_capacity(n);
    let mut b_new = Vec::with_capacity(n);
    let mut g_new = Vec::with_capacity(n);
    for i in 0..n {
        a_new.push(a_l[i] + x_inv * a_r[i]);
        b_new.push(b_l[i] + x * b_r[i]);
        g_new.push(g_l[i] + x * g_r[i]);
    }
    (a_new, b_new, g_new)
}

#[cfg(test)]
fn apply_precompression_positions(
    alpha: &mut [Scalar],
    pos_vec: &mut [usize],
    n: usize,
    ih0: usize,
    it0: usize,
    N: usize,
    n_half: usize,
    it_1: usize,
    x0: Scalar,
) {
    #[cfg(feature = "std")]
    {
        if n >= SPRING_PAR_THRESHOLD {
            pos_vec
                .par_iter_mut()
                .zip(alpha.par_iter_mut())
                .take(n)
                .enumerate()
                .for_each(|(i, (pos, alpha_i))| {
                    let new_pos = if i < ih0 {
                        i
                    } else if ih0 <= i && i <= it0 {
                        ih0 + (i - ih0)
                    } else if i >= N {
                        *alpha_i = *alpha_i * x0;
                        ih0 + (i - N)
                    } else {
                        ih0 + n_half + (i - it_1)
                    };
                    *pos = new_pos;
                });
            return;
        }
    }

    for i in 0..n {
        let new_pos = if i < ih0 {
            i
        } else if ih0 <= i && i <= it0 {
            ih0 + (i - ih0)
        } else if i >= N {
            alpha[i] = alpha[i] * x0;
            ih0 + (i - N)
        } else {
            ih0 + n_half + (i - it_1)
        };
        pos_vec[i] = new_pos;
    }
}

#[cfg(test)]
fn update_fold_positions(
    alpha: &mut [Scalar],
    pos_vec: &mut [usize],
    cur_n: usize,
    n2: usize,
    xj: Scalar,
) {
    #[cfg(feature = "std")]
    {
        if pos_vec.len() >= SPRING_PAR_THRESHOLD {
            pos_vec
                .par_iter_mut()
                .zip(alpha.par_iter_mut())
                .for_each(|(pos, alpha_i)| {
                    let p = *pos;
                    if p < cur_n {
                        if p >= n2 {
                            *alpha_i = *alpha_i * xj;
                            *pos = p - n2;
                        } else {
                            *pos = p;
                        }
                    }
                });
            return;
        }
    }

    for i in 0..pos_vec.len() {
        let p = pos_vec[i];
        if p < cur_n {
            if p >= n2 {
                alpha[i] = alpha[i] * xj;
                pos_vec[i] = p - n2;
            } else {
                pos_vec[i] = p;
            }
        }
    }
}

// Construct subset products in O(n) field operations. Challenge order is
// unchanged: the first ordinary round labels the most significant index bit.
// In fc'(n), original positions below N retain their positions; each tail
// position N+j folds into ih0+j with the extra first challenge x0.
fn folding_weights(n: usize, challenges: &[Scalar]) -> Vec<Scalar> {
    let power = n.next_power_of_two();
    let (folded_n, start_round) = if n == power { (n, 0) } else { (power / 2, 1) };
    let mut alpha = vec![Scalar::ONE; n];
    let mut width = 1;
    for x in challenges.iter().skip(start_round).rev() {
        let (left, right) = alpha[..2 * width].split_at_mut(width);
        #[cfg(feature = "std")]
        if width >= SPRING_PAR_THRESHOLD {
            right
                .par_iter_mut()
                .zip(left.par_iter())
                .for_each(|(out, value)| *out = *value * x);
            width *= 2;
            continue;
        }
        for (out, value) in right.iter_mut().zip(left.iter()) {
            *out = *value * x;
        }
        width *= 2;
    }
    debug_assert_eq!(width, folded_n);
    if n != power {
        let ih0 = (2 * folded_n - n) / 2;
        let x0 = challenges[0];
        let (head, tail) = alpha.split_at_mut(folded_n);
        #[cfg(feature = "std")]
        if tail.len() >= SPRING_PAR_THRESHOLD {
            tail.par_iter_mut()
                .zip(head[ih0..].par_iter())
                .for_each(|(out, value)| *out = *value * x0);
            return alpha;
        }
        for (out, value) in tail.iter_mut().zip(head[ih0..].iter()) {
            *out = *value * x0;
        }
    }
    alpha
}

fn weighted_sum(alpha: &[Scalar], b_vec: &[Scalar]) -> Scalar {
    #[cfg(feature = "std")]
    {
        if alpha.len() >= SPRING_PAR_THRESHOLD {
            return alpha
                .par_iter()
                .zip(b_vec.par_iter())
                .map(|(a_i, b_i)| *a_i * *b_i)
                .reduce(|| Scalar::ZERO, |acc, term| acc + term);
        }
    }

    let mut acc = Scalar::ZERO;
    for i in 0..alpha.len() {
        acc += alpha[i] * b_vec[i];
    }
    acc
}

/// A linear proof that supports arbitrary-length vectors using Springproofs-style fc'(n)
/// symmetric pre-compression schedule, then Bulletproofs-style iterative folding.
/// No external zero padding is required; the prover folds only specific ranges T
/// according to fc'(n) when n is not a power of two, reducing length to
/// N = 2^(ceil(log2(n)) - 1), then continues with standard halves folding.
#[derive(Clone, Debug)]
pub struct SpringLinearProof {
    pub(crate) L_vec: Vec<CompressedRistretto>,
    pub(crate) R_vec: Vec<CompressedRistretto>,
    /// A commitment to the base case elements
    pub(crate) S: CompressedRistretto,
    /// a_star, corresponding to the base case `a`
    pub(crate) a: Scalar,
    /// r_star, corresponding to the base case `r`
    pub(crate) r: Scalar,
}

/// Public inputs shared by SpringLinearProof instances with the same query vector
/// and generators.
#[derive(Clone, Debug)]
pub struct SpringLinearPublicInputs {
    b_vec: Vec<Scalar>,
    G_vec: SharedGeneratorVec<RistrettoPoint>,
    G_compressed: SharedGeneratorVec<CompressedRistretto>,
    F: RistrettoPoint,
    B: RistrettoPoint,
    F_compressed: CompressedRistretto,
    B_compressed: CompressedRistretto,
}

/// Local, immutable preprocessing for one witness and the exact shared basis.
/// It is never serialized, signed, or sent to a verifier. Cross commitments
/// expand the same L/R polynomials; each query keeps its original transcript.
#[derive(Clone, Debug)]
pub struct SpringLinearPreparedWitness {
    a: SharedGeneratorVec<Scalar>,
    G: SharedGeneratorVec<RistrettoPoint>,
    rounds: Vec<(Vec<RistrettoPoint>, Vec<RistrettoPoint>)>,
}
impl SpringLinearPreparedWitness {
    pub fn new(a: Vec<Scalar>, inputs: &SpringLinearPublicInputs) -> Result<Self, ProofError> {
        if a.len() != inputs.len() {
            return Err(ProofError::InvalidInputLength);
        }
        let n = a.len();
        let depth = if n.is_power_of_two() {
            (n.trailing_zeros() as usize).min(4)
        } else {
            0
        };
        let build = |round: usize| {
            let blocks = 1 << round;
            let stride = n / blocks;
            let half = stride / 2;
            let cross = |index: usize| {
                let a_start = (index / blocks) * stride;
                let g_start = (index % blocks) * stride;
                (
                    spring_multiscalar_mul(
                        &a[a_start..a_start + half],
                        &inputs.G_vec[g_start + half..g_start + stride],
                    ),
                    spring_multiscalar_mul(
                        &a[a_start + half..a_start + stride],
                        &inputs.G_vec[g_start..g_start + half],
                    ),
                )
            };
            #[cfg(feature = "std")]
            let pairs: Vec<_> = (0..blocks * blocks).into_par_iter().map(cross).collect();
            #[cfg(not(feature = "std"))]
            let pairs: Vec<_> = (0..blocks * blocks).map(cross).collect();
            pairs.into_iter().unzip()
        };
        #[cfg(feature = "std")]
        let rounds = (0..depth).into_par_iter().map(build).collect();
        #[cfg(not(feature = "std"))]
        let rounds = (0..depth).map(build).collect();
        #[cfg(feature = "std")]
        let a = Arc::new(a);
        Ok(Self {
            a,
            G: inputs.G_vec.clone(),
            rounds,
        })
    }
    pub fn witness(&self) -> &[Scalar] {
        &self.a
    }
    fn matches_basis(&self, inputs: &SpringLinearPublicInputs) -> bool {
        #[cfg(feature = "std")]
        {
            self.a.len() == inputs.len() && Arc::ptr_eq(&self.G, &inputs.G_vec)
        }
        #[cfg(not(feature = "std"))]
        {
            self.a.len() == inputs.len() && self.G == inputs.G_vec
        }
    }
    fn commitments(
        &self,
        round: usize,
        a_weights: &[Scalar],
        g_weights: &[Scalar],
    ) -> (RistrettoPoint, RistrettoPoint) {
        let coefficients: Vec<_> = a_weights
            .iter()
            .flat_map(|a| g_weights.iter().map(move |g| a * g))
            .collect();
        let (left, right) = &self.rounds[round];
        (
            spring_multiscalar_mul(&coefficients, left),
            spring_multiscalar_mul(&coefficients, right),
        )
    }
}

impl SpringLinearPublicInputs {
    /// Build a reusable public-input context. `G` may be longer than `b_vec`;
    /// only the first `b_vec.len()` generators are used, matching `create`.
    pub fn new(
        b_vec: &[Scalar],
        G: &[RistrettoPoint],
        F: &RistrettoPoint,
        B: &RistrettoPoint,
    ) -> Result<Self, ProofError> {
        let n = b_vec.len();
        if G.len() < n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        Self::from_owned(b_vec.to_vec(), G[..n].to_vec(), F, B)
    }

    /// Reuse immutable generator points and their canonical encodings with a new
    /// public coefficient vector. This performs no transcript or proof operation.
    pub fn with_coefficients(&self, b_vec: &[Scalar]) -> Result<Self, ProofError> {
        self.with_owned_coefficients(b_vec.to_vec())
    }

    /// Move request coefficients while sharing immutable generators and encodings.
    pub fn with_owned_coefficients(&self, b_vec: Vec<Scalar>) -> Result<Self, ProofError> {
        if b_vec.len() != self.b_vec.len() {
            return Err(ProofError::InvalidInputLength);
        }
        Ok(Self {
            b_vec,
            G_vec: self.G_vec.clone(),
            G_compressed: self.G_compressed.clone(),
            F: self.F,
            B: self.B,
            F_compressed: self.F_compressed,
            B_compressed: self.B_compressed,
        })
    }

    fn from_owned(
        b_vec: Vec<Scalar>,
        mut G_vec: Vec<RistrettoPoint>,
        F: &RistrettoPoint,
        B: &RistrettoPoint,
    ) -> Result<Self, ProofError> {
        let n = b_vec.len();
        if n == 0 || G_vec.len() < n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        if G_vec.len() > n {
            G_vec.truncate(n);
        }
        #[cfg(feature = "std")]
        let G_vec = Arc::new(G_vec);
        Self::from_shared(b_vec, G_vec, F, B)
    }

    /// Use the first `b_vec.len()` points from a caller's immutable generator cache.
    #[cfg(feature = "std")]
    pub fn new_with_shared_generators(
        b_vec: Vec<Scalar>,
        G_vec: Arc<Vec<RistrettoPoint>>,
        F: &RistrettoPoint,
        B: &RistrettoPoint,
    ) -> Result<Self, ProofError> {
        Self::from_shared(b_vec, G_vec, F, B)
    }

    fn from_shared(
        b_vec: Vec<Scalar>,
        G_vec: SharedGeneratorVec<RistrettoPoint>,
        F: &RistrettoPoint,
        B: &RistrettoPoint,
    ) -> Result<Self, ProofError> {
        let n = b_vec.len();
        if n == 0 || G_vec.len() < n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        #[cfg(feature = "std")]
        let G_compressed: Vec<_> = if n >= SPRING_PAR_THRESHOLD {
            G_vec[..n].par_iter().map(|g| g.compress()).collect()
        } else {
            G_vec[..n].iter().map(|g| g.compress()).collect()
        };
        #[cfg(not(feature = "std"))]
        let G_compressed: Vec<_> = G_vec[..n].iter().map(|g| g.compress()).collect();
        #[cfg(feature = "std")]
        let G_compressed = Arc::new(G_compressed);
        Ok(Self {
            b_vec,
            G_vec,
            G_compressed,
            F: *F,
            B: *B,
            F_compressed: F.compress(),
            B_compressed: B.compress(),
        })
    }

    pub fn len(&self) -> usize {
        self.b_vec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.b_vec.is_empty()
    }

    fn b_slice(&self) -> &[Scalar] {
        &self.b_vec
    }

    fn G_slice(&self) -> &[RistrettoPoint] {
        &self.G_vec[..self.len()]
    }

    fn append_to_transcript(&self, transcript: &mut Transcript, C: &CompressedRistretto) {
        transcript.innerproduct_domain_sep(self.len() as u64);
        transcript.append_point(b"C", C);
        self.append_public_after_commitment(transcript);
    }

    fn append_public_after_commitment(&self, transcript: &mut Transcript) {
        for b_i in &self.b_vec {
            transcript.append_scalar(b"b_i", b_i);
        }
        for G_i in self.G_compressed.iter() {
            transcript.append_point(b"G_i", G_i);
        }
        transcript.append_point(b"F", &self.F_compressed);
        transcript.append_point(b"B", &self.B_compressed);
    }

    fn append_to_batch_transcript(&self, transcript: &mut Transcript) {
        transcript.innerproduct_domain_sep(self.len() as u64);
        self.append_public_after_commitment(transcript);
    }
}

impl SpringLinearProof {
    /// Return the unique Spring folding-round count for an input dimension.
    /// This must be checked before verification indexes any challenge round.
    pub fn expected_rounds(n: usize) -> Result<usize, ProofError> {
        if n == 0 {
            return Err(ProofError::InvalidInputLength);
        }
        let rounds = n
            .checked_next_power_of_two()
            .ok_or(ProofError::InvalidInputLength)?
            .trailing_zeros() as usize;
        if rounds >= 32 {
            return Err(ProofError::InvalidInputLength);
        }
        Ok(rounds)
    }

    fn validate_round_count(&self, n: usize) -> Result<(), ProofError> {
        let expected = Self::expected_rounds(n)?;
        if self.L_vec.len() != expected || self.R_vec.len() != expected {
            return Err(ProofError::VerificationError);
        }
        Ok(())
    }

    /// Create a linear proof that proves <a, b> = c where a is secret and b is public.
    /// Accepts arbitrary input length. The provided generator vector G must have length >= a.len().
    pub fn create<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        // Commitment to witness over full generators
        C: &CompressedRistretto,
        // Blinding factor for C
        r: Scalar,
        // Secret scalar vector a (arbitrary length n)
        a_vec: Vec<Scalar>,
        // Public scalar vector b (same length as a)
        b_vec: Vec<Scalar>,
        // Generator vector G (length must be >= a.len())
        G_vec: Vec<RistrettoPoint>,
        // Pedersen generator F, for committing to the secret value
        F: &RistrettoPoint,
        // Pedersen generator B, for committing to the blinding value
        B: &RistrettoPoint,
    ) -> Result<SpringLinearProof, ProofError> {
        let public_inputs = SpringLinearPublicInputs::from_owned(b_vec, G_vec, F, B)?;
        Self::create_with_public_inputs(transcript, rng, C, r, a_vec, &public_inputs)
    }

    pub fn create_with_public_inputs<T: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut T,
        // Commitment to witness over full generators
        C: &CompressedRistretto,
        // Blinding factor for C
        r: Scalar,
        // Secret scalar vector a (arbitrary length n)
        a_vec: Vec<Scalar>,
        // Shared public scalar vector, generators, and transcript encodings.
        public_inputs: &SpringLinearPublicInputs,
    ) -> Result<SpringLinearProof, ProofError> {
        Self::create_internal(transcript, rng, C, r, a_vec, public_inputs, None)
    }

    /// Reuse local witness cross commitments without changing proof bytes.
    pub fn create_with_prepared_witness<R: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut R,
        C: &CompressedRistretto,
        r: Scalar,
        prepared: &SpringLinearPreparedWitness,
        public_inputs: &SpringLinearPublicInputs,
    ) -> Result<SpringLinearProof, ProofError> {
        if !prepared.matches_basis(public_inputs) {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        Self::create_internal(
            transcript,
            rng,
            C,
            r,
            prepared.a.to_vec(),
            public_inputs,
            Some(prepared),
        )
    }

    fn create_internal<R: RngCore + CryptoRng>(
        transcript: &mut Transcript,
        rng: &mut R,
        C: &CompressedRistretto,
        mut r: Scalar,
        a_vec: Vec<Scalar>,
        public_inputs: &SpringLinearPublicInputs,
        prepared: Option<&SpringLinearPreparedWitness>,
    ) -> Result<SpringLinearProof, ProofError> {
        let n_orig = public_inputs.len();
        if a_vec.len() != n_orig {
            return Err(ProofError::InvalidInputLength);
        }
        let mut n = n_orig;
        let F = &public_inputs.F;
        let B = &public_inputs.B;
        public_inputs.append_to_transcript(transcript, C);

        // work vectors
        let mut a = a_vec;
        let mut b: Cow<'_, [Scalar]> = Cow::Borrowed(public_inputs.b_slice());
        let mut G: Cow<'_, [RistrettoPoint]> = Cow::Borrowed(public_inputs.G_slice());

        let mut L_vec = Vec::new();
        let mut R_vec = Vec::new();

        // helper to compute next power-of-two
        let next_pow2 = |x: usize| -> usize { x.next_power_of_two() };

        // One pre-compression step if n is not a power of two: use fc'(n)
        let M = next_pow2(n);
        if n != M {
            let N = M >> 1; // N = 2^(ceil(log2 n)-1)
                            // 1-based indices in paper: ih = floor((2N - n)/2) + 1, it = floor(n/2)
            let ih_1 = ((2 * N - n) / 2) + 1;
            let it_1 = n / 2;
            // convert to 0-based inclusive ranges
            let ih0 = ih_1 - 1; // start of left part
            let it0 = if it_1 == 0 { 0 } else { it_1 - 1 }; // end of left part

            // Build T index list: (ih:it) then (N+1:n)
            let mut T: Vec<usize> = Vec::new();
            if ih0 <= it0 {
                for i in ih0..=it0 {
                    T.push(i);
                }
            }
            for i in N..n {
                T.push(i);
            }
            let m = T.len();
            debug_assert!(m % 2 == 0, "fc'(n) requires even |T|");
            let n_half = m / 2;
            let (T_l, T_r) = T.split_at(n_half);
            #[cfg(test)]
            {
                eprintln!(
                    "[create] n={} M={} N={} ih={} it={} |T|={} Tl={:?} Tr={:?}",
                    n, M, N, ih_1, it_1, m, T_l, T_r
                );
            }

            // Build slices for commitments
            let a_l: Vec<Scalar> = T_l.iter().map(|&i| a[i]).collect();
            let a_r: Vec<Scalar> = T_r.iter().map(|&i| a[i]).collect();
            let b_l: Vec<Scalar> = T_l.iter().map(|&i| b[i]).collect();
            let b_r: Vec<Scalar> = T_r.iter().map(|&i| b[i]).collect();
            let G_l: Vec<RistrettoPoint> = T_l.iter().map(|&i| G[i]).collect();
            let G_r: Vec<RistrettoPoint> = T_r.iter().map(|&i| G[i]).collect();

            let (c_L, c_R) = paired_inner_products(&a_l, &b_r, &a_r, &b_l);

            let s_j = Scalar::random(rng);
            let t_j = Scalar::random(rng);

            #[cfg(feature = "std")]
            let (L, R) = if n_half >= SPRING_PAR_THRESHOLD {
                rayon::join(
                    || round_commitment(&a_l, &G_r, &s_j, &c_L, B, F),
                    || round_commitment(&a_r, &G_l, &t_j, &c_R, B, F),
                )
            } else {
                (
                    round_commitment(&a_l, &G_r, &s_j, &c_L, B, F),
                    round_commitment(&a_r, &G_l, &t_j, &c_R, B, F),
                )
            };
            #[cfg(not(feature = "std"))]
            let (L, R) = (
                round_commitment(&a_l, &G_r, &s_j, &c_L, B, F),
                round_commitment(&a_r, &G_l, &t_j, &c_R, B, F),
            );

            L_vec.push(L);
            R_vec.push(R);
            transcript.append_point(b"L", &L_vec.last().unwrap());
            transcript.append_point(b"R", &R_vec.last().unwrap());
            let x = transcript.challenge_scalar(b"x_j");
            let x_inv = x.invert();

            // Fold inside T to compressed left half.
            let (a_T_new, b_T_new, G_T_new) =
                fold_halves(&a_l, &a_r, &b_l, &b_r, &G_l, &G_r, x, x_inv);

            // Assemble new arrays (length becomes N)
            let mut a_new: Vec<Scalar> = Vec::with_capacity(N);
            let mut b_new: Vec<Scalar> = Vec::with_capacity(N);
            let mut G_new: Vec<RistrettoPoint> = Vec::with_capacity(N);
            // prefix [0 .. ih0)
            for i in 0..ih0 {
                a_new.push(a[i]);
                b_new.push(b[i]);
                G_new.push(G[i]);
            }
            // compressed T
            a_new.extend_from_slice(&a_T_new);
            b_new.extend_from_slice(&b_T_new);
            G_new.extend_from_slice(&G_T_new);
            // suffix [it_1 .. N-1]  (1-based it inclusive -> 0-based start = it_1)
            for i in it_1..N {
                a_new.push(a[i]);
                b_new.push(b[i]);
                G_new.push(G[i]);
            }

            debug_assert_eq!(a_new.len(), N);
            a = a_new;
            b = Cow::Owned(b_new);
            G = Cow::Owned(G_new);
            n = N;
            r = r + x * s_j + x_inv * t_j;
        }

        // After precompression (if any), do classic halves folding until 1
        while n != 1 {
            let n2 = n / 2;
            let (a_L, a_R) = a.split_at(n2);
            let (b_L, b_R) = b.split_at(n2);
            let (G_L, G_R) = G.split_at(n2);

            let (c_L, c_R) = paired_inner_products(a_L, b_R, a_R, b_L);
            let s_j = Scalar::random(rng);
            let t_j = Scalar::random(rng);
            let cached = prepared
                .filter(|p| n == n_orig && !p.rounds.is_empty())
                .map(|p| p.commitments(0, &[Scalar::ONE], &[Scalar::ONE]));
            #[cfg(feature = "std")]
            let (L, R) = if let Some((left, right)) = cached {
                (
                    (left + RistrettoPoint::vartime_multiscalar_mul([s_j, c_L], [*B, *F]))
                        .compress(),
                    (right + RistrettoPoint::vartime_multiscalar_mul([t_j, c_R], [*B, *F]))
                        .compress(),
                )
            } else if n2 >= SPRING_PAR_THRESHOLD {
                rayon::join(
                    || round_commitment(a_L, G_R, &s_j, &c_L, B, F),
                    || round_commitment(a_R, G_L, &t_j, &c_R, B, F),
                )
            } else {
                (
                    round_commitment(a_L, G_R, &s_j, &c_L, B, F),
                    round_commitment(a_R, G_L, &t_j, &c_R, B, F),
                )
            };
            #[cfg(not(feature = "std"))]
            let (L, R) = if let Some((left, right)) = cached {
                (
                    (left + RistrettoPoint::vartime_multiscalar_mul([s_j, c_L], [*B, *F]))
                        .compress(),
                    (right + RistrettoPoint::vartime_multiscalar_mul([t_j, c_R], [*B, *F]))
                        .compress(),
                )
            } else {
                (
                    round_commitment(a_L, G_R, &s_j, &c_L, B, F),
                    round_commitment(a_R, G_L, &t_j, &c_R, B, F),
                )
            };

            L_vec.push(L);
            R_vec.push(R);
            transcript.append_point(b"L", &L_vec.last().unwrap());
            transcript.append_point(b"R", &R_vec.last().unwrap());
            let x = transcript.challenge_scalar(b"x_j");
            let x_inv = x.invert();

            #[cfg(feature = "std")]
            if n >= 16_384 && rayon::current_num_threads() > 1 {
                // Preserve each original L/R, RNG draw and Fiat-Shamir challenge.
                // Only defer generator materialization across four rounds. The
                // scalar witness and public coefficients still fold every round.
                const FUSED_ROUNDS: usize = 4;
                let (mut a_folded, mut b_folded) = fold_scalar_halves(a_L, a_R, b_L, b_R, x, x_inv);
                let mut weights = vec![Scalar::ONE, x];
                let mut a_weights = vec![Scalar::ONE, x_inv];
                r = r + x * s_j + x_inv * t_j;
                for round in 1..FUSED_ROUNDS {
                    let stride = a_folded.len();
                    let half = stride / 2;
                    let (al, ar) = a_folded.split_at(half);
                    let (bl, br) = b_folded.split_at(half);
                    let (cl, cr) = paired_inner_products(al, br, ar, bl);
                    let sj = Scalar::random(rng);
                    let tj = Scalar::random(rng);
                    let cached = prepared
                        .filter(|p| n == n_orig && round < p.rounds.len())
                        .map(|p| p.commitments(round, &a_weights, &weights));
                    let (l, rr) = if let Some((left, right)) = cached {
                        (
                            (left + RistrettoPoint::vartime_multiscalar_mul([sj, cl], [*B, *F]))
                                .compress(),
                            (right + RistrettoPoint::vartime_multiscalar_mul([tj, cr], [*B, *F]))
                                .compress(),
                        )
                    } else {
                        rayon::join(
                            || {
                                virtual_round_commitment(
                                    al, &G, stride, half, &weights, &sj, &cl, B, F,
                                )
                            },
                            || {
                                virtual_round_commitment(
                                    ar, &G, stride, 0, &weights, &tj, &cr, B, F,
                                )
                            },
                        )
                    };
                    L_vec.push(l);
                    R_vec.push(rr);
                    transcript.append_point(b"L", L_vec.last().unwrap());
                    transcript.append_point(b"R", R_vec.last().unwrap());
                    let z = transcript.challenge_scalar(b"x_j");
                    let z_inv = z.invert();
                    let (a_next, b_next) = fold_scalar_halves(al, ar, bl, br, z, z_inv);
                    a_folded = a_next;
                    b_folded = b_next;
                    weights = weights.iter().flat_map(|w| [*w, *w * z]).collect();
                    a_weights = a_weights.iter().flat_map(|w| [*w, *w * z_inv]).collect();
                    r = r + z * sj + z_inv * tj;
                }
                let width = a_folded.len();
                let G_new: Vec<_> = (0..width)
                    .into_par_iter()
                    .map(|i| {
                        RistrettoPoint::vartime_multiscalar_mul(
                            weights.iter(),
                            (0..weights.len()).map(|j| &G[i + j * width]),
                        )
                    })
                    .collect();
                a = a_folded;
                b = Cow::Owned(b_folded);
                G = Cow::Owned(G_new);
                n = width;
                continue;
            }
            let (a_new, b_new, G_new) = fold_halves(a_L, a_R, b_L, b_R, G_L, G_R, x, x_inv);
            a = a_new;
            b = Cow::Owned(b_new);
            G = Cow::Owned(G_new);
            n = n2;
            r = r + x * s_j + x_inv * t_j;
        }

        let s_star = Scalar::random(rng);
        let t_star = Scalar::random(rng);
        let S = (t_star * B + s_star * b[0] * F + s_star * G[0]).compress();
        transcript.append_point(b"S", &S);

        let x_star = transcript.challenge_scalar(b"x_star");
        let a_star = s_star + x_star * a[0];
        let r_star = t_star + x_star * r;

        Ok(SpringLinearProof {
            L_vec,
            R_vec,
            S,
            a: a_star,
            r: r_star,
        })
    }

    pub fn verify(
        &self,
        transcript: &mut Transcript,
        // Commitment to witness over full generators
        C: &CompressedRistretto,
        // Generator vector (length >= |b|)
        G: &[RistrettoPoint],
        // Pedersen generator F, for committing to the secret value
        F: &RistrettoPoint,
        // Pedersen generator B, for committing to the blinding value
        B: &RistrettoPoint,
        // Public scalar vector b
        b_vec: Vec<Scalar>,
    ) -> Result<(), ProofError> {
        let public_inputs = SpringLinearPublicInputs::new(&b_vec, G, F, B)?;
        self.verify_with_public_inputs(transcript, C, &public_inputs)
    }

    pub fn verify_with_public_inputs(
        &self,
        transcript: &mut Transcript,
        // Commitment to witness over full generators
        C: &CompressedRistretto,
        // Shared public scalar vector, generators, and transcript encodings.
        public_inputs: &SpringLinearPublicInputs,
    ) -> Result<(), ProofError> {
        let n = public_inputs.len();
        self.validate_round_count(n)?;
        let G_slice = public_inputs.G_slice();
        let F = &public_inputs.F;
        let B = &public_inputs.B;

        // Append all public data to the transcript to match prover side.
        public_inputs.append_to_transcript(transcript, C);

        // Collect challenges and points, but do not fold (b,G) per round.
        let mut x_list: Vec<Scalar> = Vec::with_capacity(self.L_vec.len());
        let mut x_inv_list: Vec<Scalar> = Vec::with_capacity(self.L_vec.len());
        let mut L_points: Vec<RistrettoPoint> = Vec::with_capacity(self.L_vec.len());
        let mut R_points: Vec<RistrettoPoint> = Vec::with_capacity(self.R_vec.len());
        for (Lc, Rc) in self.L_vec.iter().zip(self.R_vec.iter()) {
            transcript.validate_and_append_point(b"L", Lc)?;
            transcript.validate_and_append_point(b"R", Rc)?;
            let x = transcript.challenge_scalar(b"x_j");
            x_inv_list.push(x.invert());
            x_list.push(x);
            L_points.push(Lc.decompress().ok_or(ProofError::VerificationError)?);
            R_points.push(Rc.decompress().ok_or(ProofError::VerificationError)?);
        }

        // Exact folded generator coefficients, with no per-round position scan.
        let alpha = folding_weights(n, &x_list);

        // These three sums depend only on the completed challenges and can
        // share the pool without changing any transcript operation.
        #[cfg(feature = "std")]
        let (b_0, (G_final, L_R_factors)) = if alpha.len() >= SPRING_PAR_THRESHOLD {
            rayon::join(
                || weighted_sum(&alpha, public_inputs.b_slice()),
                || {
                    rayon::join(
                        || spring_multiscalar_mul(&alpha, G_slice),
                        || {
                            RistrettoPoint::vartime_multiscalar_mul(
                                x_list.iter().chain(x_inv_list.iter()),
                                L_points.iter().chain(R_points.iter()),
                            )
                        },
                    )
                },
            )
        } else {
            (
                weighted_sum(&alpha, public_inputs.b_slice()),
                (
                    spring_multiscalar_mul(&alpha, G_slice),
                    RistrettoPoint::vartime_multiscalar_mul(
                        x_list.iter().chain(x_inv_list.iter()),
                        L_points.iter().chain(R_points.iter()),
                    ),
                ),
            )
        };
        #[cfg(not(feature = "std"))]
        let (b_0, (G_final, L_R_factors)) = (
            weighted_sum(&alpha, public_inputs.b_slice()),
            (
                spring_multiscalar_mul(&alpha, G_slice),
                RistrettoPoint::vartime_multiscalar_mul(
                    x_list.iter().chain(x_inv_list.iter()),
                    L_points.iter().chain(R_points.iter()),
                ),
            ),
        );

        // Final S check
        transcript.append_point(b"S", &self.S);
        let x_star = transcript.challenge_scalar(b"x_star");
        let S = self.S.decompress().ok_or(ProofError::VerificationError)?;
        let C = C.decompress().ok_or(ProofError::VerificationError)?;
        let expect_S =
            self.r * B + self.a * b_0 * F - x_star * (C + L_R_factors) + self.a * G_final;
        if expect_S == S {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    // no verification_scalars/subset_product needed in fc'(n) mode
}

impl SpringLinearProof {
    /// Batch verify multiple SpringLinearProof instances for the same public vector b and generators.
    /// Each instance provides its commitment C. All instances must share the same b length and G slice.
    pub fn verify_batch(
        instances: &[(&SpringLinearProof, &CompressedRistretto)],
        G: &[RistrettoPoint],
        F: &RistrettoPoint,
        B: &RistrettoPoint,
        b_vec: Vec<Scalar>,
    ) -> Result<(), ProofError> {
        let public_inputs = SpringLinearPublicInputs::new(&b_vec, G, F, B)?;
        Self::verify_batch_with_public_inputs(instances, &public_inputs)
    }

    pub fn verify_batch_with_public_inputs(
        instances: &[(&SpringLinearProof, &CompressedRistretto)],
        public_inputs: &SpringLinearPublicInputs,
    ) -> Result<(), ProofError> {
        let n = public_inputs.len();
        if instances.is_empty() {
            return Err(ProofError::VerificationError);
        }
        for (proof, commitment) in instances {
            proof.validate_round_count(n)?;
            commitment
                .decompress()
                .ok_or(ProofError::VerificationError)?;
        }
        let G_slice = public_inputs.G_slice();
        let F = &public_inputs.F;
        let B = &public_inputs.B;

        // Derive batch weights beta_i via a batch transcript over all instances
        let mut batch_t = Transcript::new(b"springlinearproof_batch");
        public_inputs.append_to_batch_transcript(&mut batch_t);

        // Aggregated coefficients
        let mut agg_G_coeff: Vec<Scalar> = vec![Scalar::ZERO; n];
        let mut agg_points: Vec<RistrettoPoint> = Vec::new();
        let mut agg_scalars: Vec<Scalar> = Vec::new();

        for (proof, C_compr) in instances.iter() {
            // Append to batch transcript to derive beta
            batch_t.append_point(b"C_i", C_compr);
            for (Lc, Rc) in proof.L_vec.iter().zip(proof.R_vec.iter()) {
                batch_t.append_point(b"L_i", Lc);
                batch_t.append_point(b"R_i", Rc);
            }
            batch_t.append_point(b"S_i", &proof.S);
            let beta_i = batch_t.challenge_scalar(b"beta_i");

            // Per-proof transcript to reconstruct challenges identical to single verify
            let mut t = Transcript::new(b"springlinearproof_vo");
            public_inputs.append_to_transcript(&mut t, C_compr);

            // Collect x challenges and L/R points
            let mut x_list: Vec<Scalar> = Vec::with_capacity(proof.L_vec.len());
            let mut x_inv_list: Vec<Scalar> = Vec::with_capacity(proof.L_vec.len());
            let mut L_points: Vec<RistrettoPoint> = Vec::with_capacity(proof.L_vec.len());
            let mut R_points: Vec<RistrettoPoint> = Vec::with_capacity(proof.R_vec.len());
            for (Lc, Rc) in proof.L_vec.iter().zip(proof.R_vec.iter()) {
                t.validate_and_append_point(b"L", Lc)?;
                t.validate_and_append_point(b"R", Rc)?;
                let x = t.challenge_scalar(b"x_j");
                x_inv_list.push(x.invert());
                x_list.push(x);
                L_points.push(Lc.decompress().ok_or(ProofError::VerificationError)?);
                R_points.push(Rc.decompress().ok_or(ProofError::VerificationError)?);
            }

            let alpha = folding_weights(n, &x_list);

            // b_0 and aggregate G coeffs
            let b0 = weighted_sum(&alpha, public_inputs.b_slice());
            // accumulate G coefficients: -beta * a * alpha
            let neg_beta_a = -(beta_i * proof.a);
            for j in 0..n {
                agg_G_coeff[j] += neg_beta_a * alpha[j];
            }

            // x_star and point-side contributions
            t.append_point(b"S", &proof.S);
            let x_star = t.challenge_scalar(b"x_star");

            // S with +beta
            let S_pt = proof.S.decompress().ok_or(ProofError::VerificationError)?;
            agg_points.push(S_pt);
            agg_scalars.push(beta_i);

            // C with +beta * x_star
            let C_pt = C_compr.decompress().ok_or(ProofError::VerificationError)?;
            agg_points.push(C_pt);
            agg_scalars.push(beta_i * x_star);

            // L/R factors with +beta * x_star * x and x_inv
            for (k, Lp) in L_points.iter().enumerate() {
                agg_points.push(*Lp);
                agg_scalars.push(beta_i * x_star * x_list[k]);
            }
            for (k, Rp) in R_points.iter().enumerate() {
                agg_points.push(*Rp);
                agg_scalars.push(beta_i * x_star * x_inv_list[k]);
            }

            // B with -beta * r; F with -beta * a * b0
            agg_points.push(*B);
            agg_scalars.push(-(beta_i * proof.r));
            agg_points.push(*F);
            agg_scalars.push(-(beta_i * proof.a * b0));
        }

        // Single big MSM: non-fixed bases (agg_points) plus fixed G slice using aggregated coeffs
        // First do fixed G part
        let g_sum = RistrettoPoint::vartime_multiscalar_mul(agg_G_coeff.iter(), G_slice.iter());
        let other_sum =
            RistrettoPoint::vartime_multiscalar_mul(agg_scalars.iter(), agg_points.iter());
        let total = g_sum + other_sum;
        // Compare to the identity by decompressing a compressed zero or reusing vartime MSM with empty inputs
        // Here we use the fact that RistrettoPoint has no inherent is_identity; check equality to default identity via double-and-subtract trick
        // Construct identity by multiplying any base with zero
        let id = RistrettoPoint::vartime_multiscalar_mul([Scalar::ZERO].iter(), [*F].iter());
        if total == id {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }
}

impl SpringLinearProof {
    /// Returns the size in bytes required to serialize the spring linear proof.
    pub fn serialized_size(&self) -> usize {
        (self.L_vec.len() * 2 + 3) * 32
    }

    /// Serializes the proof into a byte array of (2m+3) 32-byte elements,
    /// where m = number of rounds = self.L_vec.len().
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_size());
        for (l, r) in self.L_vec.iter().zip(self.R_vec.iter()) {
            buf.extend_from_slice(l.as_bytes());
            buf.extend_from_slice(r.as_bytes());
        }
        buf.extend_from_slice(self.S.as_bytes());
        buf.extend_from_slice(self.a.as_bytes());
        buf.extend_from_slice(self.r.as_bytes());
        buf
    }

    /// Deserializes the spring linear proof from bytes.
    /// Layout: (2m + 3) 32-byte elements where m = rounds = L_vec.len().
    pub fn from_bytes(slice: &[u8]) -> Result<SpringLinearProof, ProofError> {
        let b = slice.len();
        if b % 32 != 0 {
            return Err(ProofError::FormatError);
        }
        let num_elements = b / 32;
        if num_elements < 3 {
            return Err(ProofError::FormatError);
        }
        if (num_elements - 3) % 2 != 0 {
            return Err(ProofError::FormatError);
        }
        let m = (num_elements - 3) / 2;
        if m >= 32 {
            return Err(ProofError::FormatError);
        }

        use crate::util::read32;

        let mut L_vec: Vec<CompressedRistretto> = Vec::with_capacity(m);
        let mut R_vec: Vec<CompressedRistretto> = Vec::with_capacity(m);
        for i in 0..m {
            let pos = 2 * i * 32;
            let l = CompressedRistretto(read32(&slice[pos..]));
            let r = CompressedRistretto(read32(&slice[pos + 32..]));
            l.decompress().ok_or(ProofError::FormatError)?;
            r.decompress().ok_or(ProofError::FormatError)?;
            L_vec.push(l);
            R_vec.push(r);
        }
        let pos = 2 * m * 32;
        let S = CompressedRistretto(read32(&slice[pos..]));
        S.decompress().ok_or(ProofError::FormatError)?;
        let a = Option::from(Scalar::from_canonical_bytes(read32(&slice[pos + 32..])))
            .ok_or(ProofError::FormatError)?;
        let r = Option::from(Scalar::from_canonical_bytes(read32(&slice[pos + 64..])))
            .ok_or(ProofError::FormatError)?;

        Ok(SpringLinearProof {
            L_vec,
            R_vec,
            S,
            a,
            r,
        })
    }

    /// Parse a proof only if its byte length encodes the unique round count for
    /// `dimension`. Points and scalars are parsed canonically before returning.
    pub fn from_bytes_for_dimension(
        slice: &[u8],
        dimension: usize,
    ) -> Result<SpringLinearProof, ProofError> {
        let rounds = Self::expected_rounds(dimension)?;
        let expected_bytes = rounds
            .checked_mul(2)
            .and_then(|value| value.checked_add(3))
            .and_then(|value| value.checked_mul(32))
            .ok_or(ProofError::FormatError)?;
        if slice.len() != expected_bytes {
            return Err(ProofError::FormatError);
        }
        let proof = Self::from_bytes(slice)?;
        proof
            .validate_round_count(dimension)
            .map_err(|_| ProofError::FormatError)?;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::{BulletproofGens, PedersenGens};

    #[cfg(feature = "std")]
    #[test]
    fn msm_schedule_covers_document_coarse_and_fine_shapes() {
        for workers in [0, 1, 2, 8, 16, 32, 64, usize::MAX] {
            for terms in [0, 1, 8192, 16383] {
                assert_eq!(spring_msm_chunks(terms, workers), 1);
            }
        }
        for terms in [23040, 65536, 1048576] {
            assert_eq!(spring_msm_chunks(terms, 1), 1);
        }
        assert_eq!(spring_msm_chunks(23040, 8), 16);
        for workers in [8, 16, 32] {
            assert_eq!(spring_msm_chunks(65536, workers), workers);
            assert_eq!(spring_msm_chunks(1048576, workers), 32);
        }
        for workers in [24, 28, 40, 48, 56, 64] {
            assert_eq!(spring_msm_chunks(1048576, workers), workers);
        }
        assert_eq!(spring_msm_chunks(1048576, usize::MAX), 64);
    }

    #[test]
    fn point_fold_matches_two_term_msm() {
        let generators = BulletproofGens::new(9, 1);
        let mut points: Vec<_> = generators.share(0).G(9).copied().collect();
        points.push(RistrettoPoint::default());
        for x in [
            Scalar::ZERO,
            Scalar::ONE,
            -Scalar::ONE,
            Scalar::from_bytes_mod_order([137; 32]),
        ] {
            for left in &points {
                for right in &points {
                    assert_eq!(
                        *left + x * right,
                        RistrettoPoint::vartime_multiscalar_mul([Scalar::ONE, x], [left, right])
                    );
                }
            }
        }
    }

    #[test]
    fn subset_products_match_legacy_positions() {
        let dimensions = (1..=257).chain([511, 512, 513, 1023, 1024, 1025, 23040, 65536, 1048576]);
        for n in dimensions {
            let rounds = SpringLinearProof::expected_rounds(n).unwrap();
            // Include zero and one challenges, in addition to full-width values.
            for special in [false, true] {
                let challenges: Vec<_> = (0..rounds)
                    .map(|j| {
                        if special {
                            Scalar::from((j % 3) as u64)
                        } else {
                            Scalar::from_bytes_mod_order([j as u8 + 17; 32])
                        }
                    })
                    .collect();
                let mut expected = vec![Scalar::ONE; n];
                let mut positions: Vec<_> = (0..n).collect();
                let power = n.next_power_of_two();
                let mut current = n;
                let mut start_round = 0;
                if n != power {
                    let half = power / 2;
                    let ih0 = (2 * half - n) / 2;
                    let it1 = n / 2;
                    apply_precompression_positions(
                        &mut expected,
                        &mut positions,
                        n,
                        ih0,
                        it1.saturating_sub(1),
                        half,
                        n - half,
                        it1,
                        challenges[0],
                    );
                    current = half;
                    start_round = 1;
                }
                for x in challenges.iter().skip(start_round) {
                    update_fold_positions(&mut expected, &mut positions, current, current / 2, *x);
                    current /= 2;
                }
                assert_eq!(folding_weights(n, &challenges), expected, "dimension {n}");
            }
        }
    }

    #[test]
    fn dimension_bound_parser_rejects_wrong_round_count_and_invalid_points() {
        let expected = (2 * SpringLinearProof::expected_rounds(128).unwrap() + 3) * 32;
        let canonical_zero_proof = vec![0u8; expected];
        SpringLinearProof::from_bytes_for_dimension(&canonical_zero_proof, 128).unwrap();
        assert!(matches!(
            SpringLinearProof::from_bytes_for_dimension(
                &canonical_zero_proof[..expected - 64],
                128
            ),
            Err(ProofError::FormatError)
        ));

        let mut invalid_point = canonical_zero_proof;
        invalid_point[..32].fill(0xff);
        assert!(matches!(
            SpringLinearProof::from_bytes_for_dimension(&invalid_point, 128),
            Err(ProofError::FormatError)
        ));
    }

    fn test_helper(n: usize) {
        let mut rng = rand::thread_rng();
        let n_pow2 = n.next_power_of_two();
        let bp_gens = BulletproofGens::new(n_pow2, 1);
        let G: Vec<RistrettoPoint> = bp_gens.share(0).G(n_pow2).cloned().collect();
        let ped = PedersenGens::default();
        let F = ped.B;
        let B = ped.B_blinding;

        let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let mut prover_transcript = Transcript::new(b"springlinearprooftest");

        // C = <a, G[..n]> + r * B + <a, b> * F  (G_len = n_pow2, a,b length n)
        let r = Scalar::random(&mut rng);
        let c = inner_product(&a, &b);
        // Build full-length a_full with zeros to align with G for commitment only
        let mut a_full = a.clone();
        a_full.resize(n_pow2, Scalar::ZERO);
        let C = RistrettoPoint::vartime_multiscalar_mul(
            a_full.iter().chain(iter::once(&r)).chain(iter::once(&c)),
            G.iter().chain(Some(&B)).chain(iter::once(&F)),
        )
        .compress();

        let proof = SpringLinearProof::create(
            &mut prover_transcript,
            &mut rng,
            &C,
            r,
            a,
            b.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();

        let mut verifier_transcript = Transcript::new(b"springlinearprooftest");
        assert!(proof
            .verify(&mut verifier_transcript, &C, &G, &F, &B, b)
            .is_ok());
    }

    #[test]
    fn test_spring_linear_proof_3() {
        test_helper(3);
    }
    #[test]
    fn test_spring_linear_proof_127() {
        test_helper(127);
    }
    #[test]
    fn test_spring_linear_proof_3092() {
        test_helper(3092);
    }
    #[test]
    fn test_spring_linear_proof_pow2() {
        test_helper(1024);
    }
    #[test]
    fn test_spring_linear_proof_968() {
        test_helper(968);
    }
    #[test]
    fn test_spring_linear_proof_3072() {
        test_helper(3072);
    }

    #[test]
    fn test_spring_linear_proof_negative() {
        let mut rng = rand::thread_rng();
        use crate::generators::{BulletproofGens, PedersenGens};
        let n = 968usize;
        let n_pow2 = n.next_power_of_two();
        let bp_gens = BulletproofGens::new(n_pow2, 1);
        let G: Vec<RistrettoPoint> = bp_gens.share(0).G(n_pow2).cloned().collect();
        let ped = PedersenGens::default();
        let F = ped.B;
        let B = ped.B_blinding;

        let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let mut b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let mut prover_transcript = Transcript::new(b"springlinearprooftest_neg");
        let r = Scalar::random(&mut rng);
        let c = inner_product(&a, &b);
        let mut a_full = a.clone();
        a_full.resize(n_pow2, Scalar::ZERO);
        let C = RistrettoPoint::vartime_multiscalar_mul(
            a_full.iter().chain(iter::once(&r)).chain(iter::once(&c)),
            G.iter().chain(Some(&B)).chain(iter::once(&F)),
        )
        .compress();

        let proof = SpringLinearProof::create(
            &mut prover_transcript,
            &mut rng,
            &C,
            r,
            a,
            b.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();

        // Tamper with the public vector b; verification should fail.
        b[0] = b[0] + Scalar::ONE;
        let mut verifier_transcript = Transcript::new(b"springlinearprooftest_neg");
        assert!(proof
            .verify(&mut verifier_transcript, &C, &G, &F, &B, b)
            .is_err());
    }

    #[test]
    fn test_spring_linear_proof_multi_rounds() {
        use crate::generators::{BulletproofGens, PedersenGens};
        let dims = [1024usize, 968usize, 3072usize];
        let rounds = [5usize, 5usize, 2usize];
        for (idx, &n) in dims.iter().enumerate() {
            for _ in 0..rounds[idx] {
                let mut rng = rand::thread_rng();
                let n_pow2 = n.next_power_of_two();
                let bp_gens = BulletproofGens::new(n_pow2, 1);
                let G: Vec<RistrettoPoint> = bp_gens.share(0).G(n_pow2).cloned().collect();
                let ped = PedersenGens::default();
                let F = ped.B;
                let B = ped.B_blinding;
                let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                let mut prover_transcript = Transcript::new(b"springlinearprooftest_multi");
                let r = Scalar::random(&mut rng);
                let c = inner_product(&a, &b);
                let mut a_full = a.clone();
                a_full.resize(n_pow2, Scalar::ZERO);
                let C = RistrettoPoint::vartime_multiscalar_mul(
                    a_full.iter().chain(iter::once(&r)).chain(iter::once(&c)),
                    G.iter().chain(Some(&B)).chain(iter::once(&F)),
                )
                .compress();
                let proof = SpringLinearProof::create(
                    &mut prover_transcript,
                    &mut rng,
                    &C,
                    r,
                    a,
                    b.clone(),
                    G.clone(),
                    &F,
                    &B,
                )
                .unwrap();
                let mut verifier_transcript = Transcript::new(b"springlinearprooftest_multi");
                assert!(proof
                    .verify(&mut verifier_transcript, &C, &G, &F, &B, b)
                    .is_ok());
            }
        }
    }

    #[test]
    fn test_spring_linear_proof_sparse_vectors() {
        use crate::generators::{BulletproofGens, PedersenGens};
        let mut rng = rand::thread_rng();
        let n = 512usize;
        let n_pow2 = n.next_power_of_two();
        let bp_gens = BulletproofGens::new(n_pow2, 1);
        let G: Vec<RistrettoPoint> = bp_gens.share(0).G(n_pow2).cloned().collect();
        let ped = PedersenGens::default();
        let F = ped.B;
        let B = ped.B_blinding;
        let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let mut b: Vec<Scalar> = vec![Scalar::ZERO; n];
        b[0] = Scalar::from(7u64);
        b[7] = Scalar::from(9u64);
        b[n - 1] = Scalar::from(3u64);
        let r = Scalar::random(&mut rng);
        let c = inner_product(&a, &b);
        let mut a_full = a.clone();
        a_full.resize(n_pow2, Scalar::ZERO);
        let C = RistrettoPoint::vartime_multiscalar_mul(
            a_full.iter().chain(iter::once(&r)).chain(iter::once(&c)),
            G.iter().chain(Some(&B)).chain(iter::once(&F)),
        )
        .compress();
        let mut prover_transcript = Transcript::new(b"springlinearprooftest_sparse");
        let proof = SpringLinearProof::create(
            &mut prover_transcript,
            &mut rng,
            &C,
            r,
            a,
            b.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();
        let mut verifier_transcript = Transcript::new(b"springlinearprooftest_sparse");
        assert!(proof
            .verify(&mut verifier_transcript, &C, &G, &F, &B, b)
            .is_ok());
    }

    #[test]
    fn test_spring_linear_proof_deterministic_seed() {
        use crate::generators::{BulletproofGens, PedersenGens};
        use rand_chacha::ChaCha20Rng;
        use rand_core::SeedableRng;
        let seed: u64 = 42;
        let n = 257usize;
        let n_pow2 = n.next_power_of_two();
        let bp_gens = BulletproofGens::new(n_pow2, 1);
        let G: Vec<RistrettoPoint> = bp_gens.share(0).G(n_pow2).cloned().collect();
        let ped = PedersenGens::default();
        let F = ped.B;
        let B = ped.B_blinding;
        let mut rng1 = ChaCha20Rng::seed_from_u64(seed);
        let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng1)).collect();
        let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng1)).collect();
        let r = Scalar::random(&mut rng1);
        let c = inner_product(&a, &b);
        let mut a_full = a.clone();
        a_full.resize(n_pow2, Scalar::ZERO);
        let C = RistrettoPoint::vartime_multiscalar_mul(
            a_full.iter().chain(iter::once(&r)).chain(iter::once(&c)),
            G.iter().chain(Some(&B)).chain(iter::once(&F)),
        )
        .compress();
        let mut prover_transcript1 = Transcript::new(b"springlinearprooftest_det");
        let mut rng2 = ChaCha20Rng::seed_from_u64(seed);
        let proof1 = SpringLinearProof::create(
            &mut prover_transcript1,
            &mut rng2,
            &C,
            r,
            a.clone(),
            b.clone(),
            G.clone(),
            &F,
            &B,
        )
        .unwrap();
        let bytes1 = proof1.to_bytes();
        let mut prover_transcript2 = Transcript::new(b"springlinearprooftest_det");
        let mut rng3 = ChaCha20Rng::seed_from_u64(seed);
        let proof2 =
            SpringLinearProof::create(&mut prover_transcript2, &mut rng3, &C, r, a, b, G, &F, &B)
                .unwrap();
        let bytes2 = proof2.to_bytes();
        assert_eq!(bytes1, bytes2, "deterministic with fixed seed and inputs");
    }
}
