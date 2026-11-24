#![allow(non_snake_case)]

use core::iter;
use std::time::Instant;

use bulletproofs::{
    BulletproofGens, InnerProductProof, LinearProof, PedersenGens, ProofError, TranscriptProtocol,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use rand::thread_rng;
use sha3::Sha3_512;

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut out = Scalar::ZERO;
    assert_eq!(a.len(), b.len());
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

fn pad_to_power_of_two(mut v: Vec<Scalar>) -> Vec<Scalar> {
    if v.is_empty() {
        return v;
    }
    let mut n = v.len();
    if n.is_power_of_two() {
        return v;
    }
    let mut pow2 = 1usize;
    while pow2 < n {
        pow2 <<= 1;
    }
    v.resize(pow2, Scalar::ZERO);
    v
}

fn bench_n(n: usize) -> Result<(), ProofError> {
    let mut rng = thread_rng();

    let bp_gens = BulletproofGens::new(n, 1);
    let G: Vec<RistrettoPoint> = bp_gens.share(0).G(n).cloned().collect();
    let H: Vec<RistrettoPoint> = bp_gens.share(0).H(n).cloned().collect();
    let ped = PedersenGens::default();
    let F = ped.B;
    let B = ped.B_blinding;

    let mut a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let mut b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    a = pad_to_power_of_two(a);
    b = pad_to_power_of_two(b);
    let n_pow2 = a.len();

    let c = inner_product(&a, &b);

    // ---------- LinearProof ----------
    // C = <a, G> + r * B + <a, b> * F
    let r = Scalar::random(&mut rng);
    let C = RistrettoPoint::vartime_multiscalar_mul(
        a.iter().chain(iter::once(&r)).chain(iter::once(&c)),
        G.iter().chain(iter::once(&B)).chain(iter::once(&F)),
    )
    .compress();

    let mut prover_ts = Transcript::new(b"ipa-compare-linear");
    let t0 = Instant::now();
    let lin_proof = LinearProof::create(
        &mut prover_ts,
        &mut rng,
        &C,
        r,
        a.clone(),
        b.clone(),
        G.clone(),
        &F,
        &B,
    )?;
    let linear_create_ms = t0.elapsed().as_millis();
    let linear_size_bytes = lin_proof.to_bytes().len();
    let linear_size_bits = linear_size_bytes * 8;

    let mut verifier_ts = Transcript::new(b"ipa-compare-linear");
    let t1 = Instant::now();
    lin_proof.verify(&mut verifier_ts, &C, &G, &F, &B, b.clone())?;
    let linear_verify_ms = t1.elapsed().as_millis();

    // ---------- InnerProductProof ----------
    let Q = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"ipa-compare-Q");
    let mut ipp_ts = Transcript::new(b"ipa-compare-ipp");

    let G_factors: Vec<Scalar> = iter::repeat(Scalar::ONE).take(n_pow2).collect();
    let H_factors: Vec<Scalar> = iter::repeat(Scalar::ONE).take(n_pow2).collect();

    let P = RistrettoPoint::vartime_multiscalar_mul(
        a.iter()
            .cloned()
            .chain(b.iter().cloned())
            .chain(iter::once(c)),
        G.iter()
            .cloned()
            .chain(H.iter().cloned())
            .chain(iter::once(Q)),
    );

    let t2 = Instant::now();
    let ipp_proof = InnerProductProof::create(
        &mut ipp_ts,
        &Q,
        &G_factors,
        &H_factors,
        G.clone(),
        H.clone(),
        a.clone(),
        b.clone(),
    );
    let ipp_create_ms = t2.elapsed().as_millis();
    let ipp_size_bytes = ipp_proof.to_bytes().len();
    let ipp_size_bits = ipp_size_bytes * 8;

    let mut ipp_ver_ts = Transcript::new(b"ipa-compare-ipp");
    let t3 = Instant::now();
    ipp_proof.verify(
        n_pow2,
        &mut ipp_ver_ts,
        G_factors.iter().cloned(),
        H_factors.iter().cloned(),
        &P,
        &Q,
        &G,
        &H,
    )?;
    let ipp_verify_ms = t3.elapsed().as_millis();

    println!(
        "n={n_pow2}: LinearProof create={linear_create_ms}ms, verify={linear_verify_ms}ms, size={linear_size_bytes} bytes ({linear_size_bits} bits) | IPP create={ipp_create_ms}ms, verify={ipp_verify_ms}ms, size={ipp_size_bytes} bytes ({ipp_size_bits} bits)"
    );

    Ok(())
}

fn main() -> Result<(), ProofError> {
    let sizes = [16usize, 32, 64, 128];
    for n in sizes.iter().copied() {
        bench_n(n)?;
    }
    Ok(())
}
