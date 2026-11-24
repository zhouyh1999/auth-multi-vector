#![allow(non_snake_case)]
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use rand::thread_rng;

use bulletproofs::{BulletproofGens, LinearProof, PedersenGens, SpringLinearProof};

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len());
    let mut acc = Scalar::ZERO;
    for i in 0..a.len() {
        acc += a[i] * b[i];
    }
    acc
}

fn bench_dims() -> Vec<usize> {
    vec![3, 127, 255, 256, 511, 512, 968, 1024, 2048, 3072]
}

fn build_commitment(
    G: &[RistrettoPoint],
    a: &[Scalar],
    r: &Scalar,
    c: &Scalar,
    F: &RistrettoPoint,
    B: &RistrettoPoint,
) -> curve25519_dalek::ristretto::CompressedRistretto {
    RistrettoPoint::vartime_multiscalar_mul(
        a.iter().chain(std::iter::once(r)).chain(std::iter::once(c)),
        G.iter().chain(std::iter::once(B)).chain(std::iter::once(F)),
    )
    .compress()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("spring_vs_padding");

    for n in bench_dims() {
        // Generators: allocate up to next power of two for padding baseline
        let n_pow2 = n.next_power_of_two();
        let bp_gens = BulletproofGens::new(n_pow2, 1);
        let G_all: Vec<RistrettoPoint> = bp_gens.share(0).G(n_pow2).cloned().collect();
        let ped = PedersenGens::default();
        let F = ped.B;
        let B = ped.B_blinding;

        // Random inputs per benchmark iteration batch
        group.bench_function(format!("spring_create_n{}", n), |bch| {
            bch.iter_batched(
                || {
                    let mut rng = thread_rng();
                    let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    let r = Scalar::random(&mut rng);
                    let c_ip = inner_product(&a, &b);
                    let C = build_commitment(&G_all[..n], &a, &r, &c_ip, &F, &B);
                    (a, b, r, C)
                },
                |(a, b, r, C)| {
                    let mut rng = thread_rng();
                    let mut t = Transcript::new(b"bench_spring");
                    let _ = SpringLinearProof::create(
                        &mut t,
                        &mut rng,
                        &C,
                        r,
                        a,
                        b,
                        G_all[..n].to_vec(),
                        &F,
                        &B,
                    )
                    .unwrap();
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("spring_verify_n{}", n), |bch| {
            bch.iter_batched(
                || {
                    let mut rng = thread_rng();
                    let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    let r = Scalar::random(&mut rng);
                    let c_ip = inner_product(&a, &b);
                    let C = build_commitment(&G_all[..n], &a, &r, &c_ip, &F, &B);
                    let mut t = Transcript::new(b"bench_spring");
                    let proof = SpringLinearProof::create(
                        &mut t,
                        &mut rng,
                        &C,
                        r,
                        a,
                        b.clone(),
                        G_all[..n].to_vec(),
                        &F,
                        &B,
                    )
                    .unwrap();
                    (proof, C, b)
                },
                |(proof, C, b)| {
                    let mut t = Transcript::new(b"bench_spring");
                    let _ = proof.verify(&mut t, &C, &G_all, &F, &B, b).unwrap();
                },
                BatchSize::SmallInput,
            );
        });

        // Zero padding baseline using LinearProof
        group.bench_function(format!("padding_create_n{}", n), |bch| {
            bch.iter_batched(
                || {
                    let mut rng = thread_rng();
                    let mut a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    let r = Scalar::random(&mut rng);
                    let c_ip = inner_product(&a, &b);
                    // pad a,b to n_pow2 with zeros
                    a.resize(n_pow2, Scalar::ZERO);
                    let mut b_pad = b.clone();
                    b_pad.resize(n_pow2, Scalar::ZERO);
                    let C = build_commitment(&G_all, &a, &r, &c_ip, &F, &B);
                    (a, b_pad, r, C)
                },
                |(a_pad, b_pad, r, C)| {
                    let mut rng = thread_rng();
                    let mut t = Transcript::new(b"bench_padding");
                    let _ = LinearProof::create(
                        &mut t,
                        &mut rng,
                        &C,
                        r,
                        a_pad,
                        b_pad,
                        G_all.clone(),
                        &F,
                        &B,
                    )
                    .unwrap();
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("padding_verify_n{}", n), |bch| {
            bch.iter_batched(
                || {
                    let mut rng = thread_rng();
                    let mut a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
                    let r = Scalar::random(&mut rng);
                    let c_ip = inner_product(&a, &b);
                    a.resize(n_pow2, Scalar::ZERO);
                    let mut b_pad = b.clone();
                    b_pad.resize(n_pow2, Scalar::ZERO);
                    let C = build_commitment(&G_all, &a, &r, &c_ip, &F, &B);
                    let mut t = Transcript::new(b"bench_padding");
                    let proof = LinearProof::create(
                        &mut t,
                        &mut rng,
                        &C,
                        r,
                        a,
                        b_pad.clone(),
                        G_all.clone(),
                        &F,
                        &B,
                    )
                    .unwrap();
                    (proof, C, b_pad)
                },
                |(proof, C, b_pad)| {
                    let mut t = Transcript::new(b"bench_padding");
                    let _ = proof.verify(&mut t, &C, &G_all, &F, &B, b_pad).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
