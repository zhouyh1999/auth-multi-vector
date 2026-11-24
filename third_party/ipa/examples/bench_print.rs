#![allow(non_snake_case)]
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use libc::{clock_gettime, timespec, CLOCK_PROCESS_CPUTIME_ID};
use merlin::Transcript;
use rand::thread_rng;
use std::time::Instant;

use bulletproofs::{BulletproofGens, LinearProof, PedersenGens, SpringLinearProof};

fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len());
    let mut acc = Scalar::ZERO;
    for i in 0..a.len() {
        acc += a[i] * b[i];
    }
    acc
}

fn dims() -> Vec<usize> {
    vec![3, 127, 255, 256, 511, 512, 968, 1024, 2048, 3072]
}

fn now_cpu_ns() -> u128 {
    unsafe {
        let mut ts: timespec = std::mem::zeroed();
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts as *mut timespec);
        (ts.tv_sec as u128) * 1_000_000_000u128 + (ts.tv_nsec as u128)
    }
}

fn main() {
    println!("springproofs-linear proof vs zero-padding + linear proof\n");
    println!("Note: times measure only create()/verify() (excluding commitment C computation)\n");

    for n in dims() {
        let n_pow2 = n.next_power_of_two();
        let bp_gens = BulletproofGens::new(n_pow2, 1);
        let G_all: Vec<RistrettoPoint> = bp_gens.share(0).G(n_pow2).cloned().collect();
        let ped = PedersenGens::default();
        let F = ped.B;
        let B = ped.B_blinding;

        // prepare random inputs
        let mut rng = thread_rng();
        let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let r = Scalar::random(&mut rng);
        let c_ip = inner_product(&a, &b);

        // commitment built once, outside timing
        let C_spring = RistrettoPoint::vartime_multiscalar_mul(
            a.iter()
                .chain(std::iter::once(&r))
                .chain(std::iter::once(&c_ip)),
            G_all[..n]
                .iter()
                .chain(std::iter::once(&B))
                .chain(std::iter::once(&F)),
        )
        .compress();

        // spring create
        let mut t = Transcript::new(b"bench_print_spring");
        let wall0 = Instant::now();
        let cpu0 = now_cpu_ns();
        let proof_spring = SpringLinearProof::create(
            &mut t,
            &mut rng,
            &C_spring,
            r,
            a.clone(),
            b.clone(),
            G_all[..n].to_vec(),
            &F,
            &B,
        )
        .unwrap();
        let create_spring_wall_ms = wall0.elapsed().as_secs_f64() * 1000.0;
        let create_spring_cpu_ms = (now_cpu_ns() - cpu0) as f64 / 1e6;

        // spring verify
        let mut t2 = Transcript::new(b"bench_print_spring");
        let wall0 = Instant::now();
        let cpu0 = now_cpu_ns();
        proof_spring
            .verify(&mut t2, &C_spring, &G_all, &F, &B, b.clone())
            .unwrap();
        let verify_spring_wall_ms = wall0.elapsed().as_secs_f64() * 1000.0;
        let verify_spring_cpu_ms = (now_cpu_ns() - cpu0) as f64 / 1e6;

        // padding baseline
        let mut a_pad = a.clone();
        let mut b_pad = b.clone();
        a_pad.resize(n_pow2, Scalar::ZERO);
        b_pad.resize(n_pow2, Scalar::ZERO);
        let C_pad = RistrettoPoint::vartime_multiscalar_mul(
            a_pad
                .iter()
                .chain(std::iter::once(&r))
                .chain(std::iter::once(&c_ip)),
            G_all
                .iter()
                .chain(std::iter::once(&B))
                .chain(std::iter::once(&F)),
        )
        .compress();

        // padding create
        let mut t3 = Transcript::new(b"bench_print_padding");
        let wall0 = Instant::now();
        let cpu0 = now_cpu_ns();
        let proof_pad = LinearProof::create(
            &mut t3,
            &mut rng,
            &C_pad,
            r,
            a_pad.clone(),
            b_pad.clone(),
            G_all.clone(),
            &F,
            &B,
        )
        .unwrap();
        let create_pad_wall_ms = wall0.elapsed().as_secs_f64() * 1000.0;
        let create_pad_cpu_ms = (now_cpu_ns() - cpu0) as f64 / 1e6;

        // padding verify
        let mut t4 = Transcript::new(b"bench_print_padding");
        let wall0 = Instant::now();
        let cpu0 = now_cpu_ns();
        proof_pad
            .verify(&mut t4, &C_pad, &G_all, &F, &B, b_pad.clone())
            .unwrap();
        let verify_pad_wall_ms = wall0.elapsed().as_secs_f64() * 1000.0;
        let verify_pad_cpu_ms = (now_cpu_ns() - cpu0) as f64 / 1e6;

        println!(
            "n={:<5} | spring: create={:>7.3}/{:>7.3} ms, verify={:>7.3}/{:>7.3} ms | padding: create={:>7.3}/{:>7.3} ms, verify={:>7.3}/{:>7.3} ms",
            n,
            create_spring_wall_ms, create_spring_cpu_ms,
            verify_spring_wall_ms, verify_spring_cpu_ms,
            create_pad_wall_ms, create_pad_cpu_ms,
            verify_pad_wall_ms, verify_pad_cpu_ms,
        );
    }
}
