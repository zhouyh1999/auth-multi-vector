//! Cost/equality experiment for dalek's public static-point precomputation API.
use curve25519_dalek::{
    ristretto::{RistrettoPoint, VartimeRistrettoPrecomputation},
    scalar::Scalar,
    traits::{VartimeMultiscalarMul, VartimePrecomputedMultiscalarMul},
};
use gem_matrix_proof::generators_v1;
use rayon::prelude::*;
use std::time::Instant;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n = 65_536;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(8).build()?;
    let g = pool.install(|| generators_v1(n))?;
    let coefficients: Vec<_> = (0..n)
        .map(|i| {
            let mut bytes = [111; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            Scalar::from_bytes_mod_order(bytes)
        })
        .collect();
    let reference = RistrettoPoint::vartime_multiscalar_mul(&coefficients, g.iter());
    let start = Instant::now();
    let tables: Vec<_> = pool.install(|| {
        g.par_chunks(n / 8)
            .map(|p| VartimeRistrettoPrecomputation::new(p.iter()))
            .collect()
    });
    let setup_ms = start.elapsed().as_secs_f64() * 1000.;
    for iteration in 0..4 {
        for offset in 0..2 {
            let kernel = (offset + iteration) % 2;
            let start = Instant::now();
            let got = pool.install(|| {
                if kernel == 0 {
                    coefficients
                        .par_chunks(n / 8)
                        .zip(g.par_chunks(n / 8))
                        .map(|(a, g)| RistrettoPoint::vartime_multiscalar_mul(a, g.iter()))
                        .reduce(RistrettoPoint::default, |a, b| a + b)
                } else {
                    coefficients
                        .par_chunks(n / 8)
                        .zip(tables.par_iter())
                        .map(|(a, t)| t.vartime_multiscalar_mul(a))
                        .reduce(RistrettoPoint::default, |a, b| a + b)
                }
            });
            assert_eq!(got, reference);
            println!(
                "{}",
                serde_json::json!({"dimension":n,"threads":8,"iteration":iteration,
                "kernel":kernel,"ms":start.elapsed().as_secs_f64()*1000.,"setup_ms":setup_ms,
                "peak_memory":std::fs::read_to_string("/proc/self/status")?.lines().find(|l|l.starts_with("VmHWM:")).unwrap_or("unknown"),"equal":true})
            );
        }
    }
    Ok(())
}
