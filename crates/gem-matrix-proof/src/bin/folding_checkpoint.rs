//! Measure equivalent public-challenge point folds before selecting a kernel.
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::VartimeMultiscalarMul};
use gem_matrix_proof::generators_v1;
use rayon::prelude::*;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "32768".into())
        .parse::<usize>()?;
    let g = generators_v1(2 * n)?;
    let x = Scalar::from_bytes_mod_order([71; 32]);
    let mut reference = None;
    for threads in [1, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()?;
        // Alternate order to expose a consistently slower kernel.
        for iteration in 0..4 {
            for offset in 0..3 {
                let kernel = (offset + iteration) % 3;
                let start = Instant::now();
                let points: Vec<_> = pool.install(|| {
                    (0..n)
                        .into_par_iter()
                        .map(|i| match kernel {
                            0 => RistrettoPoint::vartime_multiscalar_mul(
                                [Scalar::ONE, x],
                                [g[i], g[n + i]],
                            ),
                            1 => g[i] + RistrettoPoint::vartime_multiscalar_mul([x], [g[n + i]]),
                            _ => g[i] + x * g[n + i],
                        })
                        .collect()
                });
                let ms = start.elapsed().as_secs_f64() * 1000.;
                if let Some(expected) = &reference {
                    assert_eq!(&points, expected);
                } else {
                    reference = Some(points.clone());
                }
                println!(
                    "{}",
                    serde_json::json!({"n":n,"threads":threads,"iteration":iteration,"kernel":kernel,"wall_ms":ms,"equal":true})
                );
            }
        }
    }
    Ok(())
}
