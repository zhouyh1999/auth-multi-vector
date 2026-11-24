//! Compare two ordinary public-challenge folds with an equivalent four-term MSM.
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::VartimeMultiscalarMul};
use gem_matrix_proof::generators_v1;
use rayon::prelude::*;
use std::time::Instant;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n = 32_768;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(8).build()?;
    let g = pool.install(|| generators_v1(n * 4))?;
    let x = Scalar::from_bytes_mod_order([91; 32]);
    let y = Scalar::from_bytes_mod_order([121; 32]);
    let xy = x * y;
    let mut reference = None;
    for iteration in 0..4 {
        for offset in 0..2 {
            let kernel = (offset + iteration) % 2;
            let start = Instant::now();
            let points: Vec<_> = pool.install(|| {
                if kernel == 0 {
                    let first: Vec<_> = (0..2 * n)
                        .into_par_iter()
                        .map(|i| g[i] + x * g[2 * n + i])
                        .collect();
                    (0..n)
                        .into_par_iter()
                        .map(|i| first[i] + y * first[n + i])
                        .collect()
                } else {
                    (0..n)
                        .into_par_iter()
                        .map(|i| {
                            RistrettoPoint::vartime_multiscalar_mul(
                                [Scalar::ONE, y, x, xy],
                                [g[i], g[n + i], g[2 * n + i], g[3 * n + i]],
                            )
                        })
                        .collect()
                }
            });
            let ms = start.elapsed().as_secs_f64() * 1000.;
            if let Some(r) = &reference {
                assert_eq!(&points, r);
            } else {
                reference = Some(points);
            }
            println!(
                "{}",
                serde_json::json!({"dimension":4*n,"threads":8,"iteration":iteration,"kernel":kernel,"ms":ms,"equal":true})
            );
        }
    }
    Ok(())
}
