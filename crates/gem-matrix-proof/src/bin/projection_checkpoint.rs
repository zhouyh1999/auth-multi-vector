//! Reproducible full-shape component acceptance and measurements, separate from unit tests.
use gem_matrix_proof::*;
use rand::{Rng, SeedableRng, rngs::OsRng, rngs::StdRng};
use std::time::Instant;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let threads = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "8".into())
        .parse::<usize>()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;
    let profile = std::env::args()
        .nth(2)
        .unwrap_or_else(|| gem_core::FIXED_PROFILE_ID_V1.into());
    if ![
        gem_core::FIXED_PROFILE_ID_V1,
        gem_core::COMPACT_PROFILE_ID_V1,
    ]
    .contains(&profile.as_str())
    {
        return Err("unknown numeric profile".into());
    }
    let use_prepared = std::env::args().nth(3).is_some_and(|x| x == "prepared");
    let mut rng = StdRng::seed_from_u64(20261006);
    for (rows, cols) in [(180, 128), (512, 128), (8192, 128)] {
        let n = rows * cols;
        let start = Instant::now();
        generators_v1(n)?;
        let gen_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        prepare_projection_generators_v1(n)?;
        let encodings_ms = start.elapsed().as_secs_f64() * 1000.;
        let a: Vec<_> = (0..n)
            .map(|_| scalar_i32_v1(rng.gen_range(-30000..30000)))
            .collect();
        let start = Instant::now();
        let commitment = commit_scalars_v1(&a)?;
        let commit_ms = start.elapsed().as_secs_f64() * 1000.;
        let ctx = ProjectionContextV1 {
            binding: [17; 32],
            stage: ProjectionStageV1::Fine,
            rows,
            columns: cols,
            commitment,
        };
        let started = Instant::now();
        let prepared = if use_prepared {
            Some(PreparedProjectionWitnessV1::new(a.clone())?)
        } else {
            None
        };
        let preparation_ms = started.elapsed().as_secs_f64() * 1000.;
        let (p, pt) = if let Some(prepared) = &prepared {
            prove_projection_with_prepared_witness_v1(&profile, &ctx, prepared, &mut OsRng)?
        } else {
            prove_projection_with_profile_v1(&profile, &ctx, &a, &mut OsRng)?
        };
        let (_, vt) = verify_projection_with_profile_v1(&profile, &ctx, &p)?;
        let bad = ProjectionContextV1 {
            binding: [18; 32],
            ..ctx.clone()
        };
        assert!(verify_projection_with_profile_v1(&profile, &bad, &p).is_err());
        let mut wrong = p.clone();
        wrong.projection[0] = [255; 32];
        assert!(verify_projection_with_profile_v1(&profile, &ctx, &wrong).is_err());
        let rss = std::fs::read_to_string("/proc/self/status")?
            .lines()
            .find(|l| l.starts_with("VmHWM:"))
            .unwrap_or("unavailable")
            .to_string();
        println!(
            "{}",
            serde_json::json!({"prepared":use_prepared,"preparation_ms":preparation_ms,"profile":profile,"dimension":n,"argument_bytes":p.argument.len(),"projection_bytes":p.projection.len()*32,"threads":threads,"generator_ms":gen_ms,"generator_encodings_ms":encodings_ms,"commit_ms":commit_ms,"prover":pt,"verifier":vt,"peak_memory":rss,"generated_verified":true,"tamper_rejected":true})
        );
    }
    Ok(())
}
