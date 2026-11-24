use super::*;

// A small authentication-kernel experiment, not a production VO change.
// Every layout uses the same locally pinned catalog policy and numeric profile.
// Static generators and (only for B=1) static proof witnesses are prepared offline.
pub(super) struct FairWork {
    pub(super) name: String,
    pub(super) stage: ProjectionStageV1,
    pub(super) request: SchemeRequestV3,
    pub(super) documents: Vec<Vec<Coordinate>>,
    pub(super) matrices: CandidateMatricesV3,
    pub(super) source: Hash,
    pub(super) global_rows: usize,
}
pub(super) struct FairCase {
    pub(super) h: usize,
    pub(super) blocks: Vec<PilotBlock>,
    pub(super) commitments: Vec<[u8; 32]>,
    pub(super) catalog: Hash,
    pub(super) points: Vec<curve25519_dalek::ristretto::RistrettoPoint>,
    pub(super) prepared: Option<PreparedProjectionWitnessV1>,
}
pub(super) fn fair_catalog(
    w: &FairWork,
    h: usize,
    bs: &[PilotBlock],
    cs: &[[u8; 32]],
) -> Result<Hash> {
    if w.name != "rerank" {
        // A complete codebook opens its entire ordered list. Bind the layout
        // and the same source and generator identifiers used by the kernel.
        return hash(
            b"gem.bench.codebook-block.owner.v1",
            &(
                w.name.as_str(),
                w.global_rows,
                h,
                usize::from(w.request.query.dimension),
                numeric::PROFILE_ID,
                gem_matrix_proof::GENERATOR_ID_V1,
                w.source,
                cs,
            ),
        );
    }
    let boundaries: Vec<_> = w.matrices.iter().map(|(id, n, _)| (*id, *n)).collect();
    hash(
        b"gem.fair-endpoints.catalog.v1",
        &(
            w.source,
            w.stage,
            numeric::PROFILE_ID,
            gem_matrix_proof::GENERATOR_ID_V1,
            h,
            usize::from(w.request.query.dimension),
            boundaries,
            bs,
            cs,
        ),
    )
}
pub(super) fn fair_weights(c: &FairCase, binding: Hash) -> Result<Vec<Scalar>> {
    if c.blocks.len() == 1 {
        Ok(vec![Scalar::ONE])
    } else {
        document_weights_v1(binding, c.blocks.len())
    }
}
pub(super) fn fair_commitment(c: &FairCase, ws: &[Scalar]) -> Result<[u8; 32]> {
    fair_commitment_from_points(&c.commitments, &c.points, ws)
}
pub(super) fn fair_commitment_from_points(
    compressed: &[[u8; 32]],
    points: &[curve25519_dalek::ristretto::RistrettoPoint],
    ws: &[Scalar],
) -> Result<[u8; 32]> {
    use curve25519_dalek::{ristretto::RistrettoPoint, traits::VartimeMultiscalarMul};
    if compressed.len() == 1 {
        return Ok(compressed[0]);
    }
    // The authenticated points are static for every h and may all be decoded
    // offline. The same MSM scheduling rule applies to every layout.
    let chunk = if ws.len() < 4096 {
        ws.len()
    } else {
        ws.len()
            .div_ceil(rayon::current_num_threads() * 2)
            .max(1024)
    };
    Ok(ws
        .par_chunks(chunk)
        .zip(points.par_chunks(chunk))
        .map(|(a, g)| RistrettoPoint::vartime_multiscalar_mul(a.iter(), g.iter()))
        .reduce(RistrettoPoint::default, |a, b| a + b)
        .compress()
        .to_bytes())
}
pub(super) fn fair_context(
    w: &FairWork,
    c: &FairCase,
    b: Hash,
    point: [u8; 32],
) -> ProjectionContextV1 {
    ProjectionContextV1 {
        binding: b,
        stage: w.stage,
        rows: c.h,
        columns: usize::from(w.request.query.dimension),
        commitment: point,
    }
}
// One deterministic scheduling rule for ALL h. Unlike fixed 128-coordinate
// tiles, h=1 still exposes enough parallel tasks to the same worker pool.
pub(super) fn fair_aggregate(
    pieces: &[&[Coordinate]],
    ws: &[Scalar],
    dimension: usize,
) -> Vec<Scalar> {
    let mut out = vec![Scalar::ZERO; dimension];
    let tile = dimension
        .div_ceil(rayon::current_num_threads() * 4)
        .clamp(1, 128);
    for (batch, weights) in pieces.chunks(1024).zip(ws.chunks(1024)) {
        let mut tables = vec![Scalar::ZERO; weights.len() * 512];
        tables
            .par_chunks_mut(512)
            .zip(weights.par_iter())
            .for_each(|(t, w)| {
                let high = w * Scalar::from(256u64);
                for i in 1..256 {
                    t[i] = t[i - 1] + w;
                    t[256 + i] = t[255 + i] + high;
                }
            });
        out.par_chunks_mut(tile).enumerate().for_each(|(k, sums)| {
            let offset = k * tile;
            for (i, doc) in batch.iter().enumerate() {
                if let Some(values) = doc.get(offset..) {
                    let t = &tables[i * 512..(i + 1) * 512];
                    for (dst, &v) in sums.iter_mut().zip(values) {
                        let x = usize::from(v.unsigned_abs());
                        let a = t[x & 255] + t[256 + (x >> 8)];
                        *dst += if v < 0 { -a } else { a };
                    }
                }
            }
        });
    }
    out
}
pub(super) fn fair_a(w: &FairWork, c: &FairCase, ws: &[Scalar]) -> Vec<Scalar> {
    let d = usize::from(w.request.query.dimension);
    let pieces: Vec<_> = c
        .blocks
        .iter()
        .map(|b| &w.documents[b.doc][b.offset * d..(b.offset + b.len) * d])
        .collect();
    fair_aggregate(&pieces, ws, c.h * d)
}
pub(super) fn fair_y(w: &FairWork, c: &FairCase, ws: &[Scalar]) -> Vec<Scalar> {
    let m = usize::from(w.request.query.token_count);
    let mut out = vec![Scalar::ZERO; m * c.h];
    out.par_chunks_mut(c.h).enumerate().for_each(|(j, row)| {
        for (b, a) in c.blocks.iter().zip(ws) {
            let (_, n, y) = &w.matrices[b.doc];
            for (dst, &v) in row
                .iter_mut()
                .zip(&y[j * n + b.offset..j * n + b.offset + b.len])
            {
                *dst += a * scalar_similarity(v);
            }
        }
    });
    out
}
pub(super) fn fair_direct(
    q: &FixedQueryV3,
    point: [u8; 32],
    a: &[[u8; 32]],
    y: &[Scalar],
) -> anyhow::Result<()> {
    let d = usize::from(q.source.dimension);
    anyhow::ensure!(
        a.len() == d && y.len() == usize::from(q.source.token_count),
        "direct shape"
    );
    let v = a
        .iter()
        .map(|b| gem_matrix_proof::canonical_scalar_v1(*b))
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(
        gem_matrix_proof::commit_scalars_v1(&v)? == point,
        "direct commitment"
    );
    q.coordinates.par_chunks(d).zip(y.par_iter()).try_for_each(
        |(row, expected)| -> anyhow::Result<()> {
            let dot = row
                .iter()
                .zip(&v)
                .fold(Scalar::ZERO, |sum, (&x, a)| sum + scalar_coordinate(x) * a);
            anyhow::ensure!(dot == *expected, "direct table");
            Ok(())
        },
    )?;
    Ok(())
}
pub(super) fn fair_prepare_selected(w: &FairWork, hs: &[usize]) -> anyhow::Result<Vec<FairCase>> {
    let d = usize::from(w.request.query.dimension);
    let real: usize = w.matrices.iter().map(|x| x.1).sum();
    let mut out = Vec::new();
    for &h in hs {
        let t = Instant::now();
        gem_matrix_proof::prepare_projection_generators_v1(h * d)?;
        let blocks: Vec<_> = w
            .matrices
            .iter()
            .enumerate()
            .flat_map(|(doc, (id, n, _))| {
                (0..*n).step_by(h).map(move |offset| PilotBlock {
                    doc,
                    id: *id,
                    offset,
                    len: h.min(n - offset),
                })
            })
            .collect();
        let commitments = blocks
            .par_iter()
            .map(|b| {
                let mut a = w.documents[b.doc][b.offset * d..(b.offset + b.len) * d].to_vec();
                a.resize(h * d, 0);
                numeric::commit_matrix(&a)
            })
            .collect::<Result<Vec<_>>>()?;
        let prepared = if blocks.len() == 1 {
            let mut a = w.documents[0]
                .iter()
                .copied()
                .map(scalar_coordinate)
                .collect::<Vec<_>>();
            a.resize(h * d, Scalar::ZERO);
            Some(PreparedProjectionWitnessV1::new(a)?)
        } else {
            None
        };
        let points = commitments
            .iter()
            .copied()
            .map(canonical_point_v1)
            .collect::<Result<Vec<_>>>()?;
        let catalog = fair_catalog(w, h, &blocks, &commitments)?;
        println!(
            "{}",
            serde_json::json!({"type":"case","stage":w.name,"h":h,"blocks":blocks.len(),
            "real_rows":real,"padded_rows":blocks.len()*h,"zero_rows":blocks.len()*h-real,
            "dimension":h*d,"offline_ms":db_ms(t),"static_witness_prepared":prepared.is_some(),
            "catalog_hash":hex::encode(catalog),"commitment_bytes":32*blocks.len(),
            "branch":if h==1{"direct_opening"}else if blocks.len()==1{"whole_prepared"}else{"aggregate_ipa"}})
        );
        eprintln!(
            "Prepared {} h={h}, B={}, {:.1}s",
            w.name,
            blocks.len(),
            t.elapsed().as_secs_f64()
        );
        out.push(FairCase {
            h,
            blocks,
            commitments,
            catalog,
            points,
            prepared,
        });
    }
    Ok(out)
}
pub(super) fn decode_points(
    encoded: &[[u8; 32]],
) -> Result<Vec<curve25519_dalek::ristretto::RistrettoPoint>> {
    encoded
        .par_iter()
        .copied()
        .map(canonical_point_v1)
        .collect()
}
