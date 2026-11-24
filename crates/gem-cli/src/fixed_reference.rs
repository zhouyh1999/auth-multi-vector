//! Independent acceptance oracle. Does not call production numeric, replay, or verifier code.
use super::scheme_family::{
    Coordinate, DocumentMatrixCommitmentV3, FixedExecutionV3, FixedNodeDistanceV3, IS_COMPACT,
    PreparedSchemeSnapshotV3, Similarity,
};
use anyhow::{Context, Result, bail};
use gem_core::{FixedDistanceV3, Hash, QueryV3, hash_bytes};
use gem_search::{ComponentUsageV3, ExecutionNodeV3, ExecutionStopV3, ExecutionTraceV3};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FixedReferenceRecordV3 {
    pub query_id: u64,
    pub execution: FixedExecutionV3,
    pub results: Vec<FixedNodeDistanceV3>,
    pub all_candidate_scores: Vec<FixedNodeDistanceV3>,
    pub coarse_digest: Hash,
    pub fine_digest: Hash,
    pub candidate_matrix_digests: Vec<(u32, Hash)>,
    pub candidate_tokens: usize,
}
fn floor_scaled(sign: bool, significand: u64, exponent: i32) -> Result<Coordinate> {
    let numerator = u128::from(significand) * 32767;
    let (whole, remainder) = if exponent >= 0 {
        (
            numerator
                .checked_shl(exponent as u32)
                .context("reference shift overflow")?,
            false,
        )
    } else if -exponent >= 128 {
        (0, numerator != 0)
    } else {
        let shift = (-exponent) as u32;
        (numerator >> shift, numerator & ((1u128 << shift) - 1) != 0)
    };
    let signed = if sign {
        -i128::try_from(whole)? - i128::from(remainder)
    } else {
        i128::try_from(whole)?
    };
    Ok(Coordinate::try_from(signed)?)
}
fn convert_compact_ieee(bits: u32) -> Result<Coordinate> {
    let e = (bits >> 23) & 255;
    let mantissa = bits & 0x7fffff;
    if e == 255 || bits & 0x7fffffff > 0x3f800000 {
        bail!("reference compact coordinate range");
    }
    let (significand, exp) = if e == 0 {
        (u64::from(mantissa), -149)
    } else {
        (u64::from((1 << 23) | mantissa), e as i32 - 150)
    };
    floor_scaled(bits >> 31 != 0, significand, exp)
}
fn convert_compact_half(bits: u16) -> Result<Coordinate> {
    let e = (bits >> 10) & 31;
    let mantissa = u64::from(bits & 1023);
    if e == 31 || bits & 0x7fff > 0x3c00 {
        bail!("reference compact FP16 range");
    }
    let (significand, exp) = if e == 0 {
        (mantissa, -24)
    } else {
        (1024 + mantissa, e as i32 - 25)
    };
    floor_scaled(bits >> 15 != 0, significand, exp)
}
// Independent IEEE bit arithmetic: magnitude rounding uses integer shifts, then sign.
fn convert(x: f32) -> Result<Coordinate> {
    if IS_COMPACT {
        return convert_compact_ieee(x.to_bits());
    }
    let bits = x.to_bits();
    let exponent = (bits >> 23) & 255;
    let mantissa = bits & 0x7fffff;
    if exponent == 255 {
        bail!("reference nonfinite coordinate");
    }
    if exponent > 142 {
        bail!("reference coordinate overflow");
    }
    let magnitude = if exponent < 110 {
        0u64
    } else {
        let significand = u64::from((1 << 23) | mantissa);
        if exponent >= 134 {
            significand << (exponent - 134)
        } else {
            let denominator = 1u64 << (134 - exponent);
            (significand + denominator / 2) / denominator
        }
    };
    let signed = if bits >> 31 == 0 {
        magnitude as i64
    } else {
        -(magnitude as i64)
    };
    Ok(Coordinate::try_from(signed)?)
}
fn convert_half(bits: &[u16]) -> Result<Vec<Coordinate>> {
    if IS_COMPACT {
        return bits.iter().map(|&b| convert_compact_half(b)).collect();
    }
    bits.iter()
        .map(|&bits| {
            let exponent = (bits >> 10) & 31;
            let mantissa = u64::from(bits & 1023);
            if exponent == 31 {
                bail!("reference nonfinite FP16");
            }
            let magnitude = if exponent == 0 {
                (mantissa + 128) / 256
            } else if exponent >= 9 {
                (1024 + mantissa) << (exponent - 9)
            } else {
                let denominator = 1u64 << (9 - exponent);
                (1024 + mantissa + denominator / 2) / denominator
            };
            let signed = if bits >> 15 == 0 {
                magnitude as i64
            } else {
                -(magnitude as i64)
            };
            Ok(Coordinate::try_from(signed)?)
        })
        .collect()
}
fn table(q: &[Coordinate], a: &[Coordinate], d: usize) -> Result<Vec<Similarity>> {
    let mut values = Vec::with_capacity(q.len() / d * a.len() / d);
    for j in 0..q.len() / d {
        for row in 0..a.len() / d {
            let mut sum = 0i128;
            for k in 0..d {
                sum += (q[j * d + k] as i128) * (a[row * d + k] as i128);
            }
            values.push(Similarity::try_from(sum)?);
        }
    }
    Ok(values)
}
fn distance(maxima: &[Similarity]) -> Result<FixedDistanceV3> {
    let sum = maxima.iter().try_fold(0i128, |a, &b| {
        a.checked_add(b as i128)
            .ok_or_else(|| anyhow::anyhow!("reference sum overflow"))
    })?;
    Ok(FixedDistanceV3(
        (maxima.len() as i128) * (if IS_COMPACT { 1073676289 } else { 1i128 << 32 }) - sum,
    ))
}
fn digest<T: Serialize>(v: &T) -> Result<Hash> {
    Ok(hash_bytes(
        b"gem.fixed.reference.value.v1",
        &bincode::serialize(v)?,
    ))
}
fn order(a: &FixedNodeDistanceV3, b: &FixedNodeDistanceV3) -> std::cmp::Ordering {
    a.distance
        .0
        .cmp(&b.distance.0)
        .then(a.doc_id.cmp(&b.doc_id))
}
struct Queue {
    cluster: u32,
    entry: u32,
    frontier: Vec<FixedNodeDistanceV3>,
    stopped: bool,
}
pub fn independent_fixed_reference_v3(
    s: &PreparedSchemeSnapshotV3,
    q: &QueryV3,
) -> Result<FixedReferenceRecordV3> {
    let d = q.dimension as usize;
    let m = q.token_count as usize;
    let coords = q
        .coordinates
        .iter()
        .copied()
        .map(convert)
        .collect::<Result<Vec<_>>>()?;
    let coarse = s
        .public
        .coarse_bits
        .iter()
        .map(|&b| convert(f32::from_bits(b)))
        .collect::<Result<Vec<_>>>()?;
    let fine = convert_half(&s.public.fine_bits)?;
    let nc = s.public.entries.len();
    let nf = fine.len() / d;
    let tc = table(&coords, &coarse, d)?;
    let mut selected = BTreeSet::new();
    for j in 0..m {
        let mut ids = (0..nc as u32).collect::<Vec<_>>();
        ids.sort_by(|&a, &b| {
            tc[j * nc + b as usize]
                .cmp(&tc[j * nc + a as usize])
                .then(a.cmp(&b))
        });
        for c in ids.into_iter().take(q.params.cluster_top_t as usize) {
            selected.insert(c);
        }
    }
    let selected_clusters = selected.iter().copied().collect::<Vec<_>>();
    let mut owners = BTreeMap::new();
    for &c in &selected_clusters {
        if let Some(id) = s.public.entries[c as usize] {
            owners.entry(id).or_insert(c);
        }
    }
    let mut queue_entries = owners
        .into_iter()
        .map(|(id, c)| (c, id))
        .collect::<Vec<_>>();
    queue_entries.sort();
    let tf = if queue_entries.is_empty() {
        vec![]
    } else {
        table(&coords, &fine, d)?
    };
    let qch = |id: u32| -> Result<FixedNodeDistanceV3> {
        let codes = &s.index.documents[id as usize].compact_codes;
        let mut maxima = vec![];
        for j in 0..m {
            let mut best = Similarity::MIN;
            for &code in codes {
                best = best.max(tf[j * nf + code as usize]);
            }
            maxima.push(best);
        }
        Ok(ExecutionNodeV3 {
            doc_id: id,
            distance: distance(&maxima)?,
        })
    };
    let mut trace = ExecutionTraceV3 {
        selected_clusters,
        queue_entries,
        compared: vec![],
        expanded: vec![],
        membership_examined: vec![],
        cluster_pruned: vec![],
        retained: vec![],
        candidates: vec![],
        early_stops: vec![],
    };
    let mut usage = ComponentUsageV3::default();
    let mut visited = BTreeSet::new();
    let mut results = vec![];
    let mut queues = vec![];
    for &(c, id) in &trace.queue_entries {
        usage.membership.insert(id);
        usage.codes.insert(id);
        let node = qch(id)?;
        visited.insert(id);
        results.push(node);
        trace.compared.push(node);
        queues.push(Queue {
            cluster: c,
            entry: id,
            frontier: vec![node],
            stopped: false,
        });
    }
    if !queues.is_empty() {
        let mut lower = *results.iter().max_by(|a, b| order(a, b)).unwrap();
        let mut pass = 0;
        loop {
            let mut any = false;
            for queue in &mut queues {
                if queue.stopped {
                    continue;
                }
                if queue.frontier.is_empty() {
                    queue.stopped = true;
                    continue;
                }
                let pos = (0..queue.frontier.len())
                    .min_by(|&a, &b| order(&queue.frontier[a], &queue.frontier[b]))
                    .unwrap();
                let head = queue.frontier[pos];
                if head.distance.0 > lower.distance.0 {
                    queue.stopped = true;
                    trace.early_stops.push(ExecutionStopV3 {
                        pass,
                        cluster_id: queue.cluster,
                        entry_doc_id: queue.entry,
                        doc_id: head.doc_id,
                        distance: head.distance,
                        lower_bound: lower.distance,
                    });
                    continue;
                }
                queue.frontier.swap_remove(pos);
                any = true;
                trace.expanded.push(head.doc_id);
                usage.adjacency.insert(head.doc_id);
                for &neighbor in &s.index.documents[head.doc_id as usize].adjacency {
                    trace.membership_examined.push(neighbor);
                    usage.membership.insert(neighbor);
                    if !s.index.documents[neighbor as usize]
                        .cluster_ids
                        .iter()
                        .any(|c| selected.contains(c))
                    {
                        trace.cluster_pruned.push(neighbor);
                        continue;
                    }
                    if visited.contains(&neighbor) {
                        continue;
                    }
                    visited.insert(neighbor);
                    usage.codes.insert(neighbor);
                    let node = qch(neighbor)?;
                    trace.compared.push(node);
                    if results.len() < q.params.ef_search as usize
                        || node.distance.0 < lower.distance.0
                    {
                        queue.frontier.push(node);
                        results.push(node);
                        results.sort_by(order);
                        while results.len() > q.params.ef_search as usize {
                            results.pop();
                        }
                        lower = *results.last().unwrap();
                    }
                }
            }
            if !any {
                break;
            }
            pass += 1;
        }
    }
    results.sort_by(order);
    trace.retained = results;
    trace.candidates = trace
        .retained
        .iter()
        .take(q.params.rerank_k as usize)
        .copied()
        .collect();
    usage.raw.extend(trace.candidates.iter().map(|x| x.doc_id));
    let candidate_data = usage
        .raw
        .par_iter()
        .map(|&id| -> Result<_> {
            let a = convert_half(&s.raw_bits[id as usize])?;
            let n = a.len() / d;
            let y = table(&coords, &a, d)?;
            let maxima = (0..m)
                .map(|j| *y[j * n..(j + 1) * n].iter().max().unwrap())
                .collect::<Vec<_>>();
            Ok((
                ExecutionNodeV3 {
                    doc_id: id,
                    distance: distance(&maxima)?,
                },
                digest(&y)?,
                n,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let all_candidate_scores = candidate_data
        .iter()
        .map(|(r, _, _)| *r)
        .collect::<Vec<_>>();
    let mut results = all_candidate_scores.clone();
    results.sort_by(order);
    results.truncate(q.params.k as usize);
    Ok(FixedReferenceRecordV3 {
        query_id: q.query_id,
        execution: FixedExecutionV3 {
            trace,
            component_usage: usage,
        },
        results,
        all_candidate_scores,
        coarse_digest: digest(&tc)?,
        fine_digest: digest(&tf)?,
        candidate_matrix_digests: candidate_data
            .iter()
            .map(|(r, h, _)| (r.doc_id, *h))
            .collect(),
        candidate_tokens: candidate_data.iter().map(|(_, _, n)| n).sum(),
    })
}

/// Separate preparation audit: own conversion/layout, direct MSM and component/tree reconstruction.
pub fn independent_components_v3(s: &PreparedSchemeSnapshotV3) -> Result<serde_json::Value> {
    use bulletproofs::BulletproofGens;
    use curve25519_dalek::{
        ristretto::RistrettoPoint, scalar::Scalar, traits::VartimeMultiscalarMul,
    };
    let signed = &s.trusted.signed.manifest;
    let digest = hash_bytes(
        if IS_COMPACT {
            b"gem.auth.v3.manifest.9"
        } else {
            b"gem.auth.v3.manifest.8"
        },
        &bincode::serialize(signed)?,
    );
    if digest != s.trusted.expected_manifest_digest {
        bail!("independent manifest digest");
    }
    ed25519_dalek::VerifyingKey::from_bytes(&s.trusted.owner_public_key)?.verify_strict(
        &digest,
        &ed25519_dalek::Signature::from_slice(&s.trusted.signed.signature)?,
    )?;
    let m = signed.source();
    let d = usize::from(m.dimension);
    let rows = usize::from(m.max_doc_tokens);
    let n = rows * d;
    let generator_set = BulletproofGens::new(n, 1);
    let g = generator_set.share(0).G(n).copied().collect::<Vec<_>>();
    let scalar = |x: Coordinate| {
        if x < 0 {
            -Scalar::from(u64::from(x.unsigned_abs()))
        } else {
            Scalar::from(x as u64)
        }
    };
    let component =
        |meta: &gem_auth_v3::MetadataV3, kind: u8, value_bytes: Vec<u8>| -> Result<Hash> {
            let mut b = (if IS_COMPACT { 9u16 } else { 8u16 })
                .to_le_bytes()
                .to_vec();
            b.extend(bincode::serialize(&signed.numeric_profile)?);
            b.push(kind);
            b.extend(bincode::serialize(meta)?);
            b.extend(value_bytes);
            Ok(hash_bytes(
                if IS_COMPACT {
                    b"gem.auth.v3.component.9"
                } else {
                    b"gem.auth.v3.component.8"
                },
                &b,
            ))
        };
    let raw_component =
        |meta: &gem_auth_v3::MetadataV3, kind: u8, value: Vec<u8>| -> Result<Hash> {
            let mut b = 2u16.to_le_bytes().to_vec();
            b.push(kind);
            b.extend(bincode::serialize(meta)?);
            b.extend(value);
            Ok(hash_bytes(b"gem.auth.v3.component.2", &b))
        };
    let hashes = s
        .metadata
        .par_iter()
        .enumerate()
        .map(|(id, meta)| -> Result<_> {
            let coordinates = convert_half(&s.raw_bits[id])?;
            if coordinates != s.fixed_documents[id] {
                bail!("independent fixed conversion {id}");
            }
            let mut a = coordinates.into_iter().map(scalar).collect::<Vec<_>>();
            if a.len() != usize::from(meta.token_count) * d || a.len() > n {
                bail!("independent padding shape");
            }
            a.resize(n, Scalar::ZERO);
            let commitment = RistrettoPoint::vartime_multiscalar_mul(a.iter(), g.iter())
                .compress()
                .to_bytes();
            if commitment != s.commitments[id] {
                bail!("independent document commitment {id}");
            }
            let doc = &s.index.documents[id];
            let h = [
                component(meta, 0, bincode::serialize(meta)?)?,
                component(meta, 1, bincode::serialize(&doc.cluster_ids)?)?,
                component(meta, 2, bincode::serialize(&doc.compact_codes)?)?,
                component(meta, 3, bincode::serialize(&doc.adjacency)?)?,
                component(
                    meta,
                    5,
                    bincode::serialize(&DocumentMatrixCommitmentV3::new(commitment))?,
                )?,
            ];
            if h != s.component_hashes[id] {
                bail!("independent component hashes {id}");
            }
            let raw_h = [
                raw_component(meta, 0, bincode::serialize(meta)?)?,
                raw_component(meta, 1, bincode::serialize(&doc.cluster_ids)?)?,
                raw_component(meta, 2, bincode::serialize(&doc.compact_codes)?)?,
                raw_component(meta, 3, bincode::serialize(&doc.adjacency)?)?,
                raw_component(meta, 4, bincode::serialize(&s.raw_bits[id])?)?,
            ];
            if raw_h != s.raw_component_hashes[id] {
                bail!("independent raw component hashes {id}");
            }
            Ok((h, raw_h))
        })
        .collect::<Result<Vec<_>>>()?;
    for (bits32, bits16, count, expected) in [
        (
            Some(&s.public.coarse_bits),
            None,
            m.coarse_count,
            signed.coarse_commitment,
        ),
        (
            None,
            Some(&s.public.fine_bits),
            m.fine_count,
            signed.fine_commitment,
        ),
    ] {
        let a = if let Some(bits) = bits32 {
            bits.iter()
                .map(|&b| convert(f32::from_bits(b)))
                .collect::<Result<Vec<_>>>()?
        } else {
            convert_half(bits16.unwrap())?
        };
        let length = count as usize * d;
        if a.len() != length {
            bail!("independent centroid shape");
        }
        let gens = BulletproofGens::new(length, 1);
        let points = gens.share(0).G(length).copied().collect::<Vec<_>>();
        let commitment =
            RistrettoPoint::vartime_multiscalar_mul(a.into_iter().map(scalar), points.iter())
                .compress()
                .to_bytes();
        if commitment != expected {
            bail!("independent centroid commitment");
        }
    }
    let count = m.document_count;
    let rebuild_tree = |raw: bool| {
        let mut leaves = hashes
            .iter()
            .map(|(matrix, baseline)| {
                let h = if raw { baseline } else { matrix };
                let schema = if raw {
                    2u16
                } else if IS_COMPACT {
                    9u16
                } else {
                    8u16
                };
                let mut b = schema.to_le_bytes().to_vec();
                for x in h {
                    b.extend(x);
                }
                hash_bytes(
                    if raw {
                        b"gem.auth.v3.leaf.2"
                    } else if IS_COMPACT {
                        b"gem.auth.v3.leaf.9"
                    } else {
                        b"gem.auth.v3.leaf.8"
                    },
                    &b,
                )
            })
            .collect::<Vec<_>>();
        for id in count..count.next_power_of_two() {
            let mut b = count.to_le_bytes().to_vec();
            b.extend(id.to_le_bytes());
            leaves.push(hash_bytes(b"gem.auth.v3.padding.1", &b));
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next = vec![];
            for pair in current.chunks_exact(2) {
                let mut b = count.to_le_bytes().to_vec();
                b.extend(pair[0]);
                b.extend(pair[1]);
                next.push(hash_bytes(b"gem.auth.v3.node.1", &b));
            }
            levels.push(next);
        }
        levels
    };
    let levels = rebuild_tree(false);
    let raw_levels = rebuild_tree(true);
    if levels != s.tree.levels || levels.last().unwrap()[0] != signed.document_root {
        bail!("independent complete matrix MHT");
    }
    if raw_levels != s.raw_tree.levels || raw_levels.last().unwrap()[0] != m.document_root {
        bail!("independent complete raw MHT");
    }
    Ok(serde_json::json!({
        "passed":true,"documents":count,"components_rehashed":count as usize*5,
        "raw_components_rehashed":count as usize*5,"document_commitments_rebuilt":count,
        "centroid_commitments_rebuilt":2,"mht_nodes_rebuilt":levels.iter().map(Vec::len).sum::<usize>(),
        "raw_mht_nodes_rebuilt":raw_levels.iter().map(Vec::len).sum::<usize>(),
        "root":hex::encode(signed.document_root),"raw_root":hex::encode(m.document_root),
        "production_numeric_commitment_snapshot_functions_used":false,
    }))
}

#[cfg(test)]
mod conversion_tests {
    use super::*;
    #[test]
    fn independent_ieee_rounding_matches_contract_on_all_half_patterns() {
        for bits in 0u16..=u16::MAX {
            let source = half::f16::from_bits(bits).to_f32();
            assert_eq!(
                convert(source).ok().map(i64::from),
                if IS_COMPACT {
                    gem_core::compact_coordinate_v1(source).ok().map(i64::from)
                } else {
                    gem_core::fixed_coordinate_v1(source).ok().map(i64::from)
                }
            );
            assert_eq!(
                convert_half(&[bits]).ok().map(|a| a[0]),
                convert(source).ok()
            );
        }
        for x in [
            0.5 / 65536.,
            -0.5 / 65536.,
            1.5 / 65536.,
            -1.5 / 65536.,
            -32768.,
            32768.,
            f32::MAX,
            f32::MIN,
            f32::NAN,
        ] {
            assert_eq!(
                convert(x).ok().map(i64::from),
                if IS_COMPACT {
                    gem_core::compact_coordinate_v1(x).ok().map(i64::from)
                } else {
                    gem_core::fixed_coordinate_v1(x).ok().map(i64::from)
                }
            );
        }
    }
}
