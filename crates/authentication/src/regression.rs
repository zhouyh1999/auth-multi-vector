//! Recheck captured first-contact messages using the same client as a measured query.
use super::*;
use anyhow::{Context, ensure};
use std::{fs, path::Path};

pub fn check_full_fixture(public: &Path, capture: &Path) -> anyhow::Result<serde_json::Value> {
    let keys = visit_keys(&fs::read(public.join("anchors.bin"))?)?;
    let mut cases = Vec::new();
    for (policy, method) in VISIT_METHODS {
        let bundle = fs::read(public.join(format!("{method}.all.bin")))?;
        let trust = verify_visit(&bundle, &keys, policy, 3)?;
        let request: EFullRequest =
            e_decode(&fs::read(capture.join(format!("{method}.request")))?)?;
        ensure!(
            request.method == policy
                && !request.cache
                && request.heights == pop_route(policy, false).1
        );
        let response = fs::read(capture.join(format!("{method}.response")))?;
        let verify = |bytes: &[u8]| {
            e_full_client_pinned(
                &request,
                keys[1],
                trust.index,
                keys[0],
                &[None, None, None],
                bytes,
                Some(&trust.stages),
            )
        };
        let honest = hex::encode(verify(&response)?.0);
        for case in [
            "version",
            "publication",
            "request",
            "stage",
            "merkle",
            "missing_graph",
            "material_id",
            "material_length",
            "table",
            "proof",
            "result_id",
            "distance",
            "order",
        ] {
            let mut v: EFullResponse = e_decode(&response)?;
            let mut stage: EResponse = e_decode(&v.stages[2])?;
            match case {
                "version" => v.version ^= 1,
                "publication" => v.source.expected_manifest_digest[0] ^= 1,
                "request" => v.requests[0].request.query.query_id ^= 1,
                "stage" => v.requests[0].stage = 1,
                "merkle" => v.structure.proof.siblings.push([0; 32]),
                "missing_graph" => {
                    let doc = v
                        .structure
                        .documents
                        .iter_mut()
                        .find(|d| d.adjacency.is_revealed())
                        .context("fixture needs expanded node")?;
                    doc.adjacency = ComponentOpening::Digest(open_hash(
                        SchemeBackendV3::FixedRawFp16,
                        &doc.metadata,
                        3,
                        &doc.adjacency,
                    )?);
                }
                "material_id" => stage.openings[0].value.id ^= 1,
                "material_length" => stage.openings[0].value.rows += 1,
                "table" if policy == 0 => stage.table.push(0),
                "table" => stage.table[0] ^= 1,
                "proof" if policy == 0 => stage.openings[0].value.raw[0] ^= 1,
                "proof" if policy == 5 => {
                    stage.projection.as_mut().context("projection")?.argument[0] ^= 1
                }
                "proof" => stage.arguments[0][0] ^= 1,
                "result_id" => v.structure.results[0].doc_id ^= 1,
                "distance" => v.structure.results[0].distance.0 += 1,
                "order" => v.structure.results.swap(0, 1),
                _ => unreachable!(),
            }
            v.stages[2] = e_encode(&stage)?;
            let error = verify(&e_encode(&v)?)
                .err()
                .context("invalid response accepted")?;
            cases.push(
                serde_json::json!({"policy":method,"case":case,"rejected":true,
                "reason":error.to_string(),"honest_execution":honest}),
            );
        }
    }
    Ok(
        serde_json::json!({"binary":hex::encode(gem_core::sha256_file(std::env::current_exe()?)?), "cases":cases}),
    )
}
