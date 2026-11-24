//! Verify the frozen compact FP16 response. The two raw codecs differ in their frame magic.
use anyhow::{Context, Result, ensure};
use gem_auth_scheme_original::compact as scheme;
use gem_core::{hash_serialized, sha256_file};
use std::{env, fs, path::PathBuf};

fn main() -> Result<()> {
    let dir = PathBuf::from(
        env::args_os()
            .nth(1)
            .context("expected frozen fixture directory")?,
    );
    let trusted = serde_json::from_slice(&fs::read(dir.join("trusted.json"))?)?;
    let request: scheme::SchemeRequestV3 =
        serde_json::from_slice(&fs::read(dir.join("request.json"))?)?;
    let golden: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("reference.json"))?)?;
    let file = dir.join("source.vo");
    ensure!(hex::encode(sha256_file(&file)?) == golden["source_vo_sha256"]);
    let mut bytes = fs::read(file)?;
    ensure!(
        bytes.get(..8) == Some(b"G3SBEN01")
            && bytes.get(18) == Some(&0)
            && request.backend == scheme::SchemeBackendV3::FixedRawFp16,
        "expected measured raw FP16 frame"
    );
    bytes[..8].copy_from_slice(b"G3SCHVO4");
    let verified = scheme::verify_scheme_retrieval_v3(&trusted, &request, &bytes)?;
    let digest = hex::encode(hash_serialized(
        b"gem.csr38.execution-and-results.v1",
        &(&verified.execution, &verified.results),
    )?);
    let ids = verified.execution.component_usage.raw;
    ensure!(
        digest == golden["execution_digest"]
            && serde_json::to_value(&ids)? == golden["candidate_ids"]
    );
    println!(
        "{}",
        serde_json::json!({"execution":digest,"candidates":ids.len(),"results":verified.results.len()})
    );
    Ok(())
}
