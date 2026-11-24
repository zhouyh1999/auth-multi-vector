use anyhow::{Context, Result, ensure};
use gem_auth_scheme_multi::compact as scheme;
use serde::Deserialize;
use std::{env, fs, path::Path, time::Instant};

#[derive(Deserialize)]
struct Config {
    documents: usize,
    tokens: u64,
    shards: Vec<Shard>,
}
#[derive(Deserialize)]
struct Shard {
    doc_start: usize,
    doc_end: usize,
    token_start: u64,
    raw_offset: usize,
    raw_path: String,
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 3 && matches!(args[2].as_str(), "block" | "row"),
        "usage: population-owner CAMPAIGN block|row"
    );
    let root = Path::new(&args[1]);
    gem_lotte_auth_pilot::workspace_output(root)?;
    let rows = args[2] == "row";
    let input = root.join("inputs");
    let src: scheme::TrustedSchemeSnapshotV3 =
        serde_json::from_slice(&fs::read(input.join("trusted.json"))?)?;
    scheme::validate_trusted_scheme_snapshot_v3(&src)?;
    let cfg: Config = serde_json::from_slice(&fs::read(input.join("runner.json"))?)?;
    let offsets = fs::read(input.join("token-offsets.u64"))?
        .chunks_exact(8)
        .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
        .collect::<Vec<_>>();
    ensure!(
        cfg.documents == src.signed.manifest.source().document_count as usize
            && cfg.tokens == src.signed.manifest.source().token_count
            && offsets.len() == cfg.documents + 1
    );
    ensure!(offsets.first() == Some(&0) && offsets.last() == Some(&cfg.tokens));
    rayon::ThreadPoolBuilder::new().build_global()?;
    let output = root.join("native-material");
    fs::create_dir_all(&output)?;
    let mut shards = vec![];
    let mut cursor = 0;
    for (i, entry) in cfg.shards.iter().enumerate() {
        ensure!(entry.doc_start == cursor && entry.doc_end <= cfg.documents);
        let shard = scheme::PopulationShard {
            doc_start: entry.doc_start,
            doc_end: entry.doc_end,
            token_start: entry.token_start,
            raw_offset: entry.raw_offset,
        };
        let file = input.join(Path::new(&entry.raw_path).file_name().context("raw name")?);
        ensure!(file.is_file(), "missing shard {}", file.display());
        let start = Instant::now();
        scheme::population_prepare_shard(&output, &file, shard, &offsets, rows)?;
        println!(
            "{} {}/{} documents={} seconds={:.2}",
            args[2],
            i + 1,
            cfg.shards.len(),
            entry.doc_end,
            start.elapsed().as_secs_f64()
        );
        cursor = entry.doc_end;
        shards.push(shard);
    }
    ensure!(cursor == cfg.documents);
    if rows {
        scheme::population_sign_owner(&output, &shards, src.expected_manifest_digest, 1, 1)?;
    } else {
        scheme::population_sign_owner(&output, &shards, src.expected_manifest_digest, 1, 0)?;
        scheme::population_sign_owner(&output, &shards, src.expected_manifest_digest, 128, 1)?;
    }
    println!("complete {}", args[2]);
    Ok(())
}
