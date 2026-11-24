use super::*;

// Offline native material. Every root covers document IDs 0 through N-1.
pub(super) use std::io::{BufWriter as PopWriter, Write as PopWrite};
pub(super) use std::path::{Path as PopPath, PathBuf as PopPathBuf};
pub(super) use std::sync::Arc as PopArc;
pub(super) const POP_DIM: usize = 128;
pub(super) const POP_HEIGHT: usize = 128;
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct PopulationShard {
    pub doc_start: usize,
    pub doc_end: usize,
    pub token_start: u64,
    pub raw_offset: usize,
}
pub(super) fn pop_shard_file(root: &PopPath, start: usize, name: &str) -> PopPathBuf {
    root.join(format!("{start:07}")).join(name)
}
pub(super) fn pop_material(id: u32, rows: usize, raw: Vec<i16>, points: Vec<Hash>) -> EMaterial {
    EMaterial {
        id,
        rows,
        raw,
        fp16: vec![],
        fp32: vec![],
        points,
    }
}
pub(super) fn pop_commit_blocks(values: &[i16], h: usize) -> anyhow::Result<Vec<Hash>> {
    values
        .chunks(h * POP_DIM)
        .map(|chunk| {
            let mut block = chunk.to_vec();
            block.resize(h * POP_DIM, 0);
            Ok(numeric::commit_matrix(&block)?)
        })
        .collect()
}
pub(super) fn pop_atomic_write(path: &PopPath, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("pending");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}
pub fn population_prepare_shard(
    root: &PopPath,
    path: &PopPath,
    s: PopulationShard,
    offsets: &[u64],
    row_catalog: bool,
) -> anyhow::Result<()> {
    let dir = root.join(format!("{:07}", s.doc_start));
    std::fs::create_dir_all(&dir)?;
    let marker = dir.join(if row_catalog {
        "row.done"
    } else {
        "block.done"
    });
    let h = if row_catalog { 1 } else { POP_HEIGHT };
    let binding = gem_core::hash_serialized(
        b"auth-gem.population.checkpoint.v1",
        &(
            gem_core::sha256_file(path)?,
            s,
            h,
            &offsets[s.doc_start..=s.doc_end],
        ),
    )?;
    let mut outputs = vec![format!("points-{h}.bin"), format!("leaves-{h}.bin")];
    if !row_catalog {
        outputs.extend(["fixed-i16.bin".to_owned(), "leaves-raw.bin".to_owned()]);
    }
    let receipt = || -> anyhow::Result<_> {
        let hashes = outputs
            .iter()
            .map(|f| Ok((f, hex::encode(gem_core::sha256_file(dir.join(f))?))))
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        Ok(serde_json::json!({"input":hex::encode(binding),"files":hashes}))
    };
    if marker.is_file() {
        anyhow::ensure!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&marker)?)? == receipt()?,
            "completed material shard does not match input and output hashes"
        );
        return Ok(());
    }
    let bytes = std::fs::read(path)?;
    anyhow::ensure!(offsets[s.doc_start] == s.token_start && s.doc_end > s.doc_start);
    let expected = (offsets[s.doc_end] - s.token_start) as usize * POP_DIM * 2;
    anyhow::ensure!(
        bytes.len() == s.raw_offset + expected,
        "shard payload length"
    );
    gem_matrix_proof::prepare_projection_generators_v1(h * POP_DIM)?;
    let coords = &bytes[s.raw_offset..];
    let mut points = PopWriter::new(std::fs::File::create(dir.join(format!("points-{h}.bin")))?);
    let mut leaves = PopWriter::new(std::fs::File::create(dir.join(format!("leaves-{h}.bin")))?);
    let mut raw = if row_catalog {
        None
    } else {
        Some((
            PopWriter::with_capacity(2 << 20, std::fs::File::create(dir.join("fixed-i16.bin"))?),
            PopWriter::new(std::fs::File::create(dir.join("leaves-raw.bin"))?),
        ))
    };
    for first in (s.doc_start..s.doc_end).step_by(1024) {
        let last = (first + 1024).min(s.doc_end);
        let results = (first..last)
            .into_par_iter()
            .map(|id| -> anyhow::Result<_> {
                let n = (offsets[id + 1] - offsets[id]) as usize;
                anyhow::ensure!((1..=180).contains(&n), "unexpected source document length");
                let offset = (offsets[id] - s.token_start) as usize * POP_DIM * 2;
                let source = &coords[offset..offset + n * POP_DIM * 2];
                let bits = source
                    .chunks_exact(2)
                    .map(|v| u16::from_le_bytes([v[0], v[1]]))
                    .collect::<Vec<_>>();
                let fixed = fixed_fp16_v1(&bits)?;
                let material = pop_material(id as u32, n, vec![], pop_commit_blocks(&fixed, h)?);
                let leaf = e_leaf(&material)?;
                let raw = if row_catalog {
                    None
                } else {
                    let mat = pop_material(id as u32, n, fixed, vec![]);
                    let raw_leaf = e_leaf(&mat)?;
                    let packed = mat
                        .raw
                        .into_iter()
                        .flat_map(i16::to_le_bytes)
                        .collect::<Vec<_>>();
                    Some((raw_leaf, packed))
                };
                Ok((leaf, material.points, raw))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        for (leaf, blocks, coords) in results {
            leaves.write_all(&leaf)?;
            points.write_all(blocks.as_flattened())?;
            if let (Some((writer, hashes)), Some((raw_leaf, pack))) = (&mut raw, coords) {
                writer.write_all(&pack)?;
                hashes.write_all(&raw_leaf)?;
            }
        }
    }
    points.flush()?;
    leaves.flush()?;
    points.get_ref().sync_all()?;
    leaves.get_ref().sync_all()?;
    if let Some((writer, hashes)) = &mut raw {
        writer.flush()?;
        hashes.flush()?;
        writer.get_ref().sync_all()?;
        hashes.get_ref().sync_all()?;
    }
    pop_atomic_write(&marker, &serde_json::to_vec(&receipt()?)?)
}
pub(super) fn pop_read_points(path: &PopPath) -> anyhow::Result<Vec<Hash>> {
    let bytes = std::fs::read(path)?;
    anyhow::ensure!(bytes.len() % 32 == 0);
    Ok(bytes
        .chunks_exact(32)
        .map(|c| c.try_into().unwrap())
        .collect())
}
pub fn population_sign_owner(
    root: &PopPath,
    shards: &[PopulationShard],
    source: Hash,
    h: usize,
    repr: u8,
) -> anyhow::Result<()> {
    let name = if repr == 0 {
        "leaves-raw.bin".to_string()
    } else {
        format!("leaves-{h}.bin")
    };
    let mut leaves = vec![];
    for s in shards {
        anyhow::ensure!(leaves.len() == s.doc_start);
        leaves.extend(pop_read_points(&pop_shard_file(root, s.doc_start, &name))?);
        anyhow::ensure!(leaves.len() == s.doc_end);
    }
    let tree = gem_auth_v3::DocumentTreeV3::build(&leaves)?;
    let manifest = EManifest {
        version: E_VERSION,
        source,
        profile: numeric::PROFILE_ID.into(),
        generator: gem_matrix_proof::GENERATOR_ID_V1.into(),
        stage: 2,
        h,
        dimension: POP_DIM,
        leaf_count: tree.document_count,
        root: tree.root()?,
        representation: repr,
    };
    let key = SigningKey::from_bytes(&[19; 32]);
    let auth = EAuth {
        signature: key.sign(&e_encode(&manifest)?).to_bytes().to_vec(),
        manifest,
    };
    let summary = serde_json::json!({"documents":tree.document_count,"height":h,"representation":repr,
        "root":hex::encode(auth.manifest.root),"source":hex::encode(source)});
    let prefix = root.join(format!("global-h{h}-r{repr}"));
    pop_atomic_write(&prefix.with_extension("auth"), &e_encode(&auth)?)?;
    pop_atomic_write(&prefix.with_extension("tree"), &e_encode(&tree)?)?;
    pop_atomic_write(
        &prefix.with_extension("json"),
        &serde_json::to_vec(&summary)?,
    )?;
    Ok(())
}
