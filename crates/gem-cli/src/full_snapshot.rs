//! Trusted offline snapshots for a published fixed graph and its vector shards.
//! The authentication schemas, component hashes and query VO formats are unchanged.
//! Version 1 stores original immutable raw shards by reference and streams metadata;
//! raw/fixed arrays are reconstructed once per persistent process, never per query.
use anyhow::{Context, Result, bail, ensure};
use bincode::Options;
use ed25519_dalek::{Signer, SigningKey};
use gem_auth_scheme_v3::compact;
use gem_auth_v3::*;
use gem_core::*;
use gem_search::{
    GraphBuildParamsV3, SearchIndexV3, import_coarse_centroids, import_fine_centroids,
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::fs::{FileExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

pub const MAX_OFFLINE_BYTES: u64 = 4_u64 << 40;
/// Legacy 18-byte snapshot/index frames use a trusted offline size policy,
/// streamed directly into the typed object. Query VOs keep MAX_VO_BYTES.
pub fn load_legacy_offline_frame<T: serde::de::DeserializeOwned>(
    path: &Path,
    magic: &[u8; 8],
    schema: u16,
) -> Result<T> {
    let length = fs::metadata(path)?.len();
    ensure!(
        (18..=MAX_OFFLINE_BYTES + 18).contains(&length),
        "invalid offline frame length"
    );
    let mut f = BufReader::with_capacity(8 << 20, File::open(path)?);
    let mut h = [0u8; 18];
    f.read_exact(&mut h)?;
    let actual = u16::from_le_bytes(h[8..10].try_into()?);
    if &h[..8] == b"G3SNAP!!" && actual == 1 {
        bail!(
            "raw schema 1 uses retired document metadata; rerun raw prepare from the index and input data"
        )
    }
    if matches!(&h[..8], b"G3CMPSNP" | b"G3SCHSNP") && (2..=7).contains(&actual) {
        bail!(
            "scheme schema 2-7 snapshots use a retired authentication layout; rerun prepare from the raw snapshot"
        )
    }
    ensure!(
        &h[..8] == magic
            && actual == schema
            && u64::from_le_bytes(h[10..18].try_into()?) == length - 18,
        "invalid snapshot frame"
    );
    let v = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(length - 18)
        .deserialize_from(&mut f)?;
    let mut trailing = [0u8; 1];
    ensure!(f.read(&mut trailing)? == 0, "trailing offline frame bytes");
    Ok(v)
}
const MAGIC: &[u8; 8] = b"G3OFFLN1";
struct OwnerPhaseClock {
    start: Instant,
    last: Instant,
    values: BTreeMap<String, f64>,
    path: PathBuf,
}
impl OwnerPhaseClock {
    fn new(run: &Path, kind: &str) -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last: now,
            values: BTreeMap::new(),
            path: run.join(format!(
                "checkpoints/owner-timing-{kind}-{}.json",
                std::process::id()
            )),
        }
    }
    fn mark(&mut self, name: &str) -> Result<()> {
        self.values
            .insert(name.to_string(), self.last.elapsed().as_secs_f64() * 1000.);
        json_write(
            &self.path,
            &serde_json::json!({"pid":std::process::id(),"phases_ms":self.values,"elapsed_ms":self.start.elapsed().as_secs_f64()*1000.}),
        )?;
        self.last = Instant::now();
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shard {
    pub doc_start: usize,
    pub doc_end: usize,
    pub token_start: u64,
    pub raw_path: PathBuf,
    pub raw_offset: u64,
    pub codes_path: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishedConfig {
    pub dataset: String,
    pub documents: usize,
    pub tokens: u64,
    pub dimension: u16,
    pub max_doc_tokens: u16,
    pub queries: usize,
    pub fine: PathBuf,
    pub coarse: PathBuf,
    pub queries_npy: PathBuf,
    pub shards: Vec<Shard>,
    pub graph_dir: PathBuf,
    pub degree_cap: usize,
    pub graph_origin: String,
    pub query_ids: PathBuf,
}
pub fn params() -> SearchParamsV3 {
    SearchParamsV3 {
        k: 100,
        rerank_k: 1024,
        ef_search: 1024,
        cluster_top_t: 4,
    }
}
pub fn json_write(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    atomic_bytes(path, &bytes)
}
pub fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(path.parent().context("output parent")?)?;
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = File::create(&temp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&temp, path)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
pub fn save_offline<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    fs::create_dir_all(path.parent().context("offline parent")?)?;
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let size = bincode::serialized_size(value)?;
    ensure!(
        size <= MAX_OFFLINE_BYTES,
        "offline snapshot exceeds explicit 4 TiB policy"
    );
    let mut f = BufWriter::with_capacity(8 << 20, File::create(&temp)?);
    f.write_all(MAGIC)?;
    f.write_all(&size.to_le_bytes())?;
    bincode::serialize_into(&mut f, value)?;
    f.flush()?;
    f.get_ref().sync_all()?;
    drop(f);
    ensure!(
        fs::metadata(&temp)?.len() == size + 16,
        "offline size mismatch"
    );
    fs::rename(temp, path)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
pub fn load_offline<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let length = fs::metadata(path)?.len();
    ensure!(
        (16..=MAX_OFFLINE_BYTES + 16).contains(&length),
        "invalid offline length"
    );
    let mut f = BufReader::with_capacity(8 << 20, File::open(path)?);
    let mut h = [0u8; 16];
    f.read_exact(&mut h)?;
    ensure!(
        &h[..8] == MAGIC && u64::from_le_bytes(h[8..].try_into()?) == length - 16,
        "invalid offline reference frame"
    );
    let value = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(length - 16)
        .deserialize_from(&mut f)?;
    let mut tail = [0u8; 1];
    ensure!(f.read(&mut tail)? == 0, "trailing offline bytes");
    Ok(value)
}
pub fn config(run: &Path) -> Result<PublishedConfig> {
    Ok(serde_json::from_reader(File::open(
        run.join("inputs/runner.json"),
    )?)?)
}
pub fn u32s(path: &Path) -> Result<Vec<u32>> {
    let bytes = fs::read(path)?;
    ensure!(bytes.len() % 4 == 0, "u32 array shape");
    Ok(bytes
        .chunks_exact(4)
        .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
        .collect())
}
pub fn u64s(path: &Path) -> Result<Vec<u64>> {
    let bytes = fs::read(path)?;
    ensure!(bytes.len() % 8 == 0, "u64 array shape");
    Ok(bytes
        .chunks_exact(8)
        .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
        .collect())
}
pub fn import_index(run: &Path) -> Result<()> {
    let output = run.join("imported/index.offline");
    if output.exists() {
        let index: SearchIndexV3 = load_offline(&output)?;
        index.validate()?;
        return Ok(());
    }
    let cfg = config(run)?;
    ensure!(
        cfg.documents > 0 && cfg.dimension == 128 && cfg.degree_cap == 48,
        "unexpected full corpus"
    );
    let p = run.join("inputs");
    let offsets = u64s(&p.join("token-offsets.u64"))?;
    let mo = u64s(&p.join("membership-offsets.u64"))?;
    let members = u32s(&p.join("memberships.u32"))?;
    let degree = u32s(&p.join("degree.u32"))?;
    let adj = u32s(&p.join("adjacency.u32"))?;
    ensure!(
        offsets.len() == cfg.documents + 1
            && mo.len() == offsets.len()
            && degree.len() == cfg.documents
            && adj.len() == cfg.documents * cfg.degree_cap,
        "published array shapes"
    );
    let mut documents = Vec::with_capacity(cfg.documents);
    for (si, s) in cfg.shards.iter().enumerate() {
        ensure!(
            s.doc_start == documents.len() && s.token_start == offsets[s.doc_start],
            "shard identity"
        );
        let (_, codes) = read_npy_i32(p.join(s.codes_path.file_name().context("codes filename")?))?;
        ensure!(
            codes.len() as u64 == offsets[s.doc_end] - s.token_start,
            "code shard length"
        );
        for id in s.doc_start..s.doc_end {
            let first = usize::try_from(offsets[id] - s.token_start)?;
            let end = usize::try_from(offsets[id + 1] - s.token_start)?;
            ensure!(
                degree[id] as usize <= cfg.degree_cap,
                "degree exceeds published cap"
            );
            documents.push(SearchDocumentV3 {
                doc_id: u32::try_from(id)?,
                token_count: u16::try_from(end - first)?,
                compact_codes: codes[first..end]
                    .iter()
                    .map(|&v| u32::try_from(v).map_err(anyhow::Error::from))
                    .collect::<Result<_>>()?,
                cluster_ids: members[mo[id] as usize..mo[id + 1] as usize].to_vec(),
                adjacency: adj[id * cfg.degree_cap..id * cfg.degree_cap + degree[id] as usize]
                    .to_vec(),
            });
        }
        eprintln!(
            "import shard {}/{} documents={}",
            si + 1,
            cfg.shards.len(),
            documents.len()
        );
    }
    let index = SearchIndexV3 {
        semantic_profile: SemanticProfileV3::published_fixed_graph(),
        graph_params: GraphBuildParamsV3 {
            m: 24,
            m0: 48,
            ef_construction: 80,
            qemd_max_iterations: 1000,
            wave_size: 1,
        },
        dimension: cfg.dimension,
        max_doc_tokens: cfg.max_doc_tokens,
        fine_centroids: import_fine_centroids(p.join(cfg.fine.file_name().context("fine filename")?), cfg.dimension)?,
        coarse_centroids: import_coarse_centroids(p.join(cfg.coarse.file_name().context("coarse filename")?), cfg.dimension)?,
        fine_to_coarse: Vec::new(),
        cluster_entries: u32s(&p.join("entries.u32"))?
            .into_iter()
            .map(|id| if id == u32::MAX { None } else { Some(id) })
            .collect(),
        documents,
    };
    index.validate()?;
    // Independently compare the actual serialized index against the prepared view.
    save_offline(&output, &index)?;
    drop(index);
    let index: SearchIndexV3 = load_offline(&output)?;
    for (id, d) in index.documents.iter().enumerate() {
        ensure!(
            d.adjacency == adj[id * cfg.degree_cap..id * cfg.degree_cap + degree[id] as usize],
            "ordered adjacency changed"
        );
        ensure!(
            d.cluster_ids == members[mo[id] as usize..mo[id + 1] as usize],
            "membership changed"
        );
    }
    json_write(
        &run.join("imported/rust-import-validation.json"),
        &serde_json::json!({"passed":true,"documents":index.documents.len(),"ordered_adjacency_preserved":true,"memberships_preserved":true,"training_map":"absent, unused for fixed-graph search","graph_builder":"publisher-fixed-graph-v1","offline_format_version":1,"query_wire_unchanged":true,"index_sha256":hex::encode(sha256_file(&output)?)}),
    )?;
    Ok(())
}
pub fn index(run: &Path) -> Result<SearchIndexV3> {
    let i: SearchIndexV3 = load_offline(&run.join("imported/index.offline"))?;
    i.validate()?;
    Ok(i)
}
pub struct DiskCorpus {
    cfg: PublishedConfig,
    files: Vec<File>,
    offsets: Vec<u64>,
}
impl DiskCorpus {
    pub fn new(mut cfg: PublishedConfig, input: &Path) -> Result<Self> {
        // Frozen envelopes retain their historical paths. Only logical shard names
        // are resolved, after the artifact runner has verified the input manifest.
        cfg.graph_dir = input.to_owned();
        for shard in &mut cfg.shards {
            shard.raw_path = input.join(shard.raw_path.file_name().context("raw shard filename")?);
        }
        let files = cfg
            .shards
            .iter()
            .map(|s| Ok(File::open(&s.raw_path)?))
            .collect::<Result<_>>()?;
        let offsets = u64s(&cfg.graph_dir.join("token-offsets.u64"))?;
        Ok(Self {
            cfg,
            files,
            offsets,
        })
    }
    pub fn bits(&self, id: u32) -> Result<Vec<u16>> {
        let id = id as usize;
        ensure!(id < self.cfg.documents, "raw doc ID out of range");
        let si = self.cfg.shards.partition_point(|s| s.doc_end <= id);
        let s = &self.cfg.shards[si];
        ensure!(id >= s.doc_start, "raw shard mapping");
        let begin = self.offsets[id];
        let tokens = self.offsets[id + 1] - begin;
        let mut b = vec![0u8; usize::try_from(tokens)? * usize::from(self.cfg.dimension) * 2];
        self.files[si].read_exact_at(
            &mut b,
            s.raw_offset + (begin - s.token_start) * u64::from(self.cfg.dimension) * 2,
        )?;
        Ok(b.chunks_exact(2)
            .map(|v| u16::from_le_bytes(v.try_into().unwrap()))
            .collect())
    }
    pub fn fp32_candidates(&self, ids: &[u32]) -> Result<RawCandidates> {
        let docs = ids
            .par_iter()
            .map(|&id| {
                let bits = self.bits(id)?;
                Ok((
                    id,
                    RawDocumentF32V3 {
                        doc_id: id,
                        token_count: u16::try_from(bits.len() / usize::from(self.cfg.dimension))?,
                        dimension: self.cfg.dimension,
                        coordinates: decode_fp16_v3(&bits)?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        Ok(RawCandidates(docs))
    }
    pub fn load_all(&self) -> Result<Vec<Vec<u16>>> {
        let mut docs = Vec::with_capacity(self.cfg.documents);
        for (si, s) in self.cfg.shards.iter().enumerate() {
            ensure!(s.doc_start == docs.len(), "nonconsecutive corpus shards");
            let mut f = BufReader::with_capacity(8 << 20, File::open(&s.raw_path)?);
            f.seek(SeekFrom::Start(s.raw_offset))?;
            for id in s.doc_start..s.doc_end {
                let n = usize::try_from(self.offsets[id + 1] - self.offsets[id])?
                    * usize::from(self.cfg.dimension);
                let mut bytes = vec![0u8; n * 2];
                f.read_exact(&mut bytes)?;
                docs.push(
                    bytes
                        .chunks_exact(2)
                        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                        .collect(),
                );
            }
            eprintln!(
                "loaded raw shard {}/{} documents={}",
                si + 1,
                self.cfg.shards.len(),
                docs.len()
            );
        }
        Ok(docs)
    }
}
pub struct RawCandidates(pub BTreeMap<u32, RawDocumentF32V3>);
impl gem_search::RawVectorSourceV3 for RawCandidates {
    fn raw(&self, id: u32) -> gem_core::Result<&RawDocumentF32V3> {
        self.0.get(&id).ok_or(GemError::InvalidManifest)
    }
}
pub fn owner_key(run: &Path) -> Result<SigningKey> {
    let p = run.join("owner-private/owner.key");
    if !p.exists() {
        ensure!(
            !run.join("snapshots/raw/client/trusted.json").exists()
                && !run.join("checkpoints/raw").exists(),
            "owner key is missing from an existing run; restore it instead of silently changing owner identity"
        );
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut f = OpenOptions::new().write(true).create_new(true).open(&p)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(&key.to_bytes())?;
        f.sync_all()?;
    }
    ensure!(
        fs::metadata(&p)?.permissions().mode() & 0o077 == 0,
        "owner key permissions"
    );
    let bytes: [u8; 32] = fs::read(&p)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid owner key"))?;
    Ok(SigningKey::from_bytes(&bytes))
}
#[derive(Serialize, Deserialize)]
struct OfflineRaw {
    version: u32,
    input_binding: Hash,
    corpus: PublishedConfig,
    prepared: PreparedRawSnapshotV3,
}
#[derive(Serialize, Deserialize)]
struct OfflineCompact {
    version: u32,
    input_binding: Hash,
    corpus: PublishedConfig,
    prepared: compact::PreparedSchemeSnapshotV3,
}
#[derive(Serialize, Deserialize)]
struct RawShard {
    binding: Hash,
    first: usize,
    end: usize,
    hashes: Vec<[Hash; 5]>,
}
#[derive(Serialize, Deserialize)]
struct CommitmentShard {
    binding: Hash,
    first: usize,
    end: usize,
    commitments: Vec<[u8; 32]>,
}

pub fn prepare_raw(run: &Path) -> Result<()> {
    let output = run.join("snapshots/raw/server/offline.raw");
    if output.exists() {
        if run.join("snapshots/raw/client/trusted.json").exists()
            && run.join("snapshots/raw/owner-validation.json").exists()
        {
            let s = load_raw(run)?;
            validate_prepared_snapshot_v3(&s)?;
            return Ok(());
        }
        // A crash between metadata and trusted publication cannot strand resume.
        // Keep the interrupted artifact; rebuilding reuses every bound shard.
        fs::rename(
            &output,
            output.with_extension(format!("interrupted-{}", std::process::id())),
        )?;
    }
    let started = Instant::now();
    let mut phases = OwnerPhaseClock::new(run, "raw");
    let cfg = config(run)?;
    let index = index(run)?;
    let key = owner_key(run)?;
    let input_binding = sha256_file(run.join("input-bindings.json"))?;
    let provenance = hash_serialized(
        b"gem.csr38.published.provenance.v1",
        &(input_binding, sha256_file(std::env::current_exe()?)?),
    )?;
    let index_digest = hash_serialized(b"gem.auth.v3.index-provenance.1", &index)?;
    let binding = hash_serialized(
        b"gem.csr38.raw.checkpoint.v1",
        &(provenance, index_digest, key.verifying_key().to_bytes()),
    )?;
    let raw_bits = DiskCorpus::new(cfg.clone(), &run.join("inputs"))?.load_all()?;
    phases.mark("load_inputs_and_index_digest")?;
    let metadata = index
        .documents
        .iter()
        .map(|d| MetadataV3 {
            doc_id: d.doc_id,
            token_count: d.token_count,
        })
        .collect::<Vec<_>>();
    let public = PublicDataV3 {
        fine_bits: fp32_to_canonical_fp16_v3(
            &index
                .fine_centroids
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>(),
        )?,
        coarse_bits: index.coarse_centroids.iter().map(|v| v.to_bits()).collect(),
        entries: index.cluster_entries.clone(),
    };
    let mut component_hashes = Vec::with_capacity(cfg.documents);
    for (si, s) in cfg.shards.iter().enumerate() {
        let p = run.join(format!("checkpoints/raw/shard-{si:04}.offline"));
        let shard = if p.exists() {
            let v: RawShard = load_offline(&p)?;
            ensure!(
                v.binding == binding
                    && v.first == s.doc_start
                    && v.end == s.doc_end
                    && v.hashes.len() == s.doc_end - s.doc_start,
                "raw checkpoint binding mismatch"
            );
            v
        } else {
            let hashes = (s.doc_start..s.doc_end)
                .into_par_iter()
                .map(|id| -> gem_core::Result<_> {
                    let m = &metadata[id];
                    let d = &index.documents[id];
                    decode_fp16_v3(&raw_bits[id])?;
                    Ok([
                        component_hash_v3(m, 0, m)?,
                        component_hash_v3(m, 1, &d.cluster_ids)?,
                        component_hash_v3(m, 2, &d.compact_codes)?,
                        component_hash_v3(m, 3, &d.adjacency)?,
                        component_hash_v3(m, 4, &raw_bits[id])?,
                    ])
                })
                .collect::<gem_core::Result<Vec<_>>>()?;
            let v = RawShard {
                binding,
                first: s.doc_start,
                end: s.doc_end,
                hashes,
            };
            save_offline(&p, &v)?;
            v
        };
        component_hashes.extend(shard.hashes);
        json_write(
            &run.join("checkpoints/owner-progress.json"),
            &serde_json::json!({"stage":"raw_components","shards_done":si+1,"shards_total":cfg.shards.len(),"documents_done":s.doc_end,"elapsed_seconds":started.elapsed().as_secs_f64()}),
        )?;
        eprintln!("raw components shard {}/{}", si + 1, cfg.shards.len());
    }
    phases.mark("component_hashing_and_checkpoints")?;
    let tree = DocumentTreeV3::build(
        &component_hashes
            .iter()
            .map(document_leaf_v3)
            .collect::<Vec<_>>(),
    )?;
    phases.mark("mht_build")?;
    let source_ids = (0..cfg.documents as u64).collect::<Vec<_>>();
    let raw_digest = hash_serialized(b"gem.auth.v3.raw-provenance.1", &raw_bits)?;
    let source_ids_digest = hash_serialized(b"gem.auth.v3.source-ids.1", &source_ids)?;
    let manifest = ManifestV3 {
        authentication_schema: AUTH_SCHEMA_V3,
        semantic_profile: index.semantic_profile.clone(),
        graph_params: index.graph_params,
        snapshot_id: hash_serialized(
            b"gem.auth.v3.snapshot.1",
            &(index_digest, raw_digest, source_ids_digest, provenance),
        )?,
        document_count: u32::try_from(cfg.documents)?,
        token_count: cfg.tokens,
        dimension: cfg.dimension,
        max_doc_tokens: cfg.max_doc_tokens,
        query_tokens: 32,
        params: if cfg.dataset == "sample" {
            SearchParamsV3 {
                k: 3,
                rerank_k: 4,
                ef_search: 4,
                cluster_top_t: 4,
            }
        } else {
            params()
        },
        fine_count: u32::try_from(index.fine_centroids.len() / usize::from(cfg.dimension))?,
        coarse_count: u32::try_from(index.cluster_entries.len())?,
        document_root: tree.root()?,
        fine_digest: hash_serialized(b"gem.auth.v3.fine.1", &public.fine_bits)?,
        coarse_digest: hash_serialized(b"gem.auth.v3.coarse.1", &public.coarse_bits)?,
        entry_digest: hash_serialized(b"gem.auth.v3.entry.1", &public.entries)?,
        index_digest,
        raw_digest,
        source_ids_digest,
        provenance_digest: provenance,
        canonical_raw: "finite-fp16-bits-token-major-v1".into(),
        allowed_wire: vec![RawWireV3::Fp16, RawWireV3::Fp32],
    };
    phases.mark("global_hashes_and_manifest")?;
    let digest = manifest_digest_v3(&manifest)?;
    let trusted = TrustedSnapshotV3 {
        owner_public_key: key.verifying_key().to_bytes(),
        expected_manifest_digest: digest,
        signed: SignedManifestV3 {
            manifest,
            signature: key.sign(&digest).to_bytes().to_vec(),
        },
    };
    authenticate_public_data_v3(&trusted, public.clone())?;
    let mut prepared = PreparedRawSnapshotV3 {
        trusted,
        public,
        index,
        metadata,
        source_ids,
        raw_bits,
        component_hashes,
        tree,
    };
    phases.mark("signing_and_assembly")?;
    // No trusted/public file is published before deep validation succeeds.
    validate_prepared_snapshot_v3(&prepared)?;
    phases.mark("deep_validation")?;
    let raw = std::mem::take(&mut prepared.raw_bits);
    let envelope = OfflineRaw {
        version: 1,
        input_binding,
        corpus: cfg,
        prepared,
    };
    save_offline(&output, &envelope)?;
    let trusted_path = run.join("snapshots/raw/client/trusted.json");
    if trusted_path.exists() {
        let old: TrustedSnapshotV3 = serde_json::from_reader(File::open(&trusted_path)?)?;
        ensure!(
            old == envelope.prepared.trusted,
            "refusing to replace a different published trusted root"
        );
    }
    json_write(&trusted_path, &envelope.prepared.trusted)?;
    phases.mark("snapshot_serialization_and_trusted_publication")?;
    json_write(
        &run.join("snapshots/raw/owner-validation.json"),
        &serde_json::json!({"passed":true,"deep_validated":true,"documents":envelope.prepared.metadata.len(),"total_seconds":started.elapsed().as_secs_f64(),"phases_ms":phases.values,"offline_bytes":fs::metadata(&output)?.len(),"raw_payload_storage":"original read-only shards by reference; no second raw disk payload","raw_payload_bytes":raw.iter().map(|r|r.len() as u64*2).sum::<u64>(),"document_root":hex::encode(envelope.prepared.tree.root()?)}),
    )?;
    Ok(())
}
pub fn load_raw(run: &Path) -> Result<PreparedRawSnapshotV3> {
    let mut envelope: OfflineRaw = load_offline(&run.join("snapshots/raw/server/offline.raw"))?;
    ensure!(
        envelope.version == 1
            && envelope.input_binding == sha256_file(run.join("input-bindings.json"))?
            && envelope.prepared.raw_bits.is_empty(),
        "raw offline source binding"
    );
    validate_trusted_snapshot_v3(&envelope.prepared.trusted)?;
    let pinned: TrustedSnapshotV3 =
        serde_json::from_reader(File::open(run.join("snapshots/raw/client/trusted.json"))?)?;
    ensure!(
        pinned == envelope.prepared.trusted,
        "pinned raw manifest changed"
    );
    envelope.prepared.raw_bits = DiskCorpus::new(envelope.corpus, &run.join("inputs"))?.load_all()?;
    Ok(envelope.prepared)
}
pub fn prepare_compact(run: &Path) -> Result<()> {
    let output = run.join("snapshots/compact/server/offline.compact");
    if output.exists() {
        if run.join("snapshots/compact/client/trusted.json").exists()
            && run.join("snapshots/compact/owner-validation.json").exists()
        {
            let s = load_compact(run)?;
            compact::initialize_scheme_server_snapshot_v3(s)?;
            return Ok(());
        }
        fs::rename(
            &output,
            output.with_extension(format!("interrupted-{}", std::process::id())),
        )?;
    }
    let started = Instant::now();
    let mut phases = OwnerPhaseClock::new(run, "compact");
    let cfg = config(run)?;
    let raw = load_raw(run)?;
    validate_prepared_snapshot_v3(&raw)?;
    let key = owner_key(run)?;
    ensure!(
        raw.trusted.owner_public_key == key.verifying_key().to_bytes(),
        "compact owner key differs from the signed raw snapshot owner"
    );
    let input_binding = sha256_file(run.join("input-bindings.json"))?;
    let binding = hash_serialized(
        b"gem.csr38.compact.checkpoint.v1",
        &(
            raw.trusted.expected_manifest_digest,
            sha256_file(std::env::current_exe()?)?,
            COMPACT_PROFILE_ID_V1,
        ),
    )?;
    phases.mark("source_loading_and_validation")?;
    let fixed_documents = raw
        .raw_bits
        .par_iter()
        .map(|a| compact_fp16_v1(a))
        .collect::<gem_core::Result<Vec<_>>>()?;
    let fine_fixed = compact_fp16_v1(&raw.public.fine_bits)?;
    let coarse_fixed = compact_coordinates_v1(&raw.index.coarse_centroids)?;
    phases.mark("fixed_conversion")?;
    let rows = usize::from(cfg.max_doc_tokens) * usize::from(cfg.dimension);
    gem_matrix_proof::generators_v1(rows)?;
    phases.mark("document_generators")?;
    let mut commitments = Vec::with_capacity(cfg.documents);
    let commit = |id: usize| -> gem_core::Result<_> {
        let mut a = fixed_documents[id].clone();
        a.resize(rows, 0);
        compact::numeric::commit_matrix(&a)
    };
    for (si, s) in cfg.shards.iter().enumerate() {
        let p = run.join(format!("checkpoints/compact/shard-{si:04}.offline"));
        let shard = if p.exists() {
            let v: CommitmentShard = load_offline(&p)?;
            ensure!(
                v.binding == binding
                    && v.first == s.doc_start
                    && v.end == s.doc_end
                    && v.commitments.len() == s.doc_end - s.doc_start,
                "compact checkpoint binding mismatch"
            );
            v
        } else {
            let points = (s.doc_start..s.doc_end)
                .into_par_iter()
                .map(commit)
                .collect::<gem_core::Result<Vec<_>>>()?;
            let v = CommitmentShard {
                binding,
                first: s.doc_start,
                end: s.doc_end,
                commitments: points,
            };
            save_offline(&p, &v)?;
            v
        };
        commitments.extend(shard.commitments);
        json_write(
            &run.join("checkpoints/owner-progress.json"),
            &serde_json::json!({"stage":"compact_commitments","shards_done":si+1,"shards_total":cfg.shards.len(),"documents_done":s.doc_end,"elapsed_seconds":started.elapsed().as_secs_f64()}),
        )?;
        eprintln!(
            "compact commitments shard {}/{} elapsed={:.1}s",
            si + 1,
            cfg.shards.len(),
            started.elapsed().as_secs_f64()
        );
    }
    phases.mark("document_commitments_and_checkpoints")?;
    // Full deep verification is checkpointed separately from generation.
    for (si, s) in cfg.shards.iter().enumerate() {
        let p = run.join(format!("checkpoints/compact/deep-{si:04}.json"));
        let shard_digest = hash_serialized(
            b"gem.csr38.commitment-shard.v1",
            &commitments[s.doc_start..s.doc_end],
        )?;
        let expected = serde_json::json!({"binding":hex::encode(binding),"commitments":hex::encode(shard_digest),"documents":s.doc_end-s.doc_start,"passed":true});
        if p.exists() {
            let old: serde_json::Value = serde_json::from_reader(File::open(&p)?)?;
            ensure!(old == expected, "deep checkpoint changed");
            continue;
        }
        (s.doc_start..s.doc_end)
            .into_par_iter()
            .try_for_each(|id| -> Result<()> {
                ensure!(
                    fixed_documents[id] == compact_fp16_v1(&raw.raw_bits[id])?
                        && commitments[id] == commit(id)?,
                    "deep compact validation failed at {id}"
                );
                Ok(())
            })?;
        json_write(&p, &expected)?;
        eprintln!("deep compact shard {}/{}", si + 1, cfg.shards.len());
    }
    phases.mark("full_document_deep_validation_checkpointed")?;
    let coarse_commitment = compact::numeric::commit_matrix(&coarse_fixed)?;
    let fine_commitment = compact::numeric::commit_matrix(&fine_fixed)?;
    phases.mark("centroid_commitments_and_generators")?;
    let hashes = raw
        .metadata
        .par_iter()
        .enumerate()
        .map(|(id, m)| -> gem_core::Result<_> {
            let d = &raw.index.documents[id];
            Ok([
                compact::scheme_component_hash_v3(m, 0, m)?,
                compact::scheme_component_hash_v3(m, 1, &d.cluster_ids)?,
                compact::scheme_component_hash_v3(m, 2, &d.compact_codes)?,
                compact::scheme_component_hash_v3(m, 3, &d.adjacency)?,
                compact::scheme_component_hash_v3(
                    m,
                    5,
                    &compact::DocumentMatrixCommitmentV3::new(commitments[id]),
                )?,
            ])
        })
        .collect::<gem_core::Result<Vec<_>>>()?;
    let tree = DocumentTreeV3::build(
        &hashes
            .iter()
            .map(compact::scheme_document_leaf_v3)
            .collect::<Vec<_>>(),
    )?;
    phases.mark("components_and_mht")?;
    let manifest = compact::SchemeManifestV3::new(
        raw.trusted.signed.clone(),
        tree.root()?,
        hash_serialized(compact::numeric::DOCUMENTS_DOMAIN, &fixed_documents)?,
        cfg.max_doc_tokens,
        [coarse_commitment, fine_commitment],
        compact::scheme_entries_digest_v3(&raw.public.entries)?,
    );
    phases.mark("global_fixed_digest_and_manifest")?;
    let digest = compact::scheme_manifest_digest_v3(&manifest)?;
    let trusted = compact::TrustedSchemeSnapshotV3 {
        owner_public_key: key.verifying_key().to_bytes(),
        expected_manifest_digest: digest,
        signed: compact::SignedSchemeManifestV3 {
            manifest,
            signature: key.sign(&digest).to_bytes().to_vec(),
        },
    };
    compact::validate_trusted_scheme_snapshot_v3(&trusted)?;
    phases.mark("signing")?;
    let prepared = compact::PreparedSchemeSnapshotV3 {
        trusted,
        public: raw.public,
        index: raw.index,
        metadata: raw.metadata,
        source_ids: raw.source_ids,
        raw_bits: raw.raw_bits,
        fixed_documents,
        coarse_fixed,
        fine_fixed,
        commitments,
        component_hashes: hashes,
        tree,
        raw_component_hashes: raw.component_hashes,
        raw_tree: raw.tree,
    };
    let server = compact::initialize_scheme_server_snapshot_v3(prepared)?;
    phases.mark("postassembly_validation")?;
    // Move the validated server back to its serializable state without deep copies.
    let mut prepared = server.into_prepared();
    let _raw = std::mem::take(&mut prepared.raw_bits);
    let _fixed = std::mem::take(&mut prepared.fixed_documents);
    let envelope = OfflineCompact {
        version: 1,
        input_binding,
        corpus: cfg,
        prepared,
    };
    save_offline(&output, &envelope)?;
    let trusted_path = run.join("snapshots/compact/client/trusted.json");
    if trusted_path.exists() {
        let old: compact::TrustedSchemeSnapshotV3 =
            serde_json::from_reader(File::open(&trusted_path)?)?;
        ensure!(
            old == envelope.prepared.trusted,
            "refusing to replace a different published compact root"
        );
    }
    json_write(&trusted_path, &envelope.prepared.trusted)?;
    phases.mark("snapshot_serialization_and_trusted_publication")?;
    json_write(
        &run.join("snapshots/compact/owner-validation.json"),
        &serde_json::json!({"passed":true,"deep_validated":true,"deep_shards":envelope.corpus.shards.len(),"documents":envelope.prepared.metadata.len(),"total_seconds":started.elapsed().as_secs_f64(),"phases_ms":phases.values,"offline_bytes":fs::metadata(&output)?.len(),"raw_payload_storage":"original read-only shards by reference","fixed_payload_storage":"deterministically reconstructed once on load","document_root":hex::encode(envelope.prepared.tree.root()?)}),
    )?;
    Ok(())
}
pub fn load_compact(run: &Path) -> Result<compact::PreparedSchemeSnapshotV3> {
    let mut envelope: OfflineCompact =
        load_offline(&run.join("snapshots/compact/server/offline.compact"))?;
    ensure!(
        envelope.version == 1
            && envelope.input_binding == sha256_file(run.join("input-bindings.json"))?
            && envelope.prepared.raw_bits.is_empty()
            && envelope.prepared.fixed_documents.is_empty(),
        "compact offline source binding"
    );
    compact::validate_trusted_scheme_snapshot_v3(&envelope.prepared.trusted)?;
    let pinned: compact::TrustedSchemeSnapshotV3 = serde_json::from_reader(File::open(
        run.join("snapshots/compact/client/trusted.json"),
    )?)?;
    ensure!(
        pinned == envelope.prepared.trusted,
        "pinned compact manifest changed"
    );
    envelope.prepared.raw_bits = DiskCorpus::new(envelope.corpus, &run.join("inputs"))?.load_all()?;
    envelope.prepared.fixed_documents = envelope
        .prepared
        .raw_bits
        .par_iter()
        .map(|a| compact_fp16_v1(a))
        .collect::<gem_core::Result<_>>()?;
    Ok(envelope.prepared)
}
