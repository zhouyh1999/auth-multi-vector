//! Fixed-width, manifest-bounded schema 8/9 codec. Every allocation follows a byte/count check.
use super::numeric::*;
use super::*;
use gem_auth_v3::{
    ComponentOpening, MAX_VO_BYTES, MerkleProofV3, MetadataV3, PublicDataV3, PublicModeV3,
    RawOpeningV3,
};
use gem_core::{FixedDistanceV3, GemError, Result};
use gem_matrix_proof::{
    ProjectionArgumentV1, canonical_point_v1, canonical_scalar_v1, projection_argument_bytes_v1,
    validate_projection_argument_v1,
};
use gem_search::ExecutionNodeV3;
// Wire revision 4: client-supplied trust and locally computed request binding.
// Authentication schemas 8/9 and signed snapshots are unchanged.
const MAGIC: &[u8; 8] = b"G3SCHVO4";
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or(GemError::NumericOverflow)?;
        let x = self
            .b
            .get(self.p..end)
            .ok_or(GemError::InvalidFrameLength)?;
        self.p = end;
        Ok(x)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| GemError::InvalidFrameLength)?,
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| GemError::InvalidFrameLength)?,
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| GemError::InvalidFrameLength)?,
        ))
    }
    fn hash(&mut self) -> Result<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| GemError::InvalidFrameLength)
    }
    fn flag(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(GemError::NonCanonicalFrame),
        }
    }
    fn count(&mut self, max: usize, size: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > max
            || n.checked_mul(size)
                .filter(|&v| v <= self.b.len() - self.p)
                .is_none()
        {
            return Err(GemError::FrameTooLarge);
        }
        Ok(n)
    }
    fn fixed_vec16(&mut self, n: usize) -> Result<Vec<u16>> {
        let bytes = self.take(n.checked_mul(2).ok_or(GemError::NumericOverflow)?)?;
        Ok(bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect())
    }
    fn fixed_vec32(&mut self, n: usize) -> Result<Vec<u32>> {
        let bytes = self.take(n.checked_mul(4).ok_or(GemError::NumericOverflow)?)?;
        Ok(bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect())
    }
    fn vec32(&mut self, max: usize) -> Result<Vec<u32>> {
        let n = self.count(max, 4)?;
        self.fixed_vec32(n)
    }
    fn fixed_similarities(&mut self, n: usize) -> Result<Vec<Similarity>> {
        let width = std::mem::size_of::<Similarity>();
        let bytes = self.take(n.checked_mul(width).ok_or(GemError::NumericOverflow)?)?;
        bytes
            .chunks_exact(width)
            .map(|b| {
                Ok(Similarity::from_le_bytes(
                    b.try_into().map_err(|_| GemError::InvalidFrameLength)?,
                ))
            })
            .collect()
    }
    fn opening32(&mut self, max: usize) -> Result<ComponentOpening<Vec<u32>>> {
        if self.flag()? {
            Ok(ComponentOpening::Revealed(self.vec32(max)?))
        } else {
            Ok(ComponentOpening::Digest(self.hash()?))
        }
    }
    fn codes(&mut self, token_count: u16) -> Result<ComponentOpening<Vec<u32>>> {
        if self.flag()? {
            // Check all bytes before allocating; metadata bounds this count.
            let bytes = self.take(usize::from(token_count) * 4)?;
            Ok(ComponentOpening::Revealed(
                bytes
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .collect(),
            ))
        } else {
            Ok(ComponentOpening::Digest(self.hash()?))
        }
    }
    fn projection(&mut self, rows: usize, d: usize) -> Result<ProjectionArgumentV1> {
        let coordinates = self.take(d.checked_mul(32).ok_or(GemError::NumericOverflow)?)?;
        let projection = coordinates
            .chunks_exact(32)
            .map(|bytes| {
                let b = bytes.try_into().map_err(|_| GemError::InvalidFrameLength)?;
                canonical_scalar_v1(b)?;
                Ok(b)
            })
            .collect::<Result<Vec<_>>>()?;
        let dimension = rows.checked_mul(d).ok_or(GemError::NumericOverflow)?;
        let expected = projection_argument_bytes_v1(dimension)?;
        let bytes = self.take(expected)?;
        validate_projection_argument_v1(bytes, dimension)?;
        Ok(ProjectionArgumentV1 {
            projection,
            argument: bytes.to_vec(),
        })
    }
}
struct Writer {
    b: Vec<u8>,
    stats: SchemeVoBytesV3,
}
impl Writer {
    fn add(&mut self, key: &str, b: &[u8]) {
        self.b.extend_from_slice(b);
        *self.stats.parts.entry(key.into()).or_default() += b.len();
    }
    fn count(&mut self, n: usize) -> Result<()> {
        self.add(
            "framing",
            &u32::try_from(n)
                .map_err(|_| GemError::NumericOverflow)?
                .to_le_bytes(),
        );
        Ok(())
    }
    fn flag(&mut self, b: bool) {
        self.add("framing", &[u8::from(b)]);
    }
    fn fixed_vec16(&mut self, key: &str, a: &[u16]) -> Result<()> {
        let bytes = a.len().checked_mul(2).ok_or(GemError::NumericOverflow)?;
        self.b.reserve(bytes);
        for x in a {
            self.b.extend_from_slice(&x.to_le_bytes());
        }
        if bytes != 0 {
            *self.stats.parts.entry(key.into()).or_default() += bytes;
        }
        Ok(())
    }
    fn vec32(&mut self, key: &str, a: &[u32]) -> Result<()> {
        self.count(a.len())?;
        self.fixed_vec32(key, a)
    }
    fn fixed_vec32(&mut self, key: &str, a: &[u32]) -> Result<()> {
        let bytes = a.len().checked_mul(4).ok_or(GemError::NumericOverflow)?;
        self.b.reserve(bytes);
        for x in a {
            self.b.extend_from_slice(&x.to_le_bytes());
        }
        if bytes != 0 {
            *self.stats.parts.entry(key.into()).or_default() += bytes;
        }
        Ok(())
    }
    fn fixed_similarities(&mut self, key: &str, a: &[Similarity]) -> Result<()> {
        let bytes = a
            .len()
            .checked_mul(std::mem::size_of::<Similarity>())
            .ok_or(GemError::NumericOverflow)?;
        self.b.reserve(bytes);
        for x in a {
            self.b.extend_from_slice(&x.to_le_bytes());
        }
        if bytes != 0 {
            *self.stats.parts.entry(key.into()).or_default() += bytes;
        }
        Ok(())
    }
    fn opening32(&mut self, key: &str, o: &ComponentOpening<Vec<u32>>) -> Result<()> {
        match o {
            ComponentOpening::Digest(h) => {
                self.flag(false);
                self.add("hidden_digests", h);
            }
            ComponentOpening::Revealed(a) => {
                self.flag(true);
                self.vec32(key, a)?;
            }
        }
        Ok(())
    }
    fn codes(&mut self, o: &ComponentOpening<Vec<u32>>, token_count: u16) -> Result<()> {
        match o {
            ComponentOpening::Digest(h) => {
                self.flag(false);
                self.add("hidden_digests", h);
            }
            ComponentOpening::Revealed(a) => {
                if a.len() != usize::from(token_count) {
                    return Err(GemError::InvalidTokenCount);
                }
                self.flag(true);
                self.fixed_vec32("codes", a)?;
            }
        }
        Ok(())
    }
    fn projection(&mut self, p: &ProjectionArgumentV1) {
        for x in &p.projection {
            self.add("projections", x);
        }
        self.add("arguments", &p.argument);
    }
}
pub fn encode_scheme_vo_v3(v: &SchemeRetrievalVoV3) -> Result<(Vec<u8>, SchemeVoBytesV3)> {
    let mut w = Writer {
        b: vec![],
        stats: Default::default(),
    };
    w.add(
        "framing",
        &[
            v.backend as u8,
            match v.public_mode {
                PublicModeV3::Cold => 0,
            },
        ],
    );
    w.flag(v.public.is_some());
    if let Some(p) = &v.public {
        for e in &p.entries {
            w.flag(e.is_some());
            if let Some(id) = e {
                w.add("entries", &id.to_le_bytes());
            }
        }
        w.flag(p.raw_centroids.is_some());
        if let Some(raw) = &p.raw_centroids {
            if raw.entries != p.entries {
                return Err(GemError::InvalidManifest);
            }
            w.fixed_vec16("public_fine_centroids", &raw.fine_bits)?;
            w.fixed_vec32("public_coarse_centroids", &raw.coarse_bits)?;
        }
    }
    w.count(v.documents.len())?;
    for d in &v.documents {
        w.add("metadata", &d.metadata.doc_id.to_le_bytes());
        w.add("metadata", &d.metadata.token_count.to_le_bytes());
        w.opening32("membership", &d.membership)?;
        w.codes(&d.codes, d.metadata.token_count)?;
        w.opening32("adjacency", &d.adjacency)?;
        if !d.vector.matches_backend(v.backend) {
            return Err(GemError::InvalidManifest);
        }
        match &d.vector {
            DocumentVectorOpeningV3::Raw(ComponentOpening::Digest(h))
            | DocumentVectorOpeningV3::Commitment(ComponentOpening::Digest(h)) => {
                w.flag(false);
                w.add("hidden_digests", h);
            }
            DocumentVectorOpeningV3::Raw(ComponentOpening::Revealed(raw)) => {
                w.flag(true);
                match (v.backend, raw) {
                    (SchemeBackendV3::FixedRawFp16, RawOpeningV3::Fp16(a)) => {
                        w.fixed_vec16("raw", a)?;
                    }
                    (SchemeBackendV3::FixedRawFp32, RawOpeningV3::Fp32(a)) => {
                        w.fixed_vec32("raw", a)?;
                    }
                    _ => return Err(GemError::NonCanonicalFrame),
                }
            }
            DocumentVectorOpeningV3::Commitment(ComponentOpening::Revealed(c)) => {
                w.flag(true);
                w.add("commitments", &c.point);
            }
        }
    }
    w.count(v.proof.siblings.len())?;
    for s in &v.proof.siblings {
        w.add("merkle_siblings", s);
    }
    w.flag(v.metrics.is_some());
    if let Some(p) = &v.metrics {
        w.fixed_similarities("coarse_table", &p.coarse)?;
        w.projection(&p.coarse_argument);
        w.flag(p.fine_argument.is_some());
        w.fixed_similarities("fine_table", &p.fine)?;
        if let Some(fp) = &p.fine_argument {
            w.projection(fp);
        }
    }
    w.flag(v.reranking.is_some());
    if let Some(p) = &v.reranking {
        w.fixed_similarities("y", &p.similarities)?;
        w.projection(&p.argument);
    }
    w.count(v.results.len())?;
    for result in &v.results {
        w.add("results", &result.doc_id.to_le_bytes());
        w.add("results", &result.distance.0.to_le_bytes());
    }
    let mut bytes = MAGIC.to_vec();
    bytes.extend(SCHEME_AUTH_SCHEMA_V3.to_le_bytes());
    bytes.extend((w.b.len() as u64).to_le_bytes());
    bytes.extend(w.b);
    *w.stats.parts.entry("framing".into()).or_default() += 18;
    w.stats.total = bytes.len();
    if bytes.len() > MAX_VO_BYTES {
        return Err(GemError::FrameTooLarge);
    }
    if w.stats.parts.values().sum::<usize>() != bytes.len() {
        return Err(GemError::InvalidFrameLength);
    }
    Ok((bytes, w.stats))
}
pub fn decode_scheme_vo_v3(
    bytes: &[u8],
    trusted: &TrustedSchemeSnapshotV3,
) -> Result<SchemeRetrievalVoV3> {
    if bytes.len() > MAX_VO_BYTES {
        return Err(GemError::FrameTooLarge);
    }
    let mut r = Reader { b: bytes, p: 0 };
    if r.take(8)? != MAGIC {
        return Err(GemError::InvalidMagic);
    }
    let schema = r.u16()?;
    if schema != SCHEME_AUTH_SCHEMA_V3 {
        return Err(GemError::UnsupportedVersion(schema));
    }
    if r.u64()?
        != bytes
            .len()
            .checked_sub(18)
            .ok_or(GemError::InvalidFrameLength)? as u64
    {
        return Err(GemError::InvalidFrameLength);
    }
    // Only the authenticated client configuration supplies allocation bounds.
    validate_trusted_scheme_snapshot_v3(trusted)?;
    let backend = match r.u8()? {
        0 => SchemeBackendV3::FixedRawFp16,
        1 => SchemeBackendV3::FixedRawFp32,
        2 => SchemeBackendV3::MatrixScheme,
        _ => return Err(GemError::NonCanonicalFrame),
    };
    let public_mode = match r.u8()? {
        0 => PublicModeV3::Cold,
        _ => return Err(GemError::NonCanonicalFrame),
    };
    let m = &trusted.signed.manifest;
    let base = m.source();
    let d = usize::from(base.dimension);
    let qt = usize::from(base.query_tokens);
    let public = if r.flag()? {
        let n = base.coarse_count as usize;
        if n > r.b.len() - r.p {
            return Err(GemError::InvalidFrameLength);
        }
        let entries = (0..n)
            .map(|_| {
                if r.flag()? {
                    Ok(Some(r.u32()?))
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let raw_centroids = if r.flag()? {
            let fine_bits = r.fixed_vec16(base.fine_count as usize * d)?;
            let coarse_bits = r.fixed_vec32(base.coarse_count as usize * d)?;
            Some(PublicDataV3 {
                fine_bits,
                coarse_bits,
                entries: entries.clone(),
            })
        } else {
            None
        };
        Some(SchemePublicPayloadV3 {
            entries,
            raw_centroids,
        })
    } else {
        return Err(GemError::NonCanonicalFrame);
    };
    let n = r.count(base.document_count as usize, 10)?;
    let mut documents = Vec::with_capacity(n);
    let mut last = None;
    let mut candidate_count = 0usize;
    let mut candidate_tokens = 0usize;
    for _ in 0..n {
        let metadata = MetadataV3 {
            doc_id: r.u32()?,
            token_count: r.u16()?,
        };
        if metadata.doc_id >= base.document_count
            || last.is_some_and(|id| id >= metadata.doc_id)
            || metadata.token_count == 0
            || metadata.token_count > base.max_doc_tokens
        {
            return Err(GemError::NonCanonicalOrder);
        }
        last = Some(metadata.doc_id);
        let membership = r.opening32(base.coarse_count as usize)?;
        let codes = r.codes(metadata.token_count)?;
        let adjacency = r.opening32(usize::from(base.graph_params.m0))?;
        let vector = if backend == SchemeBackendV3::MatrixScheme {
            DocumentVectorOpeningV3::Commitment(if r.flag()? {
                let c = r.hash()?;
                canonical_point_v1(c)?;
                ComponentOpening::Revealed(DocumentMatrixCommitmentV3::new(c))
            } else {
                ComponentOpening::Digest(r.hash()?)
            })
        } else {
            DocumentVectorOpeningV3::Raw(if r.flag()? {
                let n = usize::from(metadata.token_count) * d;
                ComponentOpening::Revealed(match backend {
                    SchemeBackendV3::FixedRawFp16 => RawOpeningV3::Fp16(r.fixed_vec16(n)?),
                    SchemeBackendV3::FixedRawFp32 => RawOpeningV3::Fp32(r.fixed_vec32(n)?),
                    _ => return Err(GemError::NonCanonicalFrame),
                })
            } else {
                ComponentOpening::Digest(r.hash()?)
            })
        };
        if backend == SchemeBackendV3::MatrixScheme && vector.is_revealed() {
            // Parsing bound only: replay later authenticates this exact candidate set.
            candidate_count += 1;
            if candidate_count > base.params.rerank_k.min(base.document_count) as usize {
                return Err(GemError::FrameTooLarge);
            }
            candidate_tokens = candidate_tokens
                .checked_add(usize::from(metadata.token_count))
                .ok_or(GemError::NumericOverflow)?;
        }
        documents.push(SchemeDocumentOpeningV3 {
            metadata,
            membership,
            codes,
            adjacency,
            vector,
        });
    }
    let n = r.count(base.document_count as usize * 2, 32)?;
    let siblings = (0..n).map(|_| r.hash()).collect::<Result<Vec<_>>>()?;
    let metrics = if r.flag()? {
        let coarse = r.fixed_similarities(qt * base.coarse_count as usize)?;
        let coarse_argument = r.projection(base.coarse_count as usize, d)?;
        let (fine, fine_argument) = if r.flag()? {
            (
                r.fixed_similarities(qt * base.fine_count as usize)?,
                Some(r.projection(base.fine_count as usize, d)?),
            )
        } else {
            (vec![], None)
        };
        Some(MetricPayloadFixedV3 {
            coarse,
            fine,
            coarse_argument,
            fine_argument,
        })
    } else {
        None
    };
    let reranking = if r.flag()? {
        if backend != SchemeBackendV3::MatrixScheme || candidate_count == 0 {
            return Err(GemError::InvalidManifest);
        }
        let values = qt
            .checked_mul(candidate_tokens)
            .ok_or(GemError::NumericOverflow)?;
        let similarities = r.fixed_similarities(values)?;
        let argument = r.projection(usize::from(m.document_rows), d)?;
        Some(RerankingPayloadFixedV3 {
            similarities,
            argument,
        })
    } else {
        None
    };
    let n = r.count(base.params.k.min(base.document_count) as usize, 20)?;
    let results = (0..n)
        .map(|_| {
            Ok(ExecutionNodeV3 {
                doc_id: r.u32()?,
                distance: FixedDistanceV3(i128::from_le_bytes(
                    r.take(16)?
                        .try_into()
                        .map_err(|_| GemError::InvalidFrameLength)?,
                )),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if r.p != bytes.len() {
        return Err(GemError::NonCanonicalFrame);
    }
    Ok(SchemeRetrievalVoV3 {
        backend,
        public_mode,
        public,
        documents,
        proof: MerkleProofV3 { siblings },
        metrics,
        reranking,
        results,
    })
}

#[cfg(test)]
mod optimization_tests {
    use super::*;
    #[test]
    fn implicit_code_length_preserves_values_and_checks_bytes_before_allocation() {
        let codes = ComponentOpening::Revealed(vec![7, 0, u32::MAX]);
        let mut w = Writer {
            b: vec![],
            stats: Default::default(),
        };
        w.codes(&codes, 3).unwrap();
        let expected = [
            vec![1],
            7u32.to_le_bytes().to_vec(),
            0u32.to_le_bytes().to_vec(),
            u32::MAX.to_le_bytes().to_vec(),
        ]
        .concat();
        assert_eq!(w.b, expected);
        assert_eq!(w.stats.parts["codes"], 12);
        assert_eq!(w.stats.parts["framing"], 1);
        let mut r = Reader { b: &w.b, p: 0 };
        assert_eq!(r.codes(3).unwrap(), codes);
        assert_eq!(r.p, w.b.len());
        for end in 0..w.b.len() {
            assert!(
                Reader {
                    b: &w.b[..end],
                    p: 0
                }
                .codes(3)
                .is_err()
            );
        }
        assert!(Reader { b: &[1], p: 0 }.codes(u16::MAX).is_err());
        assert!(Reader { b: &[2], p: 0 }.codes(3).is_err());
        assert!(w.codes(&codes, 2).is_err());
        let hidden = ComponentOpening::Digest([17; 32]);
        let mut w = Writer {
            b: vec![],
            stats: Default::default(),
        };
        w.codes(&hidden, 3).unwrap();
        assert_eq!(w.b.len(), 33);
        assert_eq!(Reader { b: &w.b, p: 0 }.codes(3).unwrap(), hidden);
    }
    #[test]
    fn fixed_arrays_omit_lengths_and_preserve_values_and_accounting() {
        let values = [Similarity::MIN, -1, 0, 1, Similarity::MAX];
        let mut new = Writer {
            b: vec![],
            stats: SchemeVoBytesV3::default(),
        };
        let mut old = Writer {
            b: vec![],
            stats: SchemeVoBytesV3::default(),
        };
        new.fixed_similarities("Y", &values).unwrap();
        for v in values {
            old.add("Y", &v.to_le_bytes());
        }
        new.fixed_vec16("raw", &[0, 1, 65535]).unwrap();
        for v in [0u16, 1, 65535] {
            old.add("raw", &v.to_le_bytes());
        }
        new.fixed_vec32("codes", &[0, 1, u32::MAX]).unwrap();
        for v in [0u32, 1, u32::MAX] {
            old.add("codes", &v.to_le_bytes());
        }
        new.fixed_similarities("Y", &[]).unwrap();
        new.fixed_similarities("empty", &[]).unwrap();
        assert_eq!(new.b, old.b);
        assert_eq!(new.stats.parts, old.stats.parts);
        assert!(!new.stats.parts.contains_key("framing"));
        let mut r = Reader { b: &new.b, p: 0 };
        assert_eq!(r.fixed_similarities(values.len()).unwrap(), values);
        assert_eq!(r.fixed_vec16(3).unwrap(), [0, 1, 65535]);
        assert_eq!(r.fixed_vec32(3).unwrap(), [0, 1, u32::MAX]);
        assert_eq!(r.p, new.b.len());
        for length in 0..values.len() * std::mem::size_of::<Similarity>() {
            assert!(
                Reader {
                    b: &new.b[..length],
                    p: 0
                }
                .fixed_similarities(values.len())
                .is_err()
            );
        }
        for length in 0..6 {
            assert!(
                Reader {
                    b: &new.b[..length],
                    p: 0
                }
                .fixed_vec16(3)
                .is_err()
            );
        }
        for length in 0..12 {
            assert!(
                Reader {
                    b: &new.b[..length],
                    p: 0
                }
                .fixed_vec32(3)
                .is_err()
            );
        }
        assert!(
            Reader { b: &[], p: 0 }
                .fixed_similarities(usize::MAX)
                .is_err()
        );
        assert!(Reader { b: &[], p: 0 }.fixed_vec16(usize::MAX).is_err());
        assert!(Reader { b: &[], p: 0 }.fixed_vec32(usize::MAX).is_err());
        assert!(Reader { b: &[], p: 0 }.projection(1, usize::MAX).is_err());
    }
}
