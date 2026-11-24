//! Canonical bounded wire codec: lengths are checked before every allocation.
use crate::*;
use gem_core::{GemError, Hash, NodeDistanceF32V3, Result};
// Wire revision 4: global trust and request binding are not repeated in the VO.
// Authentication schema, signed snapshots, and Merkle hashing are unchanged.
const MAGIC: [u8; 8] = *b"G3RAWVO4";

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or(GemError::NumericOverflow)?;
        let b = self
            .b
            .get(self.p..end)
            .ok_or(GemError::InvalidFrameLength)?;
        self.p = end;
        Ok(b)
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
    fn hash(&mut self) -> Result<Hash> {
        self.take(32)?
            .try_into()
            .map_err(|_| GemError::InvalidFrameLength)
    }
    fn count(&mut self, max: usize, size: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > max
            || n.checked_mul(size)
                .filter(|&x| x <= self.b.len() - self.p)
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
    fn opening32(&mut self, max: usize) -> Result<ComponentOpening<Vec<u32>>> {
        match self.u8()? {
            0 => Ok(ComponentOpening::Digest(self.hash()?)),
            1 => Ok(ComponentOpening::Revealed(self.vec32(max)?)),
            _ => Err(GemError::NonCanonicalFrame),
        }
    }
    fn codes(&mut self, token_count: u16) -> Result<ComponentOpening<Vec<u32>>> {
        match self.u8()? {
            0 => Ok(ComponentOpening::Digest(self.hash()?)),
            1 => {
                // Check all bytes before allocating; metadata bounds this count.
                let bytes = self.take(usize::from(token_count) * 4)?;
                Ok(ComponentOpening::Revealed(
                    bytes
                        .chunks_exact(4)
                        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                        .collect(),
                ))
            }
            _ => Err(GemError::NonCanonicalFrame),
        }
    }
    fn public(&mut self, m: &ManifestV3) -> Result<PublicDataV3> {
        let nf = (m.fine_count as usize)
            .checked_mul(usize::from(m.dimension))
            .ok_or(GemError::NumericOverflow)?;
        let nc = (m.coarse_count as usize)
            .checked_mul(usize::from(m.dimension))
            .ok_or(GemError::NumericOverflow)?;
        let fine_bits = self.fixed_vec16(nf)?;
        let coarse_bits = self.fixed_vec32(nc)?;
        let n = m.coarse_count as usize;
        if n > self.b.len() - self.p {
            return Err(GemError::InvalidFrameLength);
        }
        let entries = (0..n)
            .map(|_| match self.u8()? {
                0 => Ok(None),
                1 => Ok(Some(self.u32()?)),
                _ => Err(GemError::NonCanonicalFrame),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PublicDataV3 {
            fine_bits,
            coarse_bits,
            entries,
        })
    }
}
fn count(b: &mut Vec<u8>, n: usize) -> Result<()> {
    b.extend(
        u32::try_from(n)
            .map_err(|_| GemError::NumericOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}
fn fixed_vec16(b: &mut Vec<u8>, v: &[u16]) {
    for x in v {
        b.extend(x.to_le_bytes())
    }
}
fn vec32(b: &mut Vec<u8>, v: &[u32]) -> Result<()> {
    count(b, v.len())?;
    fixed_vec32(b, v);
    Ok(())
}
fn fixed_vec32(b: &mut Vec<u8>, v: &[u32]) {
    for x in v {
        b.extend(x.to_le_bytes())
    }
}
fn public(b: &mut Vec<u8>, p: &PublicDataV3) {
    fixed_vec16(b, &p.fine_bits);
    fixed_vec32(b, &p.coarse_bits);
    for e in &p.entries {
        match e {
            None => b.push(0),
            Some(id) => {
                b.push(1);
                b.extend(id.to_le_bytes())
            }
        }
    }
}
fn opening32(
    b: &mut Vec<u8>,
    o: &ComponentOpening<Vec<u32>>,
    payload: &mut usize,
    stats: &mut VoBytesV3,
    exact_len: Option<usize>,
) -> Result<()> {
    match o {
        ComponentOpening::Digest(h) => {
            b.push(0);
            b.extend(h);
            stats.hidden_digests += 32;
        }
        ComponentOpening::Revealed(v) => {
            b.push(1);
            let start = b.len();
            if let Some(n) = exact_len {
                if v.len() != n {
                    return Err(GemError::InvalidTokenCount);
                }
                for x in v {
                    b.extend(x.to_le_bytes());
                }
            } else {
                vec32(b, v)?;
            }
            *payload += b.len() - start;
        }
    }
    stats.framing += 1;
    Ok(())
}
pub fn encode_raw_vo_v3(v: &RawRetrievalVoV3) -> Result<(Vec<u8>, VoBytesV3)> {
    let mut b = Vec::new();
    let mut stats = VoBytesV3::default();
    b.push(match v.raw_wire {
        RawWireV3::Fp16 => 0,
        RawWireV3::Fp32 => 1,
    });
    b.push(match v.public_mode {
        PublicModeV3::Cold => 0,
    });
    b.push(u8::from(v.public.is_some()));
    let start = b.len();
    if let Some(p) = &v.public {
        public(&mut b, p);
    }
    stats.globals = b.len() - start;
    stats.framing += 3;
    count(&mut b, v.documents.len())?;
    stats.framing += 4;
    for d in &v.documents {
        b.extend(d.metadata.doc_id.to_le_bytes());
        b.extend(d.metadata.token_count.to_le_bytes());
        stats.metadata += 6;
        let mut payload = 0;
        opening32(&mut b, &d.membership, &mut payload, &mut stats, None)?;
        stats.membership += payload;
        payload = 0;
        opening32(
            &mut b,
            &d.codes,
            &mut payload,
            &mut stats,
            Some(usize::from(d.metadata.token_count)),
        )?;
        stats.codes += payload;
        payload = 0;
        opening32(&mut b, &d.adjacency, &mut payload, &mut stats, None)?;
        stats.adjacency += payload;
        match &d.raw {
            ComponentOpening::Digest(h) => {
                b.push(0);
                b.extend(h);
                stats.hidden_digests += 32;
            }
            ComponentOpening::Revealed(raw) => {
                b.push(1);
                let start = b.len();
                match (raw, v.raw_wire) {
                    (RawOpeningV3::Fp16(v), RawWireV3::Fp16) => fixed_vec16(&mut b, v),
                    (RawOpeningV3::Fp32(v), RawWireV3::Fp32) => fixed_vec32(&mut b, v),
                    _ => return Err(GemError::NonCanonicalFrame),
                }
                stats.raw += b.len() - start;
            }
        }
        stats.framing += 1;
    }
    count(&mut b, v.proof.siblings.len())?;
    stats.framing += 4;
    for s in &v.proof.siblings {
        b.extend(s);
        stats.merkle_siblings += 32;
    }
    count(&mut b, v.results.len())?;
    stats.framing += 4;
    for r in &v.results {
        b.extend(r.doc_id.to_le_bytes());
        b.extend(r.distance_bits.to_le_bytes());
        stats.results += 8;
    }
    let mut framed = MAGIC.to_vec();
    framed.extend(AUTH_SCHEMA_V3.to_le_bytes());
    framed.extend((b.len() as u64).to_le_bytes());
    framed.extend(b);
    stats.framing += 18;
    stats.total = framed.len();
    if stats.total > MAX_VO_BYTES {
        return Err(GemError::FrameTooLarge);
    }
    if stats.total
        != stats.globals
            + stats.metadata
            + stats.membership
            + stats.codes
            + stats.adjacency
            + stats.raw
            + stats.hidden_digests
            + stats.merkle_siblings
            + stats.results
            + stats.framing
    {
        return Err(GemError::InvalidFrameLength);
    }
    Ok((framed, stats))
}
pub fn decode_raw_vo_v3(b: &[u8], trusted: &TrustedSnapshotV3) -> Result<RawRetrievalVoV3> {
    if b.len() > MAX_VO_BYTES {
        return Err(GemError::FrameTooLarge);
    }
    let mut r = Reader { b, p: 0 };
    if r.take(8)? != MAGIC {
        return Err(GemError::InvalidMagic);
    }
    if r.u16()? != AUTH_SCHEMA_V3 {
        return Err(GemError::UnsupportedVersion(0));
    }
    if r.u64()? != (b.len() - 18) as u64 {
        return Err(GemError::InvalidFrameLength);
    }
    // Bounds come exclusively from client-supplied trust, never from the VO.
    let raw_wire = match r.u8()? {
        0 => RawWireV3::Fp16,
        1 => RawWireV3::Fp32,
        _ => return Err(GemError::NonCanonicalFrame),
    };
    let public_mode = match r.u8()? {
        0 => PublicModeV3::Cold,
        _ => return Err(GemError::NonCanonicalFrame),
    };
    let m = &trusted.signed.manifest;
    let public = match (r.u8()?, public_mode) {
        (1, PublicModeV3::Cold) => Some(r.public(m)?),
        _ => return Err(GemError::NonCanonicalFrame),
    };
    let n = r.count(m.document_count as usize, 10)?;
    let mut documents = Vec::with_capacity(n);
    for _ in 0..n {
        let metadata = MetadataV3 {
            doc_id: r.u32()?,
            token_count: r.u16()?,
        };
        if metadata.doc_id >= m.document_count
            || metadata.token_count == 0
            || metadata.token_count > m.max_doc_tokens
        {
            return Err(GemError::InvalidManifest);
        }
        let membership = r.opening32(m.coarse_count as usize)?;
        let codes = r.codes(metadata.token_count)?;
        let adjacency = r.opening32(usize::from(m.graph_params.m0))?;
        let raw = match r.u8()? {
            0 => ComponentOpening::Digest(r.hash()?),
            1 => {
                let max = usize::from(metadata.token_count) * usize::from(m.dimension);
                let raw = match raw_wire {
                    RawWireV3::Fp16 => RawOpeningV3::Fp16(r.fixed_vec16(max)?),
                    RawWireV3::Fp32 => RawOpeningV3::Fp32(r.fixed_vec32(max)?),
                };
                ComponentOpening::Revealed(raw)
            }
            _ => return Err(GemError::NonCanonicalFrame),
        };
        if documents
            .last()
            .is_some_and(|d: &DocumentOpeningV3| d.metadata.doc_id >= metadata.doc_id)
        {
            return Err(GemError::NonCanonicalOrder);
        }
        documents.push(DocumentOpeningV3 {
            metadata,
            membership,
            codes,
            adjacency,
            raw,
        });
    }
    let max_siblings = (m.document_count as usize)
        .checked_next_power_of_two()
        .and_then(|n| n.checked_mul(2))
        .ok_or(GemError::NumericOverflow)?;
    let n = r.count(max_siblings, 32)?;
    let siblings = (0..n).map(|_| r.hash()).collect::<Result<Vec<_>>>()?;
    let n = r.count(m.params.k.min(m.document_count) as usize, 8)?;
    let results = (0..n)
        .map(|_| {
            Ok(NodeDistanceF32V3 {
                doc_id: r.u32()?,
                distance_bits: r.u32()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if r.p != b.len() {
        return Err(GemError::NonCanonicalFrame);
    }
    Ok(RawRetrievalVoV3 {
        raw_wire,
        public_mode,
        public,
        documents,
        proof: MerkleProofV3 { siblings },
        results,
    })
}

#[cfg(test)]
mod implicit_code_tests {
    use super::*;
    #[test]
    fn raw_arrays_have_no_length_and_reject_truncation_before_allocation() {
        let mut bytes = vec![];
        fixed_vec16(&mut bytes, &[0, 1, u16::MAX]);
        fixed_vec32(&mut bytes, &[0, 1, u32::MAX]);
        assert_eq!(
            bytes,
            [
                0, 0, 1, 0, 255, 255, 0, 0, 0, 0, 1, 0, 0, 0, 255, 255, 255, 255
            ]
        );
        let mut r = Reader { b: &bytes, p: 0 };
        assert_eq!(r.fixed_vec16(3).unwrap(), [0, 1, u16::MAX]);
        assert_eq!(r.fixed_vec32(3).unwrap(), [0, 1, u32::MAX]);
        assert_eq!(r.p, bytes.len());
        for n in 0..6 {
            assert!(
                Reader {
                    b: &bytes[..n],
                    p: 0
                }
                .fixed_vec16(3)
                .is_err()
            );
        }
        for n in 0..12 {
            assert!(
                Reader {
                    b: &bytes[..n],
                    p: 0
                }
                .fixed_vec32(3)
                .is_err()
            );
        }
        assert!(Reader { b: &[], p: 0 }.fixed_vec16(usize::MAX).is_err());
        assert!(Reader { b: &[], p: 0 }.fixed_vec32(usize::MAX).is_err());
    }
    #[test]
    fn codes_omit_only_the_length_and_reject_truncation() {
        let codes = ComponentOpening::Revealed(vec![7, 0, u32::MAX]);
        let mut bytes = vec![];
        let mut payload = 0;
        let mut stats = VoBytesV3::default();
        opening32(&mut bytes, &codes, &mut payload, &mut stats, Some(3)).unwrap();
        let expected = [
            vec![1],
            7u32.to_le_bytes().to_vec(),
            0u32.to_le_bytes().to_vec(),
            u32::MAX.to_le_bytes().to_vec(),
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_eq!(payload, 12);
        assert_eq!(stats.framing, 1);
        let mut reader = Reader { b: &bytes, p: 0 };
        assert_eq!(reader.codes(3).unwrap(), codes);
        assert_eq!(reader.p, bytes.len());
        for end in 0..bytes.len() {
            assert!(
                Reader {
                    b: &bytes[..end],
                    p: 0
                }
                .codes(3)
                .is_err()
            );
        }
        assert!(Reader { b: &[1], p: 0 }.codes(u16::MAX).is_err());
        assert!(Reader { b: &[2], p: 0 }.codes(3).is_err());
        assert!(opening32(&mut bytes, &codes, &mut payload, &mut stats, Some(2)).is_err());
        let hidden = ComponentOpening::Digest([17; 32]);
        let mut bytes = vec![];
        opening32(&mut bytes, &hidden, &mut payload, &mut stats, Some(3)).unwrap();
        assert_eq!(bytes.len(), 33);
        assert_eq!(Reader { b: &bytes, p: 0 }.codes(3).unwrap(), hidden);
    }
}
