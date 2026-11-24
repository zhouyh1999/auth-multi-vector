use gem_core::{GemError, Hash, Result, hash_bytes};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProofV3 {
    /// Missing siblings, bottom-up and left-to-right within each level.
    /// Positions follow from the authenticated document count and opened leaf IDs.
    pub siblings: Vec<Hash>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentTreeV3 {
    pub document_count: u32,
    pub levels: Vec<Vec<Hash>>,
}
fn parent(n: u32, a: Hash, b: Hash) -> Hash {
    let mut v = [0; 68];
    v[..4].copy_from_slice(&n.to_le_bytes());
    v[4..36].copy_from_slice(&a);
    v[36..].copy_from_slice(&b);
    hash_bytes(b"gem.auth.v3.node.1", &v)
}
fn width(n: u32) -> Result<u32> {
    if n == 0 {
        return Err(GemError::InvalidManifest);
    }
    n.checked_next_power_of_two()
        .ok_or(GemError::NumericOverflow)
}
impl DocumentTreeV3 {
    pub fn build(leaves: &[Hash]) -> Result<Self> {
        let n = u32::try_from(leaves.len()).map_err(|_| GemError::NumericOverflow)?;
        let w = width(n)?;
        let mut row = leaves.to_vec();
        for id in n..w {
            let mut b = Vec::new();
            b.extend(n.to_le_bytes());
            b.extend(id.to_le_bytes());
            row.push(hash_bytes(b"gem.auth.v3.padding.1", &b));
        }
        let mut levels = vec![row];
        while levels.last().ok_or(GemError::InvalidMerkleProof)?.len() > 1 {
            let next = levels
                .last()
                .ok_or(GemError::InvalidMerkleProof)?
                .chunks_exact(2)
                .map(|v| parent(n, v[0], v[1]))
                .collect();
            levels.push(next);
        }
        Ok(Self {
            document_count: n,
            levels,
        })
    }
    pub fn root(&self) -> Result<Hash> {
        self.levels
            .last()
            .and_then(|r| r.first())
            .copied()
            .ok_or(GemError::InvalidMerkleProof)
    }
    pub fn prove(&self, ids: &[u32]) -> Result<MerkleProofV3> {
        canonical_ids(ids, self.document_count)?;
        let mut frontier = ids.to_vec();
        let mut siblings = Vec::new();
        for row in self.levels.iter().take(self.levels.len() - 1) {
            let mut next = Vec::with_capacity(frontier.len());
            let mut cursor = 0;
            while cursor < frontier.len() {
                let i = frontier[cursor];
                if i.is_multiple_of(2) && frontier.get(cursor + 1) == Some(&(i + 1)) {
                    cursor += 2;
                } else {
                    siblings.push(row[(i ^ 1) as usize]);
                    cursor += 1;
                }
                next.push(i / 2);
            }
            frontier = next;
        }
        Ok(MerkleProofV3 { siblings })
    }
}
fn canonical_ids(ids: &[u32], n: u32) -> Result<()> {
    if ids.iter().any(|&i| i >= n) || ids.windows(2).any(|p| p[0] >= p[1]) {
        return Err(GemError::NonCanonicalOrder);
    }
    Ok(())
}
/// Empty proofs are authenticated only in conjunction with empty deterministic replay.
pub fn verify_document_multiproof_v3(
    n: u32,
    root: Hash,
    leaves: &[(u32, Hash)],
    proof: &MerkleProofV3,
) -> Result<()> {
    let w = width(n)?;
    let ids: Vec<u32> = leaves.iter().map(|x| x.0).collect();
    canonical_ids(&ids, n)?;
    if leaves.is_empty() {
        return if proof.siblings.is_empty() {
            Ok(())
        } else {
            Err(GemError::InvalidMerkleProof)
        };
    }
    let mut siblings = proof.siblings.iter();
    let mut row = leaves.to_vec();
    for _ in 0..w.trailing_zeros() {
        let mut next = Vec::with_capacity(row.len());
        let mut cursor = 0;
        while cursor < row.len() {
            let (i, h) = row[cursor];
            let other = if i % 2 == 0 && row.get(cursor + 1).is_some_and(|x| x.0 == i + 1) {
                cursor += 2;
                row[cursor - 1].1
            } else {
                cursor += 1;
                *siblings.next().ok_or(GemError::InvalidMerkleProof)?
            };
            let p = if i % 2 == 0 {
                parent(n, h, other)
            } else {
                parent(n, other, h)
            };
            next.push((i / 2, p));
        }
        row = next;
    }
    if siblings.next().is_some() {
        return Err(GemError::InvalidMerkleProof);
    }
    if row.as_slice() != [(0, root)] {
        return Err(GemError::MerkleRootMismatch);
    }
    Ok(())
}
