use super::*;

pub(super) fn pack_y(matrices: &[(u32, usize, Vec<Similarity>)], m: usize) -> Vec<Similarity> {
    let mut y = Vec::new();
    for j in 0..m {
        for (_, n, a) in matrices {
            y.extend_from_slice(&a[j * n..(j + 1) * n]);
        }
    }
    y
}
pub(super) struct SparseAccess<'a> {
    pub(super) docs: BTreeMap<u32, &'a SchemeDocumentOpeningV3>,
}
impl SparseAccess<'_> {
    pub(super) fn doc(&self, id: u32) -> Result<&SchemeDocumentOpeningV3> {
        self.docs.get(&id).copied().ok_or(GemError::InvalidManifest)
    }
}
impl SearchAccessV3 for SparseAccess<'_> {
    fn metadata(&self, id: u32) -> Result<u16> {
        Ok(self.doc(id)?.metadata.token_count)
    }
    fn membership(&self, id: u32) -> Result<&[u32]> {
        Ok(self.doc(id)?.membership.revealed()?)
    }
    fn codes(&self, id: u32) -> Result<&[u32]> {
        Ok(self.doc(id)?.codes.revealed()?)
    }
    fn adjacency(&self, id: u32) -> Result<&[u32]> {
        Ok(self.doc(id)?.adjacency.revealed()?)
    }
}
pub(super) fn open_hash<T: serde::Serialize>(
    backend: SchemeBackendV3,
    meta: &MetadataV3,
    kind: u8,
    o: &ComponentOpening<T>,
) -> Result<Hash> {
    match o {
        ComponentOpening::Digest(h) => Ok(*h),
        ComponentOpening::Revealed(v) => backend_component_hash_v3(backend, meta, kind, v),
    }
}
pub(super) fn ordered(ids: &[u32], max: u32) -> bool {
    ids.iter().all(|&id| id < max) && !ids.windows(2).any(|w| w[0] >= w[1])
}
pub(super) type CandidateMatricesV3 = Vec<(u32, usize, Vec<Similarity>)>;
