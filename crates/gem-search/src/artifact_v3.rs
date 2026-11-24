//! Strict import and validation of official GEM/ColBERT NPY artifacts.

use std::path::{Path, PathBuf};

use gem_core::{
    GemError, QueryV3, RawDocumentV3, Result, SearchParamsV3, decode_f16, read_npy_f16_bits,
    read_npy_f32, read_npy_i32, read_npy_i64,
};
use serde::{Deserialize, Serialize};

use crate::discover_official_shard_ids_v3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialShardSpecV3 {
    pub dimension: u16,
    pub max_doc_tokens: u16,
    pub start_doc_id: u32,
    pub encoding_f16_npy: PathBuf,
    pub doc_codes_i32_npy: PathBuf,
    pub doclens_i64_npy: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedDocumentShardV3 {
    pub dimension: u16,
    pub max_doc_tokens: u16,
    pub start_doc_id: u32,
    pub documents: Vec<RawDocumentV3>,
    pub compact_codes: Vec<Vec<u32>>,
}

impl ImportedDocumentShardV3 {
    pub fn validate(&self) -> Result<()> {
        if self.dimension == 0
            || self.max_doc_tokens == 0
            || self.documents.is_empty()
            || self.documents.len() != self.compact_codes.len()
        {
            return Err(GemError::InvalidManifest);
        }
        for (offset, (document, codes)) in
            self.documents.iter().zip(&self.compact_codes).enumerate()
        {
            let expected_id = self
                .start_doc_id
                .checked_add(u32::try_from(offset).map_err(|_| GemError::NumericOverflow)?)
                .ok_or(GemError::NumericOverflow)?;
            if document.doc_id != expected_id {
                return Err(GemError::NonCanonicalOrder);
            }
            document.validate(self.dimension, self.max_doc_tokens)?;
            if codes.len() != usize::from(document.token_count) {
                return Err(GemError::InvalidTokenCount);
            }
            for &bits in &document.coordinate_bits {
                decode_f16(bits)?;
            }
        }
        Ok(())
    }
}

pub fn import_official_document_shard(
    spec: &OfficialShardSpecV3,
) -> Result<ImportedDocumentShardV3> {
    if spec.dimension == 0 || spec.max_doc_tokens == 0 {
        return Err(GemError::InvalidManifest);
    }
    let (embedding_header, embedding_bits) = read_npy_f16_bits(&spec.encoding_f16_npy)?;
    if embedding_header.shape.len() != 2 || embedding_header.shape[1] != u64::from(spec.dimension) {
        return Err(GemError::InvalidDimension {
            expected: usize::from(spec.dimension),
            actual: embedding_header
                .shape
                .get(1)
                .copied()
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(0),
        });
    }
    let (codes_header, signed_codes) = read_npy_i32(&spec.doc_codes_i32_npy)?;
    if codes_header.shape.len() != 1
        && !(codes_header.shape.len() == 2 && codes_header.shape[1] == 1)
    {
        return Err(GemError::NonCanonicalFrame);
    }
    let (doclens_header, signed_doclens) = read_npy_i64(&spec.doclens_i64_npy)?;
    if doclens_header.shape.len() != 1 {
        return Err(GemError::NonCanonicalFrame);
    }
    let token_rows =
        usize::try_from(embedding_header.shape[0]).map_err(|_| GemError::FrameTooLarge)?;
    if signed_codes.len() != token_rows {
        return Err(GemError::InvalidTokenCount);
    }
    let token_sum = signed_doclens.iter().try_fold(0usize, |total, &length| {
        let length = u16::try_from(length).map_err(|_| GemError::InvalidTokenCount)?;
        if length == 0 || length > spec.max_doc_tokens {
            return Err(GemError::InvalidTokenCount);
        }
        total
            .checked_add(usize::from(length))
            .ok_or(GemError::NumericOverflow)
    })?;
    if token_sum != token_rows {
        return Err(GemError::InvalidTokenCount);
    }

    let codes: Vec<u32> = signed_codes
        .into_iter()
        .map(|code| u32::try_from(code).map_err(|_| GemError::InvalidManifest))
        .collect::<Result<_>>()?;
    let dimension = usize::from(spec.dimension);
    let mut token_offset = 0usize;
    let mut documents = Vec::with_capacity(signed_doclens.len());
    let mut compact_codes = Vec::with_capacity(signed_doclens.len());
    for (offset, signed_length) in signed_doclens.into_iter().enumerate() {
        let token_count = u16::try_from(signed_length).map_err(|_| GemError::InvalidTokenCount)?;
        let next_token_offset = token_offset
            .checked_add(usize::from(token_count))
            .ok_or(GemError::NumericOverflow)?;
        let coordinate_start = token_offset
            .checked_mul(dimension)
            .ok_or(GemError::NumericOverflow)?;
        let coordinate_end = next_token_offset
            .checked_mul(dimension)
            .ok_or(GemError::NumericOverflow)?;
        let doc_id = spec
            .start_doc_id
            .checked_add(u32::try_from(offset).map_err(|_| GemError::NumericOverflow)?)
            .ok_or(GemError::NumericOverflow)?;
        documents.push(RawDocumentV3 {
            doc_id,
            token_count,
            dimension: spec.dimension,
            coordinate_bits: embedding_bits
                .get(coordinate_start..coordinate_end)
                .ok_or(GemError::InvalidFrameLength)?
                .to_vec(),
        });
        compact_codes.push(
            codes
                .get(token_offset..next_token_offset)
                .ok_or(GemError::InvalidFrameLength)?
                .to_vec(),
        );
        token_offset = next_token_offset;
    }
    let shard = ImportedDocumentShardV3 {
        dimension: spec.dimension,
        max_doc_tokens: spec.max_doc_tokens,
        start_doc_id: spec.start_doc_id,
        documents,
        compact_codes,
    };
    shard.validate()?;
    Ok(shard)
}

pub fn import_fine_centroids(path: impl AsRef<Path>, dimension: u16) -> Result<Vec<f32>> {
    let (header, bits) = read_npy_f16_bits(path)?;
    validate_matrix_shape(&header.shape, dimension)?;
    bits.into_iter().map(decode_f16).collect()
}

pub fn import_coarse_centroids(path: impl AsRef<Path>, dimension: u16) -> Result<Vec<f32>> {
    let (header, values) = read_npy_f32(path)?;
    validate_matrix_shape(&header.shape, dimension)?;
    Ok(values)
}

fn validate_matrix_shape(shape: &[u64], dimension: u16) -> Result<()> {
    if shape.len() != 2 || shape[0] == 0 || shape[1] != u64::from(dimension) {
        return Err(GemError::InvalidDimension {
            expected: usize::from(dimension),
            actual: shape
                .get(1)
                .copied()
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(0),
        });
    }
    Ok(())
}

pub fn import_queries(
    path: impl AsRef<Path>,
    dimension: u16,
    token_count: u16,
    params: SearchParamsV3,
) -> Result<Vec<QueryV3>> {
    params.validate()?;
    let (header, values) = read_npy_f32(path)?;
    if header.shape.len() != 3
        || header.shape[1] != u64::from(token_count)
        || header.shape[2] != u64::from(dimension)
    {
        return Err(GemError::InvalidDimension {
            expected: usize::from(dimension),
            actual: header
                .shape
                .get(2)
                .copied()
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(0),
        });
    }
    let query_count = usize::try_from(header.shape[0]).map_err(|_| GemError::FrameTooLarge)?;
    let query_size = usize::from(dimension)
        .checked_mul(usize::from(token_count))
        .ok_or(GemError::NumericOverflow)?;
    (0..query_count)
        .map(|query_id| {
            let start = query_id
                .checked_mul(query_size)
                .ok_or(GemError::NumericOverflow)?;
            let query = QueryV3 {
                query_id: u64::try_from(query_id).map_err(|_| GemError::NumericOverflow)?,
                dimension,
                token_count,
                coordinates: values
                    .get(start..start + query_size)
                    .ok_or(GemError::InvalidFrameLength)?
                    .to_vec(),
                params: params.clone(),
            };
            query.validate(dimension)?;
            Ok(query)
        })
        .collect()
}

pub fn import_compact_codes(
    code_dir: impl AsRef<Path>,
    doclens_dir: impl AsRef<Path>,
    fine_count: usize,
    max_doc_tokens: u16,
) -> Result<Vec<Vec<u32>>> {
    let code_dir = code_dir.as_ref();
    let doclens_dir = doclens_dir.as_ref();
    if fine_count == 0 || max_doc_tokens == 0 {
        return Err(GemError::InvalidManifest);
    }
    let mut compact_codes = Vec::new();
    for shard_id in discover_official_shard_ids_v3(code_dir, doclens_dir, None)? {
        let codes_path = code_dir.join(format!("doc_codes_{shard_id}.npy"));
        let doclens_path = doclens_dir.join(format!("doclens{shard_id}.npy"));
        let (code_header, signed_codes) = read_npy_i32(&codes_path)?;
        let (doclen_header, signed_doclens) = read_npy_i64(&doclens_path)?;
        if (code_header.shape.len() != 1
            && !(code_header.shape.len() == 2 && code_header.shape[1] == 1))
            || doclen_header.shape.len() != 1
        {
            return Err(GemError::NonCanonicalFrame);
        }
        let token_sum = signed_doclens.iter().try_fold(0usize, |sum, &length| {
            let length = u16::try_from(length).map_err(|_| GemError::InvalidTokenCount)?;
            if length == 0 || length > max_doc_tokens {
                return Err(GemError::InvalidTokenCount);
            }
            sum.checked_add(usize::from(length))
                .ok_or(GemError::NumericOverflow)
        })?;
        if token_sum != signed_codes.len() {
            return Err(GemError::InvalidTokenCount);
        }
        let codes: Vec<u32> = signed_codes
            .into_iter()
            .map(|code| {
                let code = u32::try_from(code).map_err(|_| GemError::InvalidManifest)?;
                if code as usize >= fine_count {
                    return Err(GemError::InvalidManifest);
                }
                Ok(code)
            })
            .collect::<Result<_>>()?;
        let mut offset = 0usize;
        for signed_length in signed_doclens {
            let length =
                usize::from(u16::try_from(signed_length).map_err(|_| GemError::InvalidTokenCount)?);
            compact_codes.push(
                codes
                    .get(offset..offset + length)
                    .ok_or(GemError::InvalidFrameLength)?
                    .to_vec(),
            );
            offset += length;
        }
    }
    Ok(compact_codes)
}
