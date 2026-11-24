use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{GemError, Result};

const NPY_MAGIC: &[u8; 6] = b"\x93NUMPY";
const MAX_HEADER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpyHeaderV3 {
    pub version_major: u8,
    pub version_minor: u8,
    pub descr: String,
    pub fortran_order: bool,
    pub shape: Vec<u64>,
    pub data_offset: u64,
    pub element_count: u64,
    pub word_size: u8,
    pub file_bytes: u64,
}

fn extract_quoted(header: &str, key: &str) -> Result<String> {
    let key_position = header.find(key).ok_or(GemError::NonCanonicalFrame)?;
    let remainder = &header[key_position + key.len()..];
    let colon = remainder.find(':').ok_or(GemError::NonCanonicalFrame)?;
    let value = remainder[colon + 1..].trim_start();
    let quote = value.chars().next().ok_or(GemError::NonCanonicalFrame)?;
    if quote != '\'' && quote != '"' {
        return Err(GemError::NonCanonicalFrame);
    }
    let end = value[1..].find(quote).ok_or(GemError::NonCanonicalFrame)?;
    Ok(value[1..1 + end].to_owned())
}

fn extract_bool(header: &str, key: &str) -> Result<bool> {
    let key_position = header.find(key).ok_or(GemError::NonCanonicalFrame)?;
    let remainder = &header[key_position + key.len()..];
    let colon = remainder.find(':').ok_or(GemError::NonCanonicalFrame)?;
    let value = remainder[colon + 1..].trim_start();
    if value.starts_with("False") {
        Ok(false)
    } else if value.starts_with("True") {
        Ok(true)
    } else {
        Err(GemError::NonCanonicalFrame)
    }
}

fn extract_shape(header: &str) -> Result<Vec<u64>> {
    let key_position = header.find("shape").ok_or(GemError::NonCanonicalFrame)?;
    let remainder = &header[key_position + "shape".len()..];
    let open = remainder.find('(').ok_or(GemError::NonCanonicalFrame)?;
    let close = remainder[open + 1..]
        .find(')')
        .ok_or(GemError::NonCanonicalFrame)?
        + open
        + 1;
    let body = &remainder[open + 1..close];
    let mut shape = Vec::new();
    for part in body.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        shape.push(
            trimmed
                .parse::<u64>()
                .map_err(|_| GemError::NonCanonicalFrame)?,
        );
    }
    if shape.is_empty() || shape.contains(&0) {
        return Err(GemError::InvalidDimension {
            expected: 1,
            actual: 0,
        });
    }
    Ok(shape)
}

fn descriptor_word_size(descr: &str) -> Result<u8> {
    if descr.starts_with('>') {
        return Err(GemError::NonCanonicalFrame);
    }
    if !descr.starts_with('<') && !descr.starts_with('|') && !descr.starts_with('=') {
        return Err(GemError::NonCanonicalFrame);
    }
    let digits_rev: String = descr
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    if digits_rev.is_empty() {
        return Err(GemError::NonCanonicalFrame);
    }
    let digits: String = digits_rev.chars().rev().collect();
    digits
        .parse::<u8>()
        .map_err(|_| GemError::NonCanonicalFrame)
}

pub fn inspect_npy(path: impl AsRef<Path>) -> Result<NpyHeaderV3> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let file_bytes = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    let mut prefix = [0u8; 8];
    reader.read_exact(&mut prefix)?;
    if &prefix[..6] != NPY_MAGIC {
        return Err(GemError::InvalidMagic);
    }
    let version_major = prefix[6];
    let version_minor = prefix[7];
    let header_len = match version_major {
        1 => {
            let mut bytes = [0u8; 2];
            reader.read_exact(&mut bytes)?;
            u16::from_le_bytes(bytes) as usize
        }
        2 | 3 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
            usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| GemError::FrameTooLarge)?
        }
        _ => return Err(GemError::UnsupportedVersion(u16::from(version_major))),
    };
    if header_len == 0 || header_len > MAX_HEADER_BYTES {
        return Err(GemError::FrameTooLarge);
    }
    let mut header_bytes = vec![0u8; header_len];
    reader.read_exact(&mut header_bytes)?;
    let header = std::str::from_utf8(&header_bytes).map_err(|_| GemError::NonCanonicalFrame)?;
    if !header.ends_with('\n') {
        return Err(GemError::NonCanonicalFrame);
    }
    let descr = extract_quoted(header, "descr")?;
    let fortran_order = extract_bool(header, "fortran_order")?;
    if fortran_order {
        return Err(GemError::NonCanonicalFrame);
    }
    let shape = extract_shape(header)?;
    let element_count = shape.iter().try_fold(1u64, |product, &value| {
        product.checked_mul(value).ok_or(GemError::NumericOverflow)
    })?;
    let word_size = descriptor_word_size(&descr)?;
    let data_offset = reader.stream_position()?;
    let data_bytes = element_count
        .checked_mul(u64::from(word_size))
        .ok_or(GemError::NumericOverflow)?;
    if data_offset
        .checked_add(data_bytes)
        .ok_or(GemError::NumericOverflow)?
        != file_bytes
    {
        return Err(GemError::InvalidFrameLength);
    }

    Ok(NpyHeaderV3 {
        version_major,
        version_minor,
        descr,
        fortran_order,
        shape,
        data_offset,
        element_count,
        word_size,
        file_bytes,
    })
}

fn read_data(path: &Path, expected_descr: &[&str]) -> Result<(NpyHeaderV3, Vec<u8>)> {
    let header = inspect_npy(path)?;
    if !expected_descr.contains(&header.descr.as_str()) {
        return Err(GemError::NonCanonicalFrame);
    }
    let data_len = usize::try_from(
        header
            .element_count
            .checked_mul(u64::from(header.word_size))
            .ok_or(GemError::NumericOverflow)?,
    )
    .map_err(|_| GemError::FrameTooLarge)?;
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(header.data_offset))?;
    let mut data = vec![0u8; data_len];
    file.read_exact(&mut data)?;
    Ok((header, data))
}

pub fn read_npy_f16_bits(path: impl AsRef<Path>) -> Result<(NpyHeaderV3, Vec<u16>)> {
    let (header, data) = read_data(path.as_ref(), &["<f2", "=f2"])?;
    let values = data
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect();
    Ok((header, values))
}

pub fn read_npy_f32(path: impl AsRef<Path>) -> Result<(NpyHeaderV3, Vec<f32>)> {
    let (header, data) = read_data(path.as_ref(), &["<f4", "=f4"])?;
    let mut values = Vec::with_capacity(data.len() / 4);
    for bytes in data.chunks_exact(4) {
        let value = f32::from_le_bytes(bytes.try_into().map_err(|_| GemError::InvalidFrameLength)?);
        if !value.is_finite() {
            return Err(GemError::NonFinite);
        }
        values.push(value);
    }
    Ok((header, values))
}

pub fn read_npy_i32(path: impl AsRef<Path>) -> Result<(NpyHeaderV3, Vec<i32>)> {
    let (header, data) = read_data(path.as_ref(), &["<i4", "=i4"])?;
    let values = data
        .chunks_exact(4)
        .map(|bytes| {
            Ok(i32::from_le_bytes(
                bytes.try_into().map_err(|_| GemError::InvalidFrameLength)?,
            ))
        })
        .collect::<Result<_>>()?;
    Ok((header, values))
}

pub fn read_npy_i64(path: impl AsRef<Path>) -> Result<(NpyHeaderV3, Vec<i64>)> {
    let (header, data) = read_data(path.as_ref(), &["<i8", "=i8"])?;
    let values = data
        .chunks_exact(8)
        .map(|bytes| {
            Ok(i64::from_le_bytes(
                bytes.try_into().map_err(|_| GemError::InvalidFrameLength)?,
            ))
        })
        .collect::<Result<_>>()?;
    Ok((header, values))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("gem-auth-{name}-{}", std::process::id()))
    }

    fn write_npy_format_1(path: &Path, descr: &str, shape: &str, data: &[u8]) {
        let mut header =
            format!("{{'descr': '{descr}', 'fortran_order': False, 'shape': ({shape}), }}");
        let prefix_len = 10usize;
        let padding = (64 - ((prefix_len + header.len() + 1) % 64)) % 64;
        header.push_str(&" ".repeat(padding));
        header.push('\n');
        let mut bytes = Vec::new();
        bytes.extend_from_slice(NPY_MAGIC);
        bytes.extend_from_slice(&[1, 0]);
        bytes.extend_from_slice(&(header.len() as u16).to_le_bytes());
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(data);
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn parses_npy_format_1_f32_and_rejects_tail() {
        let path = temp_path("npy-f32");
        let data: Vec<u8> = [1.0f32, -2.0]
            .into_iter()
            .flat_map(f32::to_le_bytes)
            .collect();
        write_npy_format_1(&path, "<f4", "2,", &data);
        let (header, values) = read_npy_f32(&path).unwrap();
        assert_eq!(header.shape, vec![2]);
        assert_eq!(values, vec![1.0, -2.0]);
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(0);
        fs::write(&path, bytes).unwrap();
        assert_eq!(inspect_npy(&path), Err(GemError::InvalidFrameLength));
        fs::remove_file(path).unwrap();
    }
}
