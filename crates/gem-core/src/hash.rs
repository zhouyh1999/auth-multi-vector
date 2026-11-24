use std::{fs::File, io::Read, path::Path};

use sha2::{Digest, Sha256};

use crate::Result;

pub type Hash = [u8; 32];

/// Plain SHA-256 of bytes, with the same meaning as `sha256sum` and `sha256_file`.
/// Protocol commitments continue to use the domain-separated `hash_bytes`.
pub fn sha256_bytes(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

pub fn hash_bytes(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<Hash> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_and_length_are_bound() {
        assert_ne!(hash_bytes(b"a", b"bc"), hash_bytes(b"ab", b"c"));
        assert_eq!(hash_bytes(b"v3", b"payload"), hash_bytes(b"v3", b"payload"));
    }

    #[test]
    fn plain_sha256_matches_standard_vector_and_is_not_a_protocol_digest() {
        assert_eq!(
            sha256_bytes(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_ne!(
            sha256_bytes(b"abc"),
            hash_bytes(b"gem.scheme.vo.file", b"abc")
        );
    }
}

/// The exact legacy domain-separated bincode digest, without a corpus-sized
/// temporary byte Vec. Buffering keeps per-coordinate serialization inexpensive.
pub fn hash_serialized<T: serde::Serialize + ?Sized>(domain: &[u8], value: &T) -> Result<Hash> {
    use std::io::{BufWriter, Write};
    struct HashWriter(Sha256);
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let size = bincode::serialized_size(value)
        .map_err(|e| crate::GemError::Serialization(e.to_string()))?;
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update(size.to_le_bytes());
    let mut writer = BufWriter::with_capacity(1024 * 1024, HashWriter(h));
    bincode::serialize_into(&mut writer, value)
        .map_err(|e| crate::GemError::Serialization(e.to_string()))?;
    writer.flush()?;
    let writer = writer.into_inner().map_err(|e| e.into_error())?;
    Ok(writer.0.finalize().into())
}
