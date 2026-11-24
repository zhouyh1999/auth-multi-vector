use bincode::Options;
use serde::{Serialize, de::DeserializeOwned};

use crate::{GemError, Result};

const HEADER_BYTES: usize = 18;

// V3 profiles retain the already-published revision-2 outer frame.
// Semantic protocol version 3 and profile IDs live inside the payload and are
// validated after decoding. This is what lets superseded V3 payloads decode
// but fail closed at semantic validation.
const V3_OUTER_FRAME_VERSION: u16 = 2;

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}

pub fn encode_frame_v3<T: Serialize>(magic: [u8; 8], value: &T) -> Result<Vec<u8>> {
    let payload = options()
        .serialize(value)
        .map_err(|error| GemError::Serialization(error.to_string()))?;
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(&magic);
    frame.extend_from_slice(&V3_OUTER_FRAME_VERSION.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_frame_v3<T: DeserializeOwned>(
    expected_magic: [u8; 8],
    frame: &[u8],
    max_payload_bytes: u64,
) -> Result<T> {
    if frame.len() < HEADER_BYTES {
        return Err(GemError::InvalidFrameLength);
    }
    if frame[..8] != expected_magic {
        return Err(GemError::InvalidMagic);
    }
    let version = u16::from_le_bytes([frame[8], frame[9]]);
    if version != V3_OUTER_FRAME_VERSION {
        return Err(GemError::UnsupportedVersion(version));
    }
    let payload_len = u64::from_le_bytes(
        frame[10..18]
            .try_into()
            .map_err(|_| GemError::InvalidFrameLength)?,
    );
    if payload_len > max_payload_bytes {
        return Err(GemError::FrameTooLarge);
    }
    let payload_len = usize::try_from(payload_len).map_err(|_| GemError::FrameTooLarge)?;
    let expected_len = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(GemError::InvalidFrameLength)?;
    if frame.len() != expected_len {
        return Err(GemError::InvalidFrameLength);
    }
    options()
        .with_limit(max_payload_bytes)
        .deserialize(&frame[HEADER_BYTES..])
        .map_err(|error| GemError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_frame_roundtrips_and_rejects_noncanonical_lengths() {
        let value = vec![7u32, 11, 13];
        let frame = encode_frame_v3(*b"GEMTSTV3", &value).unwrap();
        assert_eq!(u16::from_le_bytes(frame[8..10].try_into().unwrap()), 2);
        let decoded: Vec<u32> = decode_frame_v3(*b"GEMTSTV3", &frame, 1024).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(encode_frame_v3(*b"GEMTSTV3", &decoded).unwrap(), frame);

        let mut tailed = frame;
        tailed.push(0);
        assert_eq!(
            decode_frame_v3::<Vec<u32>>(*b"GEMTSTV3", &tailed, 1024),
            Err(GemError::InvalidFrameLength)
        );
    }
}
