use thiserror::Error;

pub type Result<T> = std::result::Result<T, GemError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GemError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("invalid frame length")]
    InvalidFrameLength,
    #[error("frame exceeds configured maximum")]
    FrameTooLarge,
    #[error("trailing or non-canonical frame bytes")]
    NonCanonicalFrame,
    #[error("invalid dimension: expected {expected}, got {actual}")]
    InvalidDimension { expected: usize, actual: usize },
    #[error("invalid token count")]
    InvalidTokenCount,
    #[error("non-finite floating-point value")]
    NonFinite,
    #[error("qEMD transportation simplex did not converge within {0} pivots")]
    QemdNonConvergence(usize),
    #[error("invalid fixed-point scale")]
    InvalidScale,
    #[error("numeric overflow")]
    NumericOverflow,
    #[error("IDs or proof records are not in canonical order")]
    NonCanonicalOrder,
    #[error("duplicate ID or proof record")]
    DuplicateId,
    #[error("invalid Merkle proof")]
    InvalidMerkleProof,
    #[error("Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("hash mismatch")]
    HashMismatch,
    #[error("invalid matrix proof: {0}")]
    InvalidMatrixProof(String),
    #[error("invalid manifest")]
    InvalidManifest,
    #[error("invalid official shard layout: {0}")]
    InvalidShardLayout(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("I/O error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<std::io::Error> for GemError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
