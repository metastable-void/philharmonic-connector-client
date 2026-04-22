/// Errors returned when minting connector authorization tokens.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MintError {
    /// Input claims or key metadata violated local invariants.
    #[error("invalid minting input: {detail}")]
    InvalidInput { detail: String },

    /// Claim CBOR serialization failed.
    #[error("failed to serialize connector token claims: {detail}")]
    SerializationFailure { detail: String },

    /// Ed25519 signing failed.
    #[error("failed to sign COSE_Sign1 token: {detail}")]
    SigningFailure { detail: String },
}
