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

/// Errors returned when encrypting connector payload bytes.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum EncryptError {
    /// Input payload, AAD inputs, or key metadata violated local invariants.
    #[error("invalid encryption input: {detail}")]
    InvalidInput { detail: String },

    /// CBOR/COSE serialization failed.
    #[error("failed to serialize encryption data: {detail}")]
    SerializationFailure { detail: String },

    /// Hybrid-KEM encapsulation failed.
    #[error("failed to encapsulate hybrid KEM shared secret: {detail}")]
    KemEncapsulationFailure { detail: String },

    /// HKDF key derivation failed.
    #[error("failed to derive AEAD key with HKDF: {detail}")]
    HkdfFailure { detail: String },

    /// AES-256-GCM encryption failed.
    #[error("failed to encrypt payload with AEAD: {detail}")]
    AeadEncryptionFailure { detail: String },

    /// Realm public-key material was malformed.
    #[error("malformed realm public key: {detail}")]
    MalformedRealmKey { detail: String },
}
