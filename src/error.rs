/// Errors returned when minting connector authorization tokens.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MintError {
    /// Input claims or key metadata violated local invariants.
    #[error("invalid minting input: {detail}")]
    InvalidInput {
        /// Human-readable description of the input problem.
        detail: String,
    },

    /// Claim CBOR serialization failed.
    #[error("failed to serialize connector token claims: {detail}")]
    SerializationFailure {
        /// Human-readable description of the serialization failure.
        detail: String,
    },

    /// Ed25519 signing failed.
    #[error("failed to sign COSE_Sign1 token: {detail}")]
    SigningFailure {
        /// Human-readable description of the signing failure.
        detail: String,
    },
}

/// Errors returned when encrypting connector payload bytes.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum EncryptError {
    /// Input payload, AAD inputs, or key metadata violated local invariants.
    #[error("invalid encryption input: {detail}")]
    InvalidInput {
        /// Human-readable description of the input problem.
        detail: String,
    },

    /// CBOR/COSE serialization failed.
    #[error("failed to serialize encryption data: {detail}")]
    SerializationFailure {
        /// Human-readable description of the serialization failure.
        detail: String,
    },

    /// Hybrid-KEM encapsulation failed.
    #[error("failed to encapsulate hybrid KEM shared secret: {detail}")]
    KemEncapsulationFailure {
        /// Human-readable description of the encapsulation failure.
        detail: String,
    },

    /// HKDF key derivation failed.
    #[error("failed to derive AEAD key with HKDF: {detail}")]
    HkdfFailure {
        /// Human-readable description of the derivation failure.
        detail: String,
    },

    /// AES-256-GCM encryption failed.
    #[error("failed to encrypt payload with AEAD: {detail}")]
    AeadEncryptionFailure {
        /// Human-readable description of the encryption failure.
        detail: String,
    },

    /// Realm public-key material was malformed.
    #[error("malformed realm public key: {detail}")]
    MalformedRealmKey {
        /// Human-readable description of the key problem.
        detail: String,
    },
}
