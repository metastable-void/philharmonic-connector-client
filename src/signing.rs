use coset::{CoseSign1Builder, HeaderBuilder, iana};
use ed25519_dalek::{Signer, SigningKey};
use philharmonic_connector_common::{ConnectorSignedToken, ConnectorTokenClaims};
use zeroize::Zeroizing;

use crate::MintError;

/// Ed25519 signing material used to mint connector authorization tokens.
#[derive(Clone, Debug)]
pub struct LowererSigningKey {
    seed: Zeroizing<[u8; 32]>,
    kid: String,
}

impl LowererSigningKey {
    /// Construct a lowerer signing key from a 32-byte Ed25519 seed and key identifier.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>, kid: String) -> Self {
        Self { seed, kid }
    }

    /// Return the configured key identifier.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Mint a signed COSE_Sign1 token for connector authorization claims.
    pub fn mint_token(
        &self,
        claims: &ConnectorTokenClaims,
    ) -> Result<ConnectorSignedToken, MintError> {
        if claims.kid != self.kid {
            return Err(MintError::InvalidInput {
                detail: format!(
                    "claims.kid '{}' does not match signing key kid '{}'",
                    claims.kid, self.kid
                ),
            });
        }

        let payload = serialize_claims(claims)?;
        let signing_key = SigningKey::from_bytes(&self.seed);

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(claims.kid.as_bytes().to_vec())
            .build();

        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .try_create_signature(b"", |sig_structure| {
                signing_key
                    .try_sign(sig_structure)
                    .map(|signature| signature.to_bytes().to_vec())
                    .map_err(|err| MintError::SigningFailure {
                        detail: err.to_string(),
                    })
            })?
            .build();

        Ok(ConnectorSignedToken::new(sign1))
    }
}

fn serialize_claims(claims: &ConnectorTokenClaims) -> Result<Vec<u8>, MintError> {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(claims, &mut payload).map_err(|err| {
        MintError::SerializationFailure {
            detail: err.to_string(),
        }
    })?;
    Ok(payload)
}
