use std::boxed::Box;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use coset::{CoseEncrypt0Builder, Header, HeaderBuilder, cbor::value::Value, iana};
use hkdf::Hkdf;
use ml_kem::kem::Encapsulate;
use ml_kem::{B32, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::Serialize;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::EncryptError;
use philharmonic_connector_common::{ConnectorEncryptedPayload, RealmPublicKey, Uuid};
use philharmonic_types::Sha256;

const EXTERNAL_AAD_DIGEST_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"philharmonic/wave-b/hybrid-kem/v1/aead-key";
const KEM_SS_LEN: usize = 32;
const ECDH_SS_LEN: usize = 32;
const HKDF_IKM_LEN: usize = KEM_SS_LEN + ECDH_SS_LEN;
const AEAD_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const ECDH_EPH_PK_LEN: usize = 32;

struct EncryptMaterials<'a> {
    realm_kid: &'a str,
    kem_ct: ml_kem::Ciphertext<MlKem768>,
    kem_ss: Zeroizing<[u8; KEM_SS_LEN]>,
    ecdh_ss: Zeroizing<[u8; ECDH_SS_LEN]>,
    ecdh_eph_pk: [u8; ECDH_EPH_PK_LEN],
    nonce: [u8; NONCE_LEN],
    external_aad: [u8; EXTERNAL_AAD_DIGEST_LEN],
}

#[derive(Clone, Copy, Debug)]
/// Claim-derived values bound into Wave B AEAD associated data.
pub struct AeadAadInputs<'a> {
    /// Destination connector realm.
    pub realm: &'a str,
    /// Tenant UUID.
    pub tenant: Uuid,
    /// Workflow instance UUID.
    pub inst: Uuid,
    /// Workflow step sequence number.
    pub step: u64,
    /// Tenant endpoint-config UUID.
    pub config_uuid: Uuid,
    /// Wave A lowerer signing key identifier (`claims.kid`).
    pub kid: &'a str,
}

#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
/// Explicit deterministic inputs used by Wave B vector tests.
pub struct EncryptTestInputs {
    /// ML-KEM deterministic encapsulation randomness (`m`).
    pub mlkem_encapsulation_m: [u8; 32],
    /// X25519 deterministic ephemeral private key bytes.
    pub x25519_eph_private: [u8; 32],
    /// AES-256-GCM nonce bytes.
    pub nonce: [u8; NONCE_LEN],
}

/// Encrypt connector payload bytes as a COSE_Encrypt0 envelope.
pub fn encrypt_payload(
    plaintext: &[u8],
    realm_key: &RealmPublicKey,
    aad_inputs: AeadAadInputs<'_>,
    rng: &mut impl CryptoRngCore,
) -> Result<ConnectorEncryptedPayload, EncryptError> {
    if plaintext.is_empty() {
        return Err(EncryptError::InvalidInput {
            detail: "plaintext must not be empty".to_owned(),
        });
    }

    if realm_key.kid.is_empty() || realm_key.kid.len() > u8::MAX as usize {
        return Err(EncryptError::InvalidInput {
            detail: format!(
                "realm key kid length must be 1..={} bytes",
                u8::MAX as usize
            ),
        });
    }

    let ek = parse_mlkem_encapsulation_key(realm_key)?;
    let (kem_ct, kem_ss) =
        ek.encapsulate(rng)
            .map_err(|_| EncryptError::KemEncapsulationFailure {
                detail: "ML-KEM-768 encapsulation failed".to_owned(),
            })?;

    let eph_secret = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_public = PublicKey::from(&eph_secret);
    let realm_x25519_pk = PublicKey::from(realm_key.x25519_public);
    let ecdh_ss = Zeroizing::new(eph_secret.diffie_hellman(&realm_x25519_pk).to_bytes());

    let mut nonce = [0_u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let materials = EncryptMaterials {
        realm_kid: &realm_key.kid,
        kem_ct,
        kem_ss: Zeroizing::new(kem_ss.into()),
        ecdh_ss,
        ecdh_eph_pk: eph_public.to_bytes(),
        nonce,
        external_aad: compute_external_aad_digest(aad_inputs)?,
    };

    let encrypt0 = build_encrypt0(plaintext, materials)?;
    Ok(ConnectorEncryptedPayload::new(encrypt0))
}

#[doc(hidden)]
/// Deterministic encrypt path used by committed vector tests.
pub fn encrypt_payload_with_test_inputs(
    plaintext: &[u8],
    realm_key: &RealmPublicKey,
    aad_inputs: AeadAadInputs<'_>,
    test_inputs: EncryptTestInputs,
) -> Result<ConnectorEncryptedPayload, EncryptError> {
    if plaintext.is_empty() {
        return Err(EncryptError::InvalidInput {
            detail: "plaintext must not be empty".to_owned(),
        });
    }

    if realm_key.kid.is_empty() || realm_key.kid.len() > u8::MAX as usize {
        return Err(EncryptError::InvalidInput {
            detail: format!(
                "realm key kid length must be 1..={} bytes",
                u8::MAX as usize
            ),
        });
    }

    let ek = parse_mlkem_encapsulation_key(realm_key)?;
    let encaps_m = B32::from(test_inputs.mlkem_encapsulation_m);
    let (kem_ct, kem_ss) = ek.encapsulate_deterministic(&encaps_m).map_err(|_| {
        EncryptError::KemEncapsulationFailure {
            detail: "ML-KEM-768 deterministic encapsulation failed".to_owned(),
        }
    })?;

    // Deterministic vector reproduction path: explicit private bytes are required.
    let eph_secret = StaticSecret::from(test_inputs.x25519_eph_private);
    let eph_public = PublicKey::from(&eph_secret);
    let realm_x25519_pk = PublicKey::from(realm_key.x25519_public);
    let ecdh_ss = Zeroizing::new(eph_secret.diffie_hellman(&realm_x25519_pk).to_bytes());

    let materials = EncryptMaterials {
        realm_kid: &realm_key.kid,
        kem_ct,
        kem_ss: Zeroizing::new(kem_ss.into()),
        ecdh_ss,
        ecdh_eph_pk: eph_public.to_bytes(),
        nonce: test_inputs.nonce,
        external_aad: compute_external_aad_digest(aad_inputs)?,
    };

    let encrypt0 = build_encrypt0(plaintext, materials)?;
    Ok(ConnectorEncryptedPayload::new(encrypt0))
}

fn build_encrypt0(
    plaintext: &[u8],
    materials: EncryptMaterials<'_>,
) -> Result<coset::CoseEncrypt0, EncryptError> {
    let mut ikm = Zeroizing::new([0_u8; HKDF_IKM_LEN]);
    ikm[..KEM_SS_LEN].copy_from_slice(&materials.kem_ss[..]);
    ikm[KEM_SS_LEN..].copy_from_slice(&materials.ecdh_ss[..]);

    let (_, hkdf) = Hkdf::<sha2::Sha256>::extract(Some(b""), &ikm[..]);

    let mut aead_key_bytes = [0_u8; AEAD_KEY_LEN];
    hkdf.expand(HKDF_INFO, &mut aead_key_bytes)
        .map_err(|_| EncryptError::HkdfFailure {
            detail: "HKDF-Expand for AEAD key failed".to_owned(),
        })?;

    let aead_key = SecretBox::new(Box::new(aead_key_bytes));
    aead_key_bytes.zeroize();

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::A256GCM)
        .key_id(materials.realm_kid.as_bytes().to_vec())
        .iv(materials.nonce.to_vec())
        .text_value("kem_ct".to_owned(), Value::Bytes(materials.kem_ct.to_vec()))
        .text_value(
            "ecdh_eph_pk".to_owned(),
            Value::Bytes(materials.ecdh_eph_pk.to_vec()),
        )
        .build();

    CoseEncrypt0Builder::new()
        .protected(protected)
        .unprotected(Header::default())
        .try_create_ciphertext(plaintext, &materials.external_aad, |msg, aad| {
            encrypt_aes_gcm(msg, aad, materials.nonce, &aead_key)
        })
        .map(coset::CoseEncrypt0Builder::build)
}

fn parse_mlkem_encapsulation_key(
    realm_key: &RealmPublicKey,
) -> Result<<MlKem768 as KemCore>::EncapsulationKey, EncryptError> {
    realm_key
        .validate()
        .map_err(|err| EncryptError::MalformedRealmKey {
            detail: err.to_string(),
        })?;

    type MlKemEncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;

    let encoded: Encoded<MlKemEncapsulationKey> =
        realm_key.mlkem_public.as_slice().try_into().map_err(|_| {
            EncryptError::MalformedRealmKey {
                detail: "ML-KEM-768 public key bytes have invalid length".to_owned(),
            }
        })?;

    Ok(MlKemEncapsulationKey::from_bytes(&encoded))
}

fn encrypt_aes_gcm(
    plaintext: &[u8],
    aad: &[u8],
    nonce: [u8; NONCE_LEN],
    aead_key: &SecretBox<[u8; AEAD_KEY_LEN]>,
) -> Result<Vec<u8>, EncryptError> {
    // The AEAD API requires an unwrapped key reference at call time.
    let cipher = Aes256Gcm::new_from_slice(aead_key.expose_secret()).map_err(|_| {
        EncryptError::AeadEncryptionFailure {
            detail: "AES-256-GCM key length was not 32 bytes".to_owned(),
        }
    })?;

    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| EncryptError::AeadEncryptionFailure {
            detail: "AES-256-GCM encryption failed".to_owned(),
        })
}

#[derive(Serialize)]
struct ExternalAadCbor<'a> {
    realm: &'a str,
    tenant: Uuid,
    inst: Uuid,
    step: u64,
    config_uuid: Uuid,
    kid: &'a str,
}

fn compute_external_aad_digest(
    aad_inputs: AeadAadInputs<'_>,
) -> Result<[u8; EXTERNAL_AAD_DIGEST_LEN], EncryptError> {
    if aad_inputs.realm.is_empty() {
        return Err(EncryptError::InvalidInput {
            detail: "AAD realm must not be empty".to_owned(),
        });
    }

    if aad_inputs.kid.is_empty() {
        return Err(EncryptError::InvalidInput {
            detail: "AAD kid must not be empty".to_owned(),
        });
    }

    let cbor_payload = ExternalAadCbor {
        realm: aad_inputs.realm,
        tenant: aad_inputs.tenant,
        inst: aad_inputs.inst,
        step: aad_inputs.step,
        config_uuid: aad_inputs.config_uuid,
        kid: aad_inputs.kid,
    };

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&cbor_payload, &mut encoded).map_err(|err| {
        EncryptError::SerializationFailure {
            detail: err.to_string(),
        }
    })?;

    Ok(*Sha256::of(&encoded).as_bytes())
}
