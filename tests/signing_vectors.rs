use coset::{CborSerializable, CoseSign1};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use philharmonic_connector_client::{
    ConnectorTokenClaims, LowererSigningKey, MintError, Sha256, UnixMillis, Uuid, Zeroizing,
};

const SEED_HEX: &str = include_str!("../../docs/crypto-vectors/wave-a/wave_a_seed.hex");
const PUBLIC_HEX: &str = include_str!("../../docs/crypto-vectors/wave-a/wave_a_public.hex");
const PAYLOAD_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-a/wave_a_payload_plaintext.hex");
const PAYLOAD_HASH_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-a/wave_a_payload_hash.hex");
const CLAIMS_CBOR_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-a/wave_a_claims.cbor.hex");
const PROTECTED_HEX: &str = include_str!("../../docs/crypto-vectors/wave-a/wave_a_protected.hex");
const SIG_STRUCTURE1_HEX: &str =
    include_str!("../../docs/crypto-vectors/wave-a/wave_a_sig_structure1.hex");
const SIGNATURE_HEX: &str = include_str!("../../docs/crypto-vectors/wave-a/wave_a_signature.hex");
const COSE_SIGN1_HEX: &str = include_str!("../../docs/crypto-vectors/wave-a/wave_a_cose_sign1.hex");

fn decode_hex_file(input: &str) -> Vec<u8> {
    hex::decode(input.trim()).expect("vector hex must decode")
}

fn sample_claims() -> ConnectorTokenClaims {
    ConnectorTokenClaims {
        iss: "lowerer.main".to_owned(),
        exp: UnixMillis(1_924_992_000_000),
        iat: UnixMillis(1_924_991_880_000),
        kid: "lowerer.main-2026-04-22-3c8a91d0".to_owned(),
        realm: "llm".to_owned(),
        tenant: Uuid::parse_str("11111111-2222-4333-8444-555555555555")
            .expect("test UUID must be valid"),
        inst: Uuid::parse_str("66666666-7777-4888-8999-aaaaaaaaaaaa")
            .expect("test UUID must be valid"),
        step: 7,
        config_uuid: Uuid::parse_str("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff")
            .expect("test UUID must be valid"),
        payload_hash: Sha256::of(&decode_hex_file(PAYLOAD_HEX)),
    }
}

fn seed_bytes() -> [u8; 32] {
    decode_hex_file(SEED_HEX)
        .try_into()
        .expect("seed vector must be 32 bytes")
}

fn public_bytes() -> [u8; 32] {
    decode_hex_file(PUBLIC_HEX)
        .try_into()
        .expect("public-key vector must be 32 bytes")
}

#[test]
fn mint_token_matches_committed_wave_a_vectors() {
    let claims = sample_claims();

    let mut claims_cbor = Vec::new();
    ciborium::ser::into_writer(&claims, &mut claims_cbor)
        .expect("claim serialization should succeed in test fixture");
    assert_eq!(claims_cbor, decode_hex_file(CLAIMS_CBOR_HEX));

    assert_eq!(claims.payload_hash.as_bytes(), &public_payload_hash());

    let key = LowererSigningKey::from_seed(Zeroizing::new(seed_bytes()), claims.kid.clone());
    let token = key
        .mint_token(&claims)
        .expect("minting should succeed for known-answer vector");

    let sign1 = token.into_inner();
    let encoded = sign1
        .clone()
        .to_vec()
        .expect("COSE_Sign1 encoding should succeed");
    assert_eq!(encoded, decode_hex_file(COSE_SIGN1_HEX));

    assert_eq!(sign1.payload.as_deref(), Some(claims_cbor.as_slice()));
    assert_eq!(
        sign1
            .protected
            .clone()
            .to_vec()
            .expect("protected header encoding should succeed"),
        decode_hex_file(PROTECTED_HEX)
    );
    assert_eq!(sign1.tbs_data(b""), decode_hex_file(SIG_STRUCTURE1_HEX));
    assert_eq!(sign1.signature, decode_hex_file(SIGNATURE_HEX));

    let verifying_key =
        VerifyingKey::from_bytes(&public_bytes()).expect("public-key vector must decode");
    let signature =
        Signature::try_from(sign1.signature.as_slice()).expect("vector signature must decode");
    verifying_key
        .verify(&sign1.tbs_data(b""), &signature)
        .expect("vector signature must verify");

    let round_trip = CoseSign1::from_slice(&encoded).expect("token should parse back");
    assert_eq!(round_trip.payload.as_deref(), Some(claims_cbor.as_slice()));
    assert_eq!(round_trip.signature, sign1.signature);
    assert_eq!(
        round_trip
            .to_vec()
            .expect("round-trip token encoding should succeed"),
        encoded
    );
}

#[test]
fn mint_token_rejects_claim_key_id_mismatch() {
    let claims = sample_claims();
    let key = LowererSigningKey::from_seed(Zeroizing::new(seed_bytes()), "kid.other".to_owned());

    let err = key
        .mint_token(&claims)
        .expect_err("minting should fail when kid does not match claims");

    assert!(matches!(err, MintError::InvalidInput { .. }));
}

fn public_payload_hash() -> [u8; 32] {
    decode_hex_file(PAYLOAD_HASH_HEX)
        .try_into()
        .expect("payload-hash vector must be 32 bytes")
}
