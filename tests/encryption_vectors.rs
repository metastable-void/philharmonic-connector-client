use coset::{CborSerializable, EncryptionContext, enc_structure_data};
use hkdf::Hkdf;
use ml_kem::kem::Decapsulate;
use ml_kem::{B32, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768};
use philharmonic_connector_client::{
    AeadAadInputs, EncryptTestInputs, Sha256, UnixMillis, Uuid, encrypt_payload_with_test_inputs,
};
use philharmonic_connector_common::{RealmId, RealmPublicKey};
use serde::Serialize;
use x25519_dalek::{PublicKey, StaticSecret};

const WAVE_B_MLKEM_KEYGEN_D_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_keygen_d.hex");
const WAVE_B_MLKEM_KEYGEN_Z_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_keygen_z.hex");
const WAVE_B_MLKEM_ENCAPS_M_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_encaps_m.hex");
const WAVE_B_MLKEM_PUBLIC_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_public.hex");
const WAVE_B_MLKEM_SECRET_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_secret.hex");
const WAVE_B_MLKEM_CT_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_ct.hex");
const WAVE_B_MLKEM_SS_HEX: &str = include_str!("vectors/wave-b/wave_b_mlkem_ss.hex");
const WAVE_B_X25519_REALM_SK_HEX: &str = include_str!("vectors/wave-b/wave_b_x25519_realm_sk.hex");
const WAVE_B_X25519_REALM_PK_HEX: &str = include_str!("vectors/wave-b/wave_b_x25519_realm_pk.hex");
const WAVE_B_X25519_EPH_SK_HEX: &str = include_str!("vectors/wave-b/wave_b_x25519_eph_sk.hex");
const WAVE_B_X25519_EPH_PK_HEX: &str = include_str!("vectors/wave-b/wave_b_x25519_eph_pk.hex");
const WAVE_B_ECDH_SS_HEX: &str = include_str!("vectors/wave-b/wave_b_ecdh_ss.hex");
const WAVE_B_HKDF_IKM_HEX: &str = include_str!("vectors/wave-b/wave_b_hkdf_ikm.hex");
const WAVE_B_AEAD_KEY_HEX: &str = include_str!("vectors/wave-b/wave_b_aead_key.hex");
const WAVE_B_EXTERNAL_AAD_HEX: &str = include_str!("vectors/wave-b/wave_b_external_aad.hex");
const WAVE_B_NONCE_HEX: &str = include_str!("vectors/wave-b/wave_b_nonce.hex");
const WAVE_B_PLAINTEXT_HEX: &str = include_str!("vectors/wave-b/wave_b_plaintext.hex");
const WAVE_B_PROTECTED_HEX: &str = include_str!("vectors/wave-b/wave_b_protected.hex");
const WAVE_B_ENC_STRUCTURE_HEX: &str = include_str!("vectors/wave-b/wave_b_enc_structure.hex");
const WAVE_B_CIPHERTEXT_AND_TAG_HEX: &str =
    include_str!("vectors/wave-b/wave_b_ciphertext_and_tag.hex");
const WAVE_B_COSE_ENCRYPT0_HEX: &str = include_str!("vectors/wave-b/wave_b_cose_encrypt0.hex");
const WAVE_B_PAYLOAD_HASH_HEX: &str = include_str!("vectors/wave-b/wave_b_payload_hash.hex");

fn decode_hex_file(input: &str) -> Vec<u8> {
    hex::decode(input.trim()).expect("vector hex must decode")
}

fn bytes_32(input: &str) -> [u8; 32] {
    decode_hex_file(input)
        .try_into()
        .expect("vector must decode to 32 bytes")
}

fn bytes_12(input: &str) -> [u8; 12] {
    decode_hex_file(input)
        .try_into()
        .expect("vector must decode to 12 bytes")
}

fn aad_inputs() -> AeadAadInputs<'static> {
    AeadAadInputs {
        realm: "llm",
        tenant: Uuid::parse_str("11111111-2222-4333-8444-555555555555")
            .expect("test UUID must be valid"),
        inst: Uuid::parse_str("66666666-7777-4888-8999-aaaaaaaaaaaa")
            .expect("test UUID must be valid"),
        step: 7,
        config_uuid: Uuid::parse_str("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff")
            .expect("test UUID must be valid"),
        kid: "lowerer.main-2026-04-22-3c8a91d0",
    }
}

fn realm_key() -> RealmPublicKey {
    RealmPublicKey::new(
        "llm.default-2026-04-22-realmkey0",
        RealmId::new("llm"),
        decode_hex_file(WAVE_B_MLKEM_PUBLIC_HEX),
        bytes_32(WAVE_B_X25519_REALM_PK_HEX),
        UnixMillis(1_700_000_000_000),
        UnixMillis(1_950_000_000_000),
    )
    .expect("vector realm key must be valid")
}

#[derive(Serialize)]
struct ExternalAadMap {
    realm: &'static str,
    tenant: Uuid,
    inst: Uuid,
    step: u64,
    config_uuid: Uuid,
    kid: &'static str,
}

#[test]
fn wave_b_known_answer_vectors_match_committed_bytes() {
    type MlKemDecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;
    type MlKemEncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;

    let d = B32::from(bytes_32(WAVE_B_MLKEM_KEYGEN_D_HEX));
    let z = B32::from(bytes_32(WAVE_B_MLKEM_KEYGEN_Z_HEX));
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);

    assert_eq!(
        ek.as_bytes().to_vec(),
        decode_hex_file(WAVE_B_MLKEM_PUBLIC_HEX)
    );
    assert_eq!(
        dk.as_bytes().to_vec(),
        decode_hex_file(WAVE_B_MLKEM_SECRET_HEX)
    );

    let ek_encoded: Encoded<MlKemEncapsulationKey> = decode_hex_file(WAVE_B_MLKEM_PUBLIC_HEX)
        .as_slice()
        .try_into()
        .expect("vector ek bytes must match encoded length");
    let ek_from_vector = MlKemEncapsulationKey::from_bytes(&ek_encoded);

    let m = B32::from(bytes_32(WAVE_B_MLKEM_ENCAPS_M_HEX));
    let (kem_ct, kem_ss) = ek_from_vector
        .encapsulate_deterministic(&m)
        .expect("deterministic encapsulation must succeed for test vector");

    assert_eq!(kem_ct.to_vec(), decode_hex_file(WAVE_B_MLKEM_CT_HEX));
    assert_eq!(kem_ss.to_vec(), decode_hex_file(WAVE_B_MLKEM_SS_HEX));

    let dk_encoded: Encoded<MlKemDecapsulationKey> = decode_hex_file(WAVE_B_MLKEM_SECRET_HEX)
        .as_slice()
        .try_into()
        .expect("vector dk bytes must match encoded length");
    let dk_from_vector = MlKemDecapsulationKey::from_bytes(&dk_encoded);
    let kem_ss_roundtrip = dk_from_vector
        .decapsulate(&kem_ct)
        .expect("decapsulation must succeed for test vector");
    assert_eq!(
        kem_ss_roundtrip.to_vec(),
        decode_hex_file(WAVE_B_MLKEM_SS_HEX)
    );

    let realm_sk = StaticSecret::from(bytes_32(WAVE_B_X25519_REALM_SK_HEX));
    let realm_pk = PublicKey::from(&realm_sk);
    assert_eq!(realm_pk.to_bytes(), bytes_32(WAVE_B_X25519_REALM_PK_HEX));

    let eph_sk = StaticSecret::from(bytes_32(WAVE_B_X25519_EPH_SK_HEX));
    let eph_pk = PublicKey::from(&eph_sk);
    assert_eq!(eph_pk.to_bytes(), bytes_32(WAVE_B_X25519_EPH_PK_HEX));

    let ecdh_ss = realm_sk.diffie_hellman(&eph_pk).to_bytes();
    assert_eq!(ecdh_ss, bytes_32(WAVE_B_ECDH_SS_HEX));

    let mut hkdf_ikm = Vec::new();
    hkdf_ikm.extend_from_slice(kem_ss.as_ref());
    hkdf_ikm.extend_from_slice(&ecdh_ss);
    assert_eq!(hkdf_ikm, decode_hex_file(WAVE_B_HKDF_IKM_HEX));

    let hkdf = Hkdf::<sha2::Sha256>::new(Some(b""), &hkdf_ikm);
    let mut aead_key = [0_u8; 32];
    hkdf.expand(b"philharmonic/wave-b/hybrid-kem/v1/aead-key", &mut aead_key)
        .expect("HKDF expand for test vector should succeed");
    assert_eq!(aead_key, bytes_32(WAVE_B_AEAD_KEY_HEX));

    let aad_inputs = aad_inputs();
    let aad_cbor = ExternalAadMap {
        realm: aad_inputs.realm,
        tenant: aad_inputs.tenant,
        inst: aad_inputs.inst,
        step: aad_inputs.step,
        config_uuid: aad_inputs.config_uuid,
        kid: aad_inputs.kid,
    };
    let mut aad_cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&aad_cbor, &mut aad_cbor_bytes)
        .expect("AAD CBOR encoding should succeed for test vector");
    let external_aad = Sha256::of(&aad_cbor_bytes);
    assert_eq!(external_aad.as_bytes(), &bytes_32(WAVE_B_EXTERNAL_AAD_HEX));

    let payload = encrypt_payload_with_test_inputs(
        &decode_hex_file(WAVE_B_PLAINTEXT_HEX),
        &realm_key(),
        aad_inputs,
        EncryptTestInputs {
            mlkem_encapsulation_m: bytes_32(WAVE_B_MLKEM_ENCAPS_M_HEX),
            x25519_eph_private: bytes_32(WAVE_B_X25519_EPH_SK_HEX),
            nonce: bytes_12(WAVE_B_NONCE_HEX),
        },
    )
    .expect("deterministic encrypt should succeed for test vector");

    let encrypt0 = payload.into_inner();
    let encoded = encrypt0
        .clone()
        .to_vec()
        .expect("COSE_Encrypt0 encoding should succeed");
    assert_eq!(encoded, decode_hex_file(WAVE_B_COSE_ENCRYPT0_HEX));

    assert_eq!(
        encrypt0
            .protected
            .clone()
            .to_vec()
            .expect("protected header should serialize"),
        decode_hex_file(WAVE_B_PROTECTED_HEX)
    );

    let enc_structure = enc_structure_data(
        EncryptionContext::CoseEncrypt0,
        encrypt0.protected.clone(),
        external_aad.as_bytes(),
    );
    assert_eq!(enc_structure, decode_hex_file(WAVE_B_ENC_STRUCTURE_HEX));

    let ciphertext_and_tag = encrypt0
        .ciphertext
        .as_ref()
        .expect("vector envelope should include ciphertext");
    assert_eq!(
        ciphertext_and_tag,
        &decode_hex_file(WAVE_B_CIPHERTEXT_AND_TAG_HEX)
    );

    let payload_hash = Sha256::of(&encoded);
    assert_eq!(payload_hash.as_bytes(), &bytes_32(WAVE_B_PAYLOAD_HASH_HEX));
}
