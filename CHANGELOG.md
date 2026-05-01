# Changelog

All notable changes to this crate are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-23

### Added

- Added `LowererSigningKey` with `Zeroizing<[u8; 32]>` seed storage and
  per-call transient `SigningKey` reconstruction for minting.
- Added `mint_token` COSE_Sign1 minting flow (`alg=-8`, protected `kid`,
  CBOR claim serialization via `ciborium`).
- Added `MintError` taxonomy for input validation, serialization, and signing
  failures.
- Added known-answer tests loading committed Wave A vectors and asserting
  byte-for-byte equality with `wave_a_cose_sign1.hex`.
- Added crate-level exports and README usage documentation.
- Bump `philharmonic-connector-common` pin `"0.1"` → `"0.2"`. Picks up the
  new `iat` claim on `ConnectorTokenClaims`; signing code passes it through
  unchanged (ciborium serializes it positionally). Committed Wave A
  reference vectors at `tests/vectors/wave-a/` were regenerated to
  reflect the 10-entry claim-map layout.
- Added Wave B `encrypt_payload` and deterministic
  `encrypt_payload_with_test_inputs` APIs for lowerer-side hybrid-KEM
  encapsulation (ML-KEM-768 + X25519), HKDF-SHA256 key derivation,
  AES-256-GCM sealing, and COSE_Encrypt0 envelope construction.
- Added `AeadAadInputs` and deterministic `EncryptTestInputs` helper inputs
  for payload-AAD binding and byte-for-byte vector reproduction.
- Added `EncryptError` taxonomy and re-exports for the Wave B encryption
  surface.
- Added committed-vector known-answer tests for every Wave B stage
  (`kem_ct`/`kem_ss`, ECDH, HKDF key, `external_aad`, protected header,
  `Enc_structure`, ciphertext+tag, final envelope, payload hash).

### Changed

- Tightened Wave B AEAD key handling by zeroizing stack `aead_key_bytes` immediately after copying into `SecretBox`.
- Removed dead HKDF `prk_bytes` scratch handling and unused PRK tuple binding; HKDF expansion continues through the existing `hkdf` context unchanged.
