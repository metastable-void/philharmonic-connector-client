# Changelog

All notable changes to this crate are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  reference vectors at `docs/crypto-vectors/wave-a/` were regenerated to
  reflect the 10-entry claim-map layout.

## [0.0.0]

Name reservation on crates.io. No functional content yet.
