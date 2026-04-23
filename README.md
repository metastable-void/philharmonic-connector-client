# philharmonic-connector-client

Lowerer-side minting library for the Philharmonic connector layer.

This crate runs in the executor-adjacent *lowerer* process. It takes
a `ConnectorTokenClaims` value (already assembled from workflow
context + fetched `TenantEndpointConfig`) and produces a
`ConnectorSignedToken` — a `COSE_Sign1` structure signed with
Ed25519 (COSE `alg = -8`, EdDSA) and tagged with the lowerer's `kid`
in the protected header. No network I/O; no file I/O; no mutable
state beyond the key handle the caller passes in.

Part of the Philharmonic workspace:
https://github.com/metastable-void/philharmonic-workspace

## What's in this crate

- `LowererSigningKey` — the signing-key handle. Built from a
  `Zeroizing<[u8; 32]>` Ed25519 seed plus the `kid` string; the seed
  bytes are zeroized on drop. `mint_token(&claims)` returns a
  `ConnectorSignedToken` on success.
- `MintError` — failure modes on the mint path (claim serialization,
  COSE construction). Typed so callers can decide whether to retry
  or surface the failure.
- Re-exports of the common vocabulary
  (`ConnectorTokenClaims`, `ConnectorSignedToken`, `Sha256`,
  `UnixMillis`, `Uuid`, `Zeroizing`) so consumers only need one
  import path for everyday use.

## What's out of scope

- Payload **encryption** (COSE_Encrypt0, hybrid ML-KEM-768 + X25519
  KEM, AES-256-GCM). Wave A ships only the mint path; the encrypt
  path lands with Wave B and will share this same crate.
- Key loading from filesystem / environment / KMS. Per the workspace
  library-boundary convention, this library takes raw bytes
  (`Zeroizing<[u8; 32]>`); a bin crate is responsible for sourcing
  those bytes.
- Claim-set assembly. Callers build `ConnectorTokenClaims` from
  their workflow + policy inputs; this crate only signs what it's
  given.

## Quick start

```rust
use philharmonic_connector_client::{
    ConnectorTokenClaims, LowererSigningKey, Sha256, UnixMillis, Uuid, Zeroizing,
};

fn mint_example() -> Result<(), Box<dyn std::error::Error>> {
    let claims = ConnectorTokenClaims {
        iss: "lowerer.main".to_owned(),
        exp: UnixMillis(1_924_992_000_000),
        iat: UnixMillis(1_924_991_880_000),
        kid: "lowerer.main-2026-04-22-3c8a91d0".to_owned(),
        realm: "llm".to_owned(),
        tenant: Uuid::parse_str("11111111-2222-4333-8444-555555555555")?,
        inst: Uuid::parse_str("66666666-7777-4888-8999-aaaaaaaaaaaa")?,
        step: 7,
        config_uuid: Uuid::parse_str("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff")?,
        payload_hash: Sha256::of(b"phase-5-wave-a-test-payload"),
    };

    let seed = Zeroizing::new([0_u8; 32]);
    let signing_key = LowererSigningKey::from_seed(seed, claims.kid.clone());
    let _token = signing_key.mint_token(&claims)?;
    Ok(())
}
```

The seed bytes are held in a `Zeroizing` wrapper for the whole
lifetime of `LowererSigningKey`; the internal `ed25519_dalek`
`SigningKey` is reconstructed per mint call so the expanded secret
material never lives longer than one signature.

## Verification + security notes

- Primitives: `ed25519-dalek 2` for signing, `coset 0.4` for COSE
  framing, `ciborium 0.2` for CBOR. No custom crypto.
- The token commits to the encrypted payload via the
  `payload_hash` claim (SHA-256 of the COSE_Encrypt0 bytes). Wave A
  accepts arbitrary `Sha256` values so the mint path is exercisable
  without a Wave B ciphertext in hand; real deployments will hash
  actual ciphertexts.
- Known-answer test vectors live under
  [`docs/crypto-vectors/wave-a/`](../docs/crypto-vectors/wave-a/)
  (generated with an external Python reference, committed, and
  verified byte-for-byte by the test suite).
- Design background:
  [`docs/design/11-security-and-cryptography.md`](../docs/design/11-security-and-cryptography.md),
  [`docs/design/08-connector-architecture.md`](../docs/design/08-connector-architecture.md).

## Versioning notes

- `0.1.0` — first publish (with Wave B); bundles the Wave A mint
  path with the Wave B encrypt path so `0.1.0` is a cohesive
  release of the lowerer-side library.

## License

Dual-licensed under `Apache-2.0 OR MPL-2.0`. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MPL](LICENSE-MPL).

SPDX-License-Identifier: `Apache-2.0 OR MPL-2.0`

## Contributing

This crate is developed as a submodule of the Philharmonic
workspace. Workspace-wide development conventions — git workflow,
script wrappers, Rust code rules, versioning, terminology — live
in the workspace meta-repo at
[metastable-void/philharmonic-workspace](https://github.com/metastable-void/philharmonic-workspace),
authoritatively in its
[`CONTRIBUTING.md`](https://github.com/metastable-void/philharmonic-workspace/blob/main/CONTRIBUTING.md).
