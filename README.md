# philharmonic-connector-client

Minting library for Phase 5 connector authorization tokens in the
Philharmonic workspace. This crate signs `ConnectorTokenClaims` as
`COSE_Sign1` with Ed25519 (`alg = -8`) and returns
`ConnectorSignedToken`.

Part of the Philharmonic workspace:
https://github.com/metastable-void/philharmonic-workspace

## Quick start

```rust
use philharmonic_connector_client::{
    ConnectorTokenClaims, LowererSigningKey, Sha256, UnixMillis, Uuid, Zeroizing,
};

fn mint_example() -> Result<(), Box<dyn std::error::Error>> {
    let claims = ConnectorTokenClaims {
        iss: "lowerer.main".to_owned(),
        exp: UnixMillis(1_924_992_000_000),
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

Real lowerers should obtain the seed bytes in the bin crate
(filesystem, environment, KMS), then pass bytes to this library.

## License

Dual-licensed under `Apache-2.0 OR MPL-2.0`.

SPDX-License-Identifier: Apache-2.0 OR MPL-2.0
