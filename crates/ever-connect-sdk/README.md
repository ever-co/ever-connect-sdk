# ever-connect-sdk

The Ever Platform client of an Ever product installation, for Rust, and the pieces it is built
from. Each part is a feature:

| Feature | Content | Dependencies |
|---|---|---|
| `client` (default) | `client::EverPlatformClient` over the generated operation table, behind the egress guard (only the base URL, no redirects, no cookies), with the instance token in memory; `keys` and `assertion` (the connect key, the client assertion, the rotation proofs, `subject_hash`) | `reqwest` with rustls and the webpki roots (no OpenSSL), `tokio` |
| `entitlement` | `manifest::verify_key_manifest`, `keyset::KeySet`, `entitlement::verify_entitlement` and `entitlement_status` | `ed25519-dalek`, `sha2`, `base64` |
| `stats` | the anonymous statistics checks and signer | `ed25519-dalek`, `sha2`, `base64` |
| `lookup` | `lookup::normalize_identifier`, `lookup_hash`, `check_test_vectors` | `sha2`, `idna`, `unicode-normalization` |
| `usage` | `usage::validate_usage_reading` | |

`default-features = false, features = ["entitlement", "lookup"]` pulls no HTTP client. The
managed-operation runner (`managed`) and the connect-code helpers (`codes`) are always there.
Errors, `Debug` and `Display` never carry a token, an assertion, a key or a document.

## Install

Until the first release on crates.io, depend on the repository at a commit:

```toml
ever-connect-sdk = { git = "https://github.com/ever-co/ever-connect-sdk", rev = "<commit>" }
```

## Verify an entitlement document

```rust
use ever_connect_sdk::entitlement::{verify_entitlement, VerifyEntitlementOptions};
use ever_connect_sdk::keyset::KeySet;
use ever_connect_sdk::manifest::VerifyKeyManifestOptions;

let keys = KeySet::verify(&manifest_body, &VerifyKeyManifestOptions {
    issuer: Some("https://api.ever.co"),
    ..Default::default()
})?;
let verified = verify_entitlement(&document, &VerifyEntitlementOptions {
    key_set: &keys,
    expected_issuer: "https://api.ever.co",
    expected_instance_id: &registry_id,
    expected_subject: &format!("instance:{registry_id}"),
    cached: stored.map(|s| s.cached),
    now: None,
})?;
```

The checks and their order are in [docs/entitlements.md](../../docs/entitlements.md); the codes
are the same as in the TypeScript package.

## The client

```rust
use std::sync::Arc;
use ever_connect_sdk::client::{ClientOptions, EverPlatformClient};
use ever_connect_sdk::keys::Ed25519Signer;

let mut options = ClientOptions::new(api_url, "works", env!("CARGO_PKG_VERSION"));
options.signer = Some(Arc::new(Ed25519Signer::from_seed(&connect_seed)));
options.registry_instance_id = Some(Arc::new(move || store.registry_instance_id()));
let client = EverPlatformClient::new(options)?;
let integrations = client.integrations().await?;
```

The extra roots (`root_keys`, `EVER_PLATFORM_ROOT_KEYS_FILE`) and another `issuer` are honoured
only when the base URL is a local host; otherwise they are ignored with one warning.
