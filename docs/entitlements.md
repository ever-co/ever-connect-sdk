# Entitlements and signing keys

**Audience:** engineers building the Ever Platform modules into a product, and reviewers of how an installation decides which Ever Platform features it may offer.

An **entitlement** is a signed document an installation fetches from Ever Platform and verifies offline. It says which Ever Platform features a linked organization (or the installation itself) may use: lookup, discoverability, app sync and the like. It never restricts the product: nothing outside the Ever Platform modules reads it, so every product feature works the same with or without one. When it lapses, Ever Platform features pause; the product keeps working.

This page describes the wire formats in `contracts/`, the order in which the SDK checks them (`verifyKeyManifest` and `verifyEntitlement` in `@ever-co/connect-sdk`, `verify_key_manifest` and `verify_entitlement` in the `ever-connect-sdk` crate: one implementation, the same codes in both languages), and how an installation keeps its keys. The fixtures in `contracts/fixtures/keys/`, `contracts/fixtures/keys-platform/` and `contracts/fixtures/entitlement/` pin every outcome below, with the expected result of each file in their `expected.json`.

---

## 1. Key discovery

Every Ever Platform signature an installation verifies (entitlements, assertions, provisioning intents) uses a key published at one address:

```
GET <EVER_PLATFORM_API_URL>/.well-known/ever-keys.json
```

The body (`contracts/schemas/ever.key-manifest.v1.json`) has two members:

| Member | Content |
|---|---|
| `keys` | the published Ed25519 keys: `kty: OKP`, `crv: Ed25519`, `kid`, `x`, `use: sig`, `alg: EdDSA`, `ever_purpose` (`entitlement`, `assertion` or `intent`), `state` (`active`, or `previous` during a rotation overlap), `not_before`, `not_after` |
| `manifest` | a compact JWS signed by a **root key**, header `{alg: EdDSA, kid: <root kid>, typ: ever-key-manifest+jwt}`, payload `{iss, iat, exp, keys_sha256, root_kid}` with `exp` 30 days after `iat` |

A manifest is always verified **for one issuer**: the caller names it (`verifyKeyManifest(body, { issuer })`; `KeySet.verify`, `KeySet.restore` and `keySet.update` take the same option; in Rust `VerifyKeyManifestOptions { issuer, .. }` or `VerifyKeyManifestOptions::for_issuer(issuer)`). There is no default: without an issuer the call is refused, and the issuer is never taken from a root. The SDK trusts the served `keys` only when every check passes, in this order (the first failure is the answer):

| # | Check | Code |
|---|---|---|
| 1 | the body is `{manifest, keys}` under the closed schema; every `not_before`/`not_after` is a UTC time that exists; every key `x` is a curve point of large order | `schema_violation` |
| 2 | `manifest` is a compact JWS under the decoding rule below | `malformed` |
| 3 | header `typ` is `ever-key-manifest+jwt` | `bad_typ` |
| 4 | header `alg` is `EdDSA` and there is no `crit`, before any key is looked at | `bad_alg` |
| 5 | header `kid` is a root pinned for this issuer (a root's `iss` names the one issuer it vouches for), and the root is a strong key | `unknown_root` |
| 6 | the root's Ed25519 signature, verified strictly (no small-order point, no non-canonical encoding) | `bad_signature` |
| 7 | the payload is `{iss, iat, exp, keys_sha256, root_kid}` and `root_kid` is the header's `kid` | `malformed` |
| 8 | `iss` is the issuer the manifest is verified for | `issuer_mismatch` |
| 9 | `iat` is at most 300 s in the future | `manifest_not_yet_valid` |
| 10 | `exp` has not passed | `manifest_expired` |
| 11 | `keys_sha256` is the hexadecimal SHA-256 of the RFC 8785 canonical JSON of the served `keys` | `keys_sha256_mismatch` |

**The decoding rule** (every compact JWS the SDK reads: manifests and entitlement documents, the same in both languages): at most 64 KiB; three canonical base64url parts (no padding, no other alphabet, no stray bits); header and payload are JSON objects in valid UTF-8 without a byte order mark, with well-formed strings (no lone surrogate) and at most 127 levels of nesting; every number is an integer without fraction or exponent, between -(2^53-1) and 2^53-1 (`3.0`, `1e3`, `-0` and `9007199254740992` are `malformed`).

**Key times** are RFC 3339 UTC times (`2026-11-01T10:00:00Z`, an optional fraction of a second): an offset, a space, a lower-case `z`, a leap second or a day that does not exist refuses the whole manifest (`schema_violation`). A key is never trusted on a time the SDK cannot read.

A key of a verified manifest verifies a document only for its own `ever_purpose`, in state `active` or `previous`, inside its `not_before`/`not_after` window (300 s of clock skew). An installation caches the verified key set (`KeySet` keeps it in memory; the product stores `toJSON()` (Rust: `stored()`), which holds no secret, and `KeySet.restore(stored, { issuer })` verifies it again for the issuer the installation is configured for; a stored fetch time in the future counts as now), fetches it again every 24 h (`key_manifest.refresh_s`), and on a key id it does not know, at most once every 10 minutes (`key_manifest.unknown_kid_refresh_min_s`). A manifest that fails verification, is for another issuer, or is older than the cached one never replaces it.

**Verified objects cannot be made by hand.** A `KeySet` comes only from `KeySet.verify`, `KeySet.restore`, `keySet.update` or the client's `keys.refresh` (Rust: `KeySet::verify`, `KeySet::restore`, `update`, `refresh_keys`); `verifyEntitlement` refuses anything else. In TypeScript the verified manifest is branded (`isVerifiedKeyManifest`) and `KeySet.fromManifest` accepts only one that `verifyKeyManifest` returned; in Rust `VerifiedKeyManifest` and `ManifestKey` have private fields (read through getters) and `KeySet::from_manifest` is private to the crate. A product persists the served body and restores it; it never rebuilds a verified object from stored fields.

### Pinned roots

Roots are pinned per issuer in `root_keys` (`contracts/constants.json`): a root vouches only for manifests whose `iss` is the issuer it is pinned for, so the development or staging root never vouches for a production manifest.

| Issuer | Root `kid` | Use |
|---|---|---|
| `https://api-dev.ever.co` | `ever-202610-0d77` | product builds that talk to the development API |
| `https://api-stage.ever.co` | `ever-202610-8704` | product builds that talk to the staging API |
| `https://api.ever.co` | pending | added by its own reviewed change once the production root exists; until then no release is tagged |

A root changes only in an SDK release, with the old and the new root pinned side by side for the transition (adding a root is a minor release, removing one a major release).

No TEST root is pinned. The TEST root (`test-root-1`) is derived from a public seed, so anyone can sign with it: it lives in `contracts/fixtures/keys/roots.json` (for the SDK's own tests) and in the mock platform (`testRootEntry(issuer)` from `ever-mock-platform/keys`), and a local run passes it through the override below. A release still refuses a `test-` root in `root_keys`.

### Test roots for local runs

`EVER_PLATFORM_ROOT_KEYS_FILE` names a JWKS file (`{"keys": [...]}`) of extra roots, each with the `iss` it vouches for, and the client's `rootKeys` option (`root_keys` in Rust) adds roots in code. Both are honoured **only when the API base URL is a local address** (`root_keys_file_hosts` in `contracts/constants.json`: `localhost`, loopback, the private ranges and `*.localhost`); on any other base URL they are ignored with one warning. The same rule holds for the client's `issuer` option, which lets a local run name another issuer (the mock signs as `https://mock-platform.test` in the SDK's own tests). They exist for continuous integration against the mock platform.

Below the client, `unsafeRootKeys` (`unsafe_root_keys` in Rust) on `verifyKeyManifest` and `KeySet` **replaces** the pinned roots on any base URL; it is named for what it does and is meant for tests and offline tools only. Product code leaves it out.

---

## 2. The entitlement document

A compact JWS with the header `{alg: EdDSA, kid, typ: ever-entitlement+jwt}`. The payload follows `contracts/schemas/ever.entitlement.v1.json`, closed at every level:

| Claim | Meaning |
|---|---|
| `iss` | the API origin (`https://…`) |
| `aud` | `ever-connect` |
| `sub` | `instance:<id>` for the installation's own document, `link:<tenant link id>` for a linked organization, `org:<id>` |
| `jti`, `iat`, `nbf`, `exp` | identifier and times; documents are valid for 7 days (`entitlement.validity_s`) |
| `ever.schema` | `ever.entitlement.v1` |
| `ever.seq` | increases with every re-issue for the same subject |
| `ever.instance_id`, `ever.tenant_link_id`, `ever.tenant` | the installation and the link the document is for |
| `ever.tier`, `ever.plan`, `ever.products` | the organization's tier and plan |
| `ever.features`, `ever.limits`, `ever.meters` | the Ever Platform features granted, and their limits |
| `ever.managed` | maintenance operations and support level |
| `ever.grace_s`, `ever.refresh_after_s` | how long the document stays usable after `exp` (30 days), and when to refresh it (6 h) |

`ever.handle` is the only human-readable field.

---

## 3. Verification order

The SDK checks an entitlement document in this order and stops at the first failure:

| # | Check | Code |
|---|---|---|
| 0 | the key set was verified for the expected issuer (a key set vouches for documents of its own issuer only), before the document is decoded | `issuer_mismatch` |
| 1 | a compact JWS under the decoding rule of section 1 | `malformed` |
| 2 | header `typ` is `ever-entitlement+jwt` | `bad_typ` |
| 3 | `alg` is `EdDSA` and there is no `crit` header, checked before any key lookup (no `none`, no RS256) | `bad_alg` |
| 4 | `kid` names a key of the root-verified key set with `ever_purpose: entitlement`, `state` `active` or `previous`, inside its window | `unknown_kid` (with `refreshSuggested` when the manifest does not list the id at all) |
| 5 | the Ed25519 signature over `base64url(header).base64url(payload)`, verified strictly (no small-order point, no non-canonical encoding) | `bad_signature` |
| 6 | `ever.schema` is `ever.entitlement.v1` | `schema_violation` |
| 7 | `iss` is the origin of the API | `issuer_mismatch` |
| 8 | `aud` is `ever-connect` | `audience_mismatch` |
| 9 | the whole payload validates against the closed schema | `schema_violation` (with the JSON pointer of the first field) |
| 10 | `ever.instance_id` is this installation's Registry id | `instance_mismatch` |
| 11 | `sub` is the subject asked for; a `link:` document names its own link (`ever.tenant_link_id` is the id after `link:`), an `instance:` document carries neither `ever.tenant_link_id` nor `ever.tenant` | `subject_mismatch` |
| 12 | `iat` is at most 300 s in the future | `iat_in_future` |
| 13 | `nbf` is at most 300 s in the future | `nbf_in_future` |
| 14 | `ever.seq` is higher than the cached document's, or equal with a later `iat` | `entitlement_stale` |

On `unknown_kid` with `refreshSuggested`, the product refreshes the key set once (`KeySet.unknownKidRefreshAllowed` says whether 10 minutes have passed) and verifies again; a second `unknown_kid` is final. The clients do this for you: `client.verifyEntitlementRefreshing(jws, { keySet })` answers `{ verified, keySet }` (Rust: `verify_entitlement_refreshing` answers the result and, when the refresh replaced it, the new key set to keep). A document that fails any check is discarded and the previous one is kept; no error carries the token or a claim value, only the code.

`exp` is not a verification failure. It decides what the verified document allows (`entitlementStatus`, from the cached document only, never from the state of the connection):

| Condition | Status | Ever Platform features | The product |
|---|---|---|---|
| before `exp` | `valid` | as `ever.features` say | unaffected |
| from `exp` until `exp + ever.grace_s` | `stale` | as `ever.features` say, with an admin notice that entitlements could not be refreshed | unaffected |
| after `exp + ever.grace_s`, or no document | `paused` | paused until a fresh document verifies | unaffected |

### Offline import

An installation without egress can be given a document by hand (downloaded from app.ever.co and uploaded in the product's admin page). The same checks apply; the installation needs only its stored key set (`KeySet.restore(stored, { issuer })`, with the issuer it is configured for) and the root pinned in the SDK for that issuer.

---

## 4. Refresh

- Row 8 of *What this installation sends, and when*: `GET /v1/instances/me/entitlement` for the installation, `GET /v1/instances/me/tenant-links/{link}/entitlement` for a linked organization, with `If-None-Match: "<seq>"`. `304` keeps the cached document (`{notModified: true}` from the client); `200` carries a new one that goes through the checks above.
- When: every `refresh_after_s` (6 h), at boot, when the event feed delivers `ever.entitlements.entitlement.issued` for the subject, and on demand from the admin page; at most 6 reads an hour (`entitlement.max_reads_per_hour`).
- A revocation or downgrade takes effect on the platform at once (it refuses the calls) and reaches the installation as a new document with a higher `seq`.

---

## 5. The installation's own keys

- The **connect key** (Ed25519) is the installation's credential: its public JWK goes into the redeem, and every instance token is obtained with a client assertion it signs (`signClientAssertion`: `iss = sub =` the Registry id the redeem answered, `aud = <API origin>/v1/instances/token`, a random `jti`, at most 300 s of life). Its key id is `base64url(sha256(raw key)[0:8])`.
- The **statistics key** is a separate Ed25519 key used for anonymous statistics only. Keep the two apart: rotating the connect key (`POST /v1/instances/me/keys` with the two proofs `signKeyRotation` builds; the previous key is accepted for 7 days) never changes the statistics identity, and the statistics ingest refuses a report signed with another key under the same statistics id.
- Before the first redeem there is no Registry id: every call that needs the instance token is refused before anything is sent (`NotConnectedError`). The anonymous statistics id (a UUID) never authenticates (`not_a_registry_id`).

---

## 6. In this repository

| Item | Where |
|---|---|
| Schemas | `contracts/schemas/ever.key-manifest.v1.json`, `contracts/schemas/ever.entitlement.v1.json` |
| Constants (roots, lifetimes, refresh intervals, the roots file hosts) | `contracts/constants.json`, also exported by `@ever-co/connect-contracts` and the `ever-connect-contracts` crate |
| The verifier | `@ever-co/connect-sdk` (`verifyKeyManifest`, `KeySet`, `verifyEntitlement`, `entitlementStatus`); the `ever-connect-sdk` crate, feature `entitlement` (`manifest`, `keyset`, `entitlement`) |
| Fixtures with expected outcomes | `contracts/fixtures/keys/` (TEST root, the small-order encodings, the shared origin vectors), `contracts/fixtures/keys-platform/` (manifests the development and staging APIs serve), `contracts/fixtures/entitlement/` (with `mutations.json`: the answers of the seeded mutation corpus, and `structured.json`: documents and manifests built on purpose with the answers of the reference verifier; both languages reproduce every answer) |
| A platform that signs both | the mock platform (`docs/mock-platform.md`): `GET /.well-known/ever-keys.json` and the entitlement routes, signed with the TEST keys; `POST /__mock/keys/rotate` and `POST /__mock/entitlement/reissue` drive rotation and re-issue |
