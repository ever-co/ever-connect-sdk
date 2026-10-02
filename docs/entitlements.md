# Entitlements and signing keys

**Audience:** engineers building the Ever Platform modules into a product, and reviewers of how an installation decides which Ever Platform features it may offer.

An **entitlement** is a signed document an installation fetches from Ever Platform and verifies offline. It says which Ever Platform features a linked organization (or the installation itself) may use: lookup, discoverability, app sync and the like. It never restricts the product: nothing outside the Ever Platform modules reads it, so every product feature works the same with or without one.

This page describes the wire formats in `contracts/` and the order in which a verifier checks them. The fixtures in `contracts/fixtures/keys/` and `contracts/fixtures/entitlement/` pin every outcome below, with the expected result of each file in their `expected.json`.

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

The root public keys are pinned in the SDK (`root_keys` in `contracts/constants.json`). A verifier trusts the served `keys` only when all of these hold:

1. the manifest is a compact JWS with `alg: EdDSA` and `typ: ever-key-manifest+jwt`;
2. its `kid` names a pinned root whose issuer is the API origin, and the signature verifies with that root;
3. the payload's `iss` is the API origin and `root_kid` is the header's `kid`;
4. `iat` is not more than 60 s in the future and `exp` has not passed;
5. `keys_sha256` equals the hexadecimal SHA-256 of the RFC 8785 canonical JSON of the served `keys` array.

An installation caches the verified key set, fetches it again every 24 h (`key_manifest.refresh_s`), and on a key id it does not know, at most once every 10 minutes (`key_manifest.unknown_kid_refresh_min_s`).

### Rotation

- An `entitlement` key is replaced on a schedule. During the overlap the old key is listed with `state: previous` and still verifies; documents signed with it stay valid until they are re-issued.
- A retired key disappears from the manifest; every document it signed is re-issued with a new key and a higher `seq`, and installations pick it up from the event feed or the next refresh.
- A root key changes only in an SDK release, with the old and the new root pinned side by side for the transition.

### Test roots for local runs

`EVER_PLATFORM_ROOT_KEYS_FILE` names a JWKS file (`{"keys": [...]}`) of alternative roots. The modules honour it **only when the API base URL is a local address** (`root_keys_file_hosts` in `contracts/constants.json`: `localhost`, loopback, the private ranges and `*.localhost`); on any other base URL it is ignored and a warning is logged at boot. It exists for continuous integration against the mock platform, whose TEST root is in `root_keys` with the issuer `http://mock-platform:8080`. The TEST keys are derived from public seeds, so they sign nothing anyone trusts.

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
| `ever.managed` | managed updates, backups and support level |
| `ever.grace_s`, `ever.refresh_after_s` | how long the document stays usable after `exp` (30 days), and when to refresh it (6 h) |

`ever.handle` is the only human-readable field.

---

## 3. Verification order

A verifier checks an entitlement document in this order and stops at the first failure (the code in brackets is the one the fixtures expect):

1. A compact JWS whose header `typ` is `ever-entitlement+jwt` (`bad_typ`).
2. `alg` is `EdDSA` and there is no `crit` header, checked before any key lookup (`bad_alg`).
3. `kid` names a key of the cached, root-verified key set with `ever_purpose: entitlement` and `state` `active` or `previous`; an unknown key id refreshes the key set (at most once per 10 minutes) before the document is refused (`unknown_kid`).
4. The Ed25519 signature over the JWS signing input (`bad_signature`).
5. `ever.schema` is `ever.entitlement.v1`, `iss` is the API origin, `aud` is `ever-connect`, and the payload validates against the schema (`schema_violation`, `issuer_mismatch`, `audience_mismatch`).
6. `ever.instance_id` is this installation and `sub` is the subject asked for (`instance_mismatch`, `subject_mismatch`).
7. `iat` and `nbf` are at most 300 s in the future (`iat_in_future`, `nbf_in_future`).
8. `ever.seq` is higher than the cached document's, or equal with a later `iat`; a lower `seq` is refused and audited (`entitlement_stale`).

`exp` is not a verification failure. It decides what the verified document allows:

| Condition | Ever Platform features | The product |
|---|---|---|
| before `exp` | as `ever.features` say | unaffected |
| from `exp` until `exp + ever.grace_s` | as `ever.features` say, with an admin notice that entitlements could not be refreshed | unaffected |
| after `exp + ever.grace_s`, or no document | paused until a fresh document verifies | unaffected |

A document that fails any check is discarded and the previous one is kept. Tokens are never logged.

---

## 4. Refresh

- Row 8 of *What this installation sends, and when*: `GET /v1/instances/me/entitlement` for the installation, `GET /v1/instances/me/tenant-links/{link}/entitlement` for a linked organization, with `If-None-Match: "<seq>"`. `304` keeps the cached document; `200` carries a new one that goes through the checks above.
- When: every `refresh_after_s` (6 h), at boot, when the event feed delivers `ever.entitlements.entitlement.issued` for the subject, and on demand from the admin page; at most 6 reads an hour (`entitlement.max_reads_per_hour`).
- A revocation or downgrade takes effect on the platform at once (it refuses the calls) and reaches the installation as a new document with a higher `seq`.

---

## 5. In this repository

| Item | Where |
|---|---|
| Schemas | `contracts/schemas/ever.key-manifest.v1.json`, `contracts/schemas/ever.entitlement.v1.json` |
| Constants (roots, lifetimes, refresh intervals, the roots file hosts) | `contracts/constants.json`, also exported by `@ever-co/connect-contracts` and the `ever-connect-contracts` crate |
| Fixtures with expected outcomes | `contracts/fixtures/keys/`, `contracts/fixtures/entitlement/` |
| A platform that signs both | the mock platform (`docs/mock-platform.md`): `GET /.well-known/ever-keys.json` and the entitlement routes, signed with the TEST keys; `POST /__mock/keys/rotate` and `POST /__mock/entitlement/reissue` drive rotation and re-issue |
