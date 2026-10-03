# Mock platform

**Audience:** engineers testing a product's Ever Platform modules in continuous integration, without an Ever Platform account and without any outbound connection.

`ever-mock-platform` answers every outbound call of the Ever Platform modules (every row of `docs/outbound-calls.md`) with the statuses, problem codes and response shapes of the Ever Platform API contract in `contracts/`. It signs with TEST keys derived from public seeds, records every call it receives, and has controls under `/__mock/*` that stand in for what an organization does in app.ever.co. It holds its state in memory and makes no outbound request.

---

## 1. Run it

```sh
# from this repository
node tools/mock-platform/bin/ever-mock-platform.mjs --port 8080

# from a product, through the dev-only tools package
pnpm exec ever-mock-platform --port 8080 --record artifacts/requests.jsonl

# as a container (built from tools/mock-platform)
docker build -t ever-mock-platform:local tools/mock-platform
docker run --rm -p 8080:8080 ever-mock-platform:local
```

| Option | Default | Meaning |
|---|---|---|
| `--port` | `8080` (or `PORT`) | listening port |
| `--host` | `0.0.0.0` (or `HOST`) | listening address |
| `--config <file>` | none | configuration file (see *Configuration* below); `EVER_MOCK_CONFIG_JSON` passes the same JSON through the environment |
| `--record <file.jsonl>` | none | appends one line per call received |
| `--state-out <file.json>` | none | writes the state on exit (`SIGTERM`, `SIGINT`) |
| `--fixed-clock` | off | keeps the deterministic clock instead of real time |

The clock follows real time from start, so a product signs assertions with its own clock. A configuration with a `clock` entry, or `--fixed-clock`, keeps the deterministic clock the SDK's own tests use (`2026-11-02T10:00:00Z` until `POST /__mock/clock` moves it).

In Compose, next to the product:

```yaml
services:
  mock-platform:
    build: ./node_modules/@ever-co/connect-tools/dist/mock-platform
    environment:
      EVER_MOCK_CONFIG_JSON: '{"integrations":{"enabled":["stats_link"]}}'
  api:
    environment:
      EVER_PLATFORM_API_URL: http://mock-platform:8080
      EVER_STATS_API_URL: http://mock-platform:8080
      EVER_CONNECT_ENABLED: "true"
      EVER_CONNECT_CODE: EVC-TEST-0000-0001
      EVER_PLATFORM_ROOT_KEYS_FILE: /ever-audit/roots.json
    depends_on: [mock-platform]
```

The SDK pins no TEST root, so the product must be given the mock's: write `{"keys": [testRootEntry(issuer)]}` (`testRootEntry` from `ever-mock-platform/keys`, with the mock's issuer, `http://mock-platform:8080` by default) to the file `EVER_PLATFORM_ROOT_KEYS_FILE` names. The modules honour that file only for a local base URL (`docs/entitlements.md`).

---

## 2. Configuration

Every key is optional; `tools/mock-platform/mock.config.example.json` shows the defaults.

| Key | Default | Meaning |
|---|---|---|
| `issuer` | `http://mock-platform:8080` | the origin in tokens, manifests, entitlements and assertion audiences |
| `clock` | real time (CLI) | `{start}` for a fixed clock (seconds), `{real: true}` for real time |
| `codes` | `EVC-TEST-0000-0001` (gauzy, ready), `EVC-TEST-0000-0003` (gauzy, pending approval), `EVC-TEST-0000-0004` (works), `EVL-TEST-0000-0002` (link) | connect and link codes with their product, organization, lifetime and approval state |
| `entitlement` | `tier: paid` with lookup, discoverability, handle, public profile and Ever ID sign-in | the content of issued entitlement documents |
| `integrations` | `{cloud_defaults: false, enabled: []}` | integrations consented at connect |
| `consent` | `{web_url: 'https://app.ever.co', allow_local_return: true}` | the address consent links point to, and whether their return address may be plain `http` on localhost (a development deployment; Ever Platform's own deployments take `https` only) |
| `lookup` | one salt version, one opted-in VAT number | lookup salts, opt-ins and claimed hashes |
| `people` | one Ever ID person, owner of the organization | people the person tokens are issued for |
| `limits` | the platform's rate limits | wrong codes per hour (connect codes per client address, link codes per installation, with `wrong_link_codes_per_address_hour` as the per-address backstop), tokens per hour per installation (`tokens_per_hour`), heartbeat interval, entitlement reads per hour, statistics reports per day (`stats_reports_per_day`), months stored per statistics id and day (`stats_periods_per_day`), new statistics ids per source address and hour (`stats_new_ids_per_address_hour`) and per day (`stats_new_ids_per_day`), lookup and discovery rates, device starts, webhook endpoints |
| `faults` | none | `keys_unavailable`, `webhooks_module_disabled`, `revoke_credential_at_call`, `connect_issuance_off` (a deployment that issues no connect or link codes: a well-formed redeem or link-code redemption answers 404, a malformed body still 422), `legal_unavailable` (no terms published: the legal texts and any consent write answer 503), `consent_links_unavailable` (consent links not configured: 503) |

---

### 2.1 Integrations as the mock keeps them

- A call gated by a per-link integration names its tenant link in `Ever-Link-Id` (`422 validation_failed` at `#Ever-Link-Id` without it, or with a value that is not a tenant link id); an installation-wide integration (`instance_url`, `stats_link`, `ever_id_login`, `webhooks`, and `managed_operations` until its platform module exists) ignores the link.
- The heartbeat's `integrations_denied` is the installation's whole local deny list: a key it names goes off on every link and reads `denied_by_policy`; a later heartbeat without the key lifts the deny. Switching an integration off with `reason: policy` adds the key to the list.
- The consent link takes an optional `return`, accepted only when its origin is one the redeem declared (`return_origins`, at most four, normalised).
- An integration the catalog marks `coming_soon` reads `coming_soon` and cannot be enabled through the API, as on Ever Platform; `POST /__mock/consent` still enables one, so a product can test what comes next.

## 3. The call record

`GET /__mock/requests` answers one entry per call, in order:

```json
{ "ts": "2026-10-02T04:05:46Z", "method": "POST", "path_template": "/v1/connect/redeem", "row": 3,
  "status": 201, "user_agent": "ever-connect-sdk/1.0.0 (gauzy/96.2.1)", "idempotency_key": "…",
  "body_sha256": "…" }
```

`row` is the outbound-call row of the operation (`null` for a call outside the table). The record never holds a body, a code, an assertion, a token or a secret: only the SHA-256 of the body. The egress audit compares it with the rows a mode allows (`tools/egress-audit/assert-call-log.mjs`). The controls below are never recorded.

---

## 4. Controls (`/__mock/*`)

`instance_id` is optional wherever it appears: the last connected installation is used.

| Control | Body | Effect |
|---|---|---|
| `GET /__mock/healthz` | | `{ok: true}` |
| `GET /__mock/requests` | | the call record |
| `GET /__mock/state` | | installations, links, integration states, feeds, statistics reports, managed operations |
| `POST /__mock/reset` | | empties the state and the record |
| `POST /__mock/clock` | `{set}` or `{advance}` (seconds) | moves the clock; expires managed operations past their window |
| `POST /__mock/keys/rotate` | | rotates the entitlement key (the old one stays `previous`) |
| `POST /__mock/codes` | `{code, kind?, product?, org?, expires_in_s?, pending_approval?}` | adds a code |
| `POST /__mock/codes/revoke` | `{code}` | revokes a code, as an organization admin does in app.ever.co: its redemption answers `422 code_invalid` |
| `POST /__mock/approve` | `{instance_id}` or `{user_code \| device_code, org?}` | approves a pending installation or a device-first connect |
| `POST /__mock/emit` | `{type, data, subject?}` | puts an event of the instance audience on the feed (validated against its schema) |
| `POST /__mock/entitlement/reissue` | `{link?}` | issues a new entitlement document (higher `seq`) and notifies the feed |
| `POST /__mock/consent` | `{integration, link?, enabled?, consent_source?, operator_accept?}` | records a consent as app.ever.co would (`operator_accept: "pending"` waits for the operator) |
| `POST /__mock/revoke` | `{integration, link?}` | revokes a consent |
| `POST /__mock/disconnect` | | disconnects the installation from the platform side |
| `POST /__mock/revoke-instance` | | revokes the installation's credential |
| `POST /__mock/person-token` | `{sub?, role?, azp?, auth_time? \| auth_age_s?, ttl?}` | an Ever ID token for the person routes (step-up freshness through `auth_time`) |
| `POST /__mock/provision-intent` | `{expires_in_s?}` | a signed provisioning intent to complete |
| `POST /__mock/install` | `{state?}` | an install request from apps.ever.co |
| `POST /__mock/provider-grant` | `{status?, role?}` | a provider access grant |
| `POST /__mock/managed/request` | `{kind, params, expires_in_s?}` | requests a managed operation (needs the `managed_operations` integration, else `403 integration_disabled`) |
| `GET /__mock/managed/operations` | | the managed operations with their state and results |
| `POST /__mock/webhook-delivery` | `{webhook_id, state?}` | a delivery of a webhook endpoint |
| `POST /__mock/faults` | `{keys_unavailable?, webhooks_module_disabled?, revoke_credential_at_call?, connect_issuance_off?}` | switches faults on and off |
| `POST /__mock/person-request` | `{kind: deletion \| export, …}` | a deletion or export request for a person on the feed |

The connect key rotates as on the platform. `POST /v1/instances/me/keys` takes the new public key and two proofs: `current_key_proof`, signed with the current connect key, and `new_key_proof`, signed with the new key. Both carry the claims of a client assertion with `aud` = `<issuer>/v1/instances/me/keys` and `cnf.jkt` = the RFC 7638 thumbprint of the new key, each with its own `jti`. Any proof that fails answers `401 invalid_client`; the current key, or a key an installation holds or held, answers `422 public_jwk_invalid`. `signRotationProof` (from `ever-mock-platform/keys`) builds a proof with the TEST keys. Tokens minted with the replaced key work until its 7-day overlap ends; rotating again inside the overlap stops them at once (`401 unauthorized`: mint a new token). The token endpoint mints at most 60 tokens an hour per installation, then answers `429 rate_limited` with `Retry-After`: keep a token for its hour.

---

## 5. Scenarios the SDK tests run

The mock's own tests (`tools/mock-platform/test/`) are the reference for how to drive it:

- `rows.test.mjs`: the good path of every operation and every documented `(status, code)` pair, with every success answer validated against the contract's response schema;
- `sample-flow.test.ts`: connect, link, entitlement, feed and statistics in the order a product runs them;
- `in-product-consent.test.mjs`: the consent dialog after a fresh Ever ID sign-in;
- `managed.test.mjs`: scenario `managed-backup`, a fixture executor on the SDK's managed-operation runner;
- `issuance.test.mjs`: a deployment that issues no connect codes (`connect_issuance_off`), and the assertion rules;
- `rows-core.test.mjs`: the core rows in depth, among them the connect-key rotation and its proofs, the token limit, the link-code windows, and the statistics report checks in the platform's order (media type, size, key, signature shape, key id, signature, strict JSON, schema, key pin, day window);
- `stats-sender.test.ts`: the SDK's statistics signer and sender against the mock: the goldens are accepted and then superseded, a second key is told to reset the identity, and for every statistics fixture the SDK's own verdict equals the mock's answer.
