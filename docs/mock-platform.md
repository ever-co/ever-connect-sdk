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

The TEST root the product must trust is `root_keys` in `contracts/constants.json` (issuer `http://mock-platform:8080`); write it as `{"keys": [...]}` to the file `EVER_PLATFORM_ROOT_KEYS_FILE` names. The modules honour that file only for a local base URL (`docs/entitlements.md`).

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
| `lookup` | one salt version, one opted-in VAT number | lookup salts, opt-ins and claimed hashes |
| `people` | one Ever ID person, owner of the organization | people the person tokens are issued for |
| `limits` | the platform's rate limits | wrong codes per hour, heartbeat interval, entitlement reads per hour, statistics reports per day, lookup and discovery rates, device starts, webhook endpoints |
| `faults` | none | `keys_unavailable`, `webhooks_module_disabled`, `revoke_credential_at_call` |

---

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
| `POST /__mock/faults` | `{keys_unavailable?, webhooks_module_disabled?, revoke_credential_at_call?}` | switches faults on and off |
| `POST /__mock/person-request` | `{kind: deletion \| export, …}` | a deletion or export request for a person on the feed |

---

## 5. Scenarios the SDK tests run

The mock's own tests (`tools/mock-platform/test/`) are the reference for how to drive it:

- `rows.test.mjs`: the good path of every operation and every documented `(status, code)` pair, with every success answer validated against the contract's response schema;
- `sample-flow.test.ts`: connect, link, entitlement, feed and statistics in the order a product runs them;
- `in-product-consent.test.mjs`: the consent dialog after a fresh Ever ID sign-in;
- `managed.test.mjs`: scenario `managed-backup`, a fixture executor on the SDK's managed-operation runner.
