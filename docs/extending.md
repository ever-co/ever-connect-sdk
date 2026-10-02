# Extending the contracts

**Audience:** engineers changing what the Ever Platform modules may send: a new integration, a new product, a new outbound call.

Everything in this repository is derived from a few hand-kept files and the Ever Platform contract they were synchronised from. Change those, regenerate, and continuous integration refuses anything that drifted.

| Hand-kept | What it holds |
|---|---|
| `contracts/openapi/sync.config.json` | which operations of the Ever Platform API belong to the instance-facing subset |
| `contracts/openapi/rows.json` | the outbound-call rows: title, operations, module, group, integration, trigger, payload, cadence, how to disable, products, phase and the documented `(status, code)` pairs |
| `contracts/openapi/pending-upstream.json` | operations and problem codes the modules need before the Ever Platform API publishes them |
| `contracts/integrations/overrides.json` | corrections applied when the vendored integration catalog disagrees with another contract |
| `contracts/constants.json` | wire constants and defaults (the contract-derived fields are refreshed by the tools) |
| `contracts/VERSION` | the contracts version |

Everything else under `contracts/` (the OpenAPI subset, the vendored schemas and catalog, one definition file per integration, the fixtures) and every generated type is written by the tools below.

---

## 1. Regenerate

```sh
EVER_PLATFORM_REPO=../platform pnpm sync   # the subset, the vendored schemas and catalog, VENDOR.json
node tools/split-integrations.mjs          # one definition per integration, constants, the scope lock
pnpm fixtures                              # the signed fixtures (TEST keys from public seeds)
pnpm generate                              # TypeScript and Rust types, rows, docs regions, generated.lock
pnpm test && cargo test --workspace
```

Each tool has a `--check` mode, and continuous integration runs them: `generate-check` (types, docs regions, integration definitions, fixtures and the vendored hashes), `contract-sync` (the subset and the vendored files equal the platform at the commit recorded in `contracts/VENDOR.json`), `ts`, `rust`, `fixtures-roundtrip` (TypeScript and Rust agree on every fixture), `mock-rows` and `tools`.

---

## 2. Add or change an integration definition

Integration definitions are data. The platform keeps the catalog; this repository vendors it (`contracts/integrations/catalog.v1.json`) and splits it into `contracts/integrations/<key>.json`, the files products and the consent screens read.

1. Change the catalog in the platform repository (a new row, or a change to an existing one): `key` (snake_case, stable forever), `name`, `description`, `direction`, `defaults` and `availability` for Ever Cloud and self-hosted installations, `requires_feature`, `products`, `scope_version`, `revoke_effect` and the `scope` rows (`field_path`, `direction`, `form`, `frequency`, `required`, `purpose`, `retention`).
2. Synchronise, split and regenerate (section 1). A key with `status: hidden` gets no definition file.
3. `requires_feature` must name a key of the entitlement document's `features` (or be `null`). When the catalog uses another name, `overrides.json` maps it, with the reason, until the catalog is corrected.

### The `scope_version` rule

The `scope` is what the consent screen shows and the only data the integration may move. **Any change to `scope` needs a higher `scope_version`**, because the change needs a new consent: an existing consent covers only the version it was given for, and the row shows *re-consent required*. `tools/split-integrations.mjs` enforces it with `contracts/integrations/scope-versions.lock.json`, which pins the SHA-256 of every scope with its version:

- a changed scope with the same `scope_version` is refused;
- a `scope_version` never goes down;
- a changed scope with a higher `scope_version` passes and moves the pin.

Wording-only changes outside `scope` (`name`, `description`, `revoke_effect`) do not need a bump.

---

## 3. Add or change an outbound call

1. The operation must exist in the Ever Platform API contract. Until it does, describe it in `pending-upstream.json` (method, path, request schema, the row it belongs to); the row then shows *pending upstream* in the generated table and the mock answers it.
2. Add the operation to `sync.config.json` (`include_operation_ids`) and the row to `rows.json`, with every `(status, code)` pair the platform documents for it.
3. Synchronise and regenerate. The generator refuses a row without a trigger, payload, cadence or way to disable it, an operation without its row, and a request body without a schema.
4. Teach the mock platform the operation (`tools/mock-platform/src/routes/`) and add a scenario for its good path and for every pair (`tools/mock-platform/test/scenarios.mjs`). `rows.test.mjs` fails on any pair without a scenario, and every success answer is validated against the response schema.
5. If a mode of the egress audit should see the row, add it to `tools/egress-audit/modes.json`. `every_trigger` follows the generated list on its own.

`docs/outbound-calls.md` is regenerated from `rows.json`: a request the modules can make and the page does not list fails the build.

---

## 4. Add a product

1. The product code joins `ProductCode` in the Ever Platform API contract and the statistics schema gains its branch (both upstream), then synchronise.
2. Add it to the `products` of the rows and integrations it takes part in.
3. Give the mock platform a connect code for it (`codes` in its configuration) if the product's continuous integration connects.
4. Products keep only their own pieces: an egress audit config and adapter (`tools/egress-audit/README.md`), the product prefix of the environment variables (`env_prefix`, for example `TR_EVER_`), and their scenarios. The harness, the mock and the contracts come from the packages.

---

## 5. Versions

`contracts/VERSION` follows semantic versioning. A new optional field, a new row, a new integration or a new problem code is a minor change; removing or renaming anything a product reads, or narrowing what the platform accepts, is a major change. The generated `constants.contracts_version` carries the value into both languages.
