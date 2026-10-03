# Ever Connect SDK

Contracts, fixtures, a mock platform and an egress audit for the two optional Ever Platform
modules that Ever products ship: **anonymous usage statistics** and the **Ever Platform
connection**. Everything a product needs to build, test and prove those modules lives here, in one
place, in TypeScript and Rust:

- what the modules may send, row by row, generated from the Ever Platform API contract
  ([docs/outbound-calls.md](docs/outbound-calls.md));
- the statistics report format ([docs/stats-schema.md](docs/stats-schema.md)), the integration
  definitions and their scopes ([docs/integrations.md](docs/integrations.md)), and the signed
  entitlement and key formats ([docs/entitlements.md](docs/entitlements.md));
- fixtures every implementation must agree on, signed with TEST keys;
- a mock of the Ever Platform API for product CI ([docs/mock-platform.md](docs/mock-platform.md));
- an egress audit that proves a product makes no outbound call it should not
  ([tools/egress-audit/README.md](tools/egress-audit/README.md)).

## Layout

| Path | Content |
|---|---|
| `contracts/openapi/` | the instance-facing subset of the Ever Platform API (`ever-platform.v1.yaml`), the outbound-call rows (`rows.json`), the subset selection and the operations pending upstream |
| `contracts/schemas/` | JSON Schemas: statistics report, entitlement document, consent record, key manifest, usage report (the counts a product reports for plans priced by usage, only while `usage_reporting` is enabled), and the event feed envelope and event types |
| `contracts/integrations/` | one definition per integration (`<key>.json`), split from the vendored catalog, and the scope-version lock |
| `contracts/fixtures/` | requests, feed events, key manifests, entitlements, consent records and screens, connect vectors, statistics reports and lookup vectors, each with its expected outcome |
| `contracts/constants.json`, `contracts/VERSION` | wire constants and the contracts version |
| `contracts/generated/` | the bundled contract, the outbound-call table and the row coverage, generated |
| `packages/ts/connect-contracts` | `@ever-co/connect-contracts`: generated TypeScript types, schemas, integration definitions, constants and fixtures; no runtime dependencies |
| `packages/ts/connect-sdk` | `@ever-co/connect-sdk`: the client (every call over the generated operation table, behind the egress guard), the key manifest and entitlement verifier, the client assertion, lookup normalisation and hashing, usage readings, the statistics signer and sender, and the managed-operation runner |
| `packages/ts/connect-tools` | `@ever-co/connect-tools`: the dev-only `ever-mock-platform` and `ever-egress-audit` commands |
| `crates/ever-connect-contracts` | the same contracts for Rust: generated types, embedded schemas, definitions and constants |
| `crates/ever-connect-sdk` | the same for Rust, by feature: `client` (default), `entitlement`, `stats`, `lookup`, `usage`; without `client` it pulls no HTTP client |
| `tools/mock-platform` | the mock platform and its image |
| `tools/egress-audit` | the egress audit and its self-test |
| `tools/` | the generators and checks (`generate.mjs`, `sync-contract.mjs`, `split-integrations.mjs`, `fixtures/build-signed.mjs`, `check-schema-drift.mjs`, `check-public-safe.mjs`, `copy-draft.mjs`) and `conformance/run.mjs`, which replays non-destructive cases against a running Ever Platform API and the mock |
| `docs/` | the documentation pages; the tables in them are generated |

## Build and test

Requirements: Node 24 (`.nvmrc`) with pnpm through Corepack, the Rust toolchain pinned in
`rust-toolchain.toml`, and Docker for the mock image and the egress audit.

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm generate --check     # generated types, tables and docs equal the contract
pnpm test                 # build, every workspace test and the tool tests
cargo test --workspace
node tools/egress-audit/run.mjs --selftest   # Docker: the harness must catch its leaky control
```

How to add an integration, an outbound call or a product, and the `scope_version` rule:
[docs/extending.md](docs/extending.md).

## Versions

The contracts follow semantic versioning (`contracts/VERSION`); the packages and crates carry the
same version. A product pins one version and regenerates nothing itself.

## Security

Report a vulnerability privately through the repository's security advisories rather than in a
public issue. The TEST keys in the fixtures and the mock are derived from public seeds and sign
nothing anyone trusts.

## Licence

See the [LICENSE](LICENSE) file at the root of the repository.
