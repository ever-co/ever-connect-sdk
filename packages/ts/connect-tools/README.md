# @ever-co/connect-tools

Dev-only tools for Ever products that host the Ever Platform modules. A product adds this package
as a **devDependency** and keeps only its own configuration, adapter and workflow, instead of
copying either tool:

- `ever-mock-platform`: a mock of the Ever Platform API for continuous integration. It answers
  every outbound call of the modules with the platform's statuses, problem codes and response
  shapes, signs with TEST keys derived from public seeds, records every call, and makes no
  outbound request ([docs/mock-platform.md](https://github.com/ever-co/ever-connect-sdk/blob/main/docs/mock-platform.md));
- `ever-egress-audit`: proves a product makes no outbound call it should not
  ([tools/egress-audit/README.md](https://github.com/ever-co/ever-connect-sdk/blob/main/tools/egress-audit/README.md)).

## Install

```sh
npm install --save-dev @ever-co/connect-tools@next   # pnpm add -D / yarn add -D work the same way
```

`1.0.0-rc.1` is a release candidate, published under the `next` dist-tag; pin the exact version,
the same as `@ever-co/connect-sdk`.

## Use

```sh
npx ever-mock-platform --port 8080 --record artifacts/requests.jsonl
npx ever-egress-audit --config egress-audit.config.json --mode off
```

The modules are ESM (`.mjs`); the subpath exports reach them from a test:

| Import | Module |
|---|---|
| `@ever-co/connect-tools/mock-platform` | `createMockPlatform` and the rest of the mock server |
| `@ever-co/connect-tools/mock-platform/keys` | the TEST keys: `testRootEntry`, `signManifest`, `signEntitlement`, `signRotationProof`, ..., and `MOCK_ISSUER` |
| `@ever-co/connect-tools/mock-platform/crypto`, `.../validate` | the mock's signing and validation helpers |
| `@ever-co/connect-tools/egress-audit/assert`, `.../assert-call-log`, `.../static-hostnames`, `.../cloud-inference`, `.../overlay`, `.../runner` | the egress audit's building blocks |

The mock image builds from the installed package:
`docker build node_modules/@ever-co/connect-tools/dist/mock-platform`.

The mock serves plain HTTP and its documents name the https issuer `https://mock-platform.test`
(`MOCK_ISSUER`). Point the SDK at the mock's local address and pass that issuer (the client's
`issuer` option) and its TEST root (`testRootEntry()` in the file `EVER_PLATFORM_ROOT_KEYS_FILE`
names); the SDK honours all three for a local base URL only
([docs/mock-platform.md](https://github.com/ever-co/ever-connect-sdk/blob/main/docs/mock-platform.md)).

## Licence

See the [LICENSE](https://github.com/ever-co/ever-connect-sdk/blob/main/LICENSE) file at the root of the repository.
