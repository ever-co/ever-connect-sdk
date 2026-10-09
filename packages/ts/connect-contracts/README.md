# @ever-co/connect-contracts

The wire contracts between an installation of an Ever product and the Ever Platform API, generated
from the contract files of [ever-co/ever-connect-sdk](https://github.com/ever-co/ever-connect-sdk):

- TypeScript types for every request and response body (`components`, `operations`, `paths` and
  named aliases such as `RedeemRequest` or `EntitlementV1`);
- the wire constants (`CONSTANTS`, `FEED_EVENT_TYPES`), the integration definitions
  (`INTEGRATIONS`, `INTEGRATION_KEYS`), the outbound-call table (`ROWS`, `ROW_COVERAGE`), the JSON
  Schemas (`SCHEMAS`, `EVENT_SCHEMAS`) and the problem codes;
- the JSON files themselves, for tools in any language: `schemas/*`, `integrations/*` and the
  shared `fixtures/*` (signed with TEST keys derived from public seeds; they sign nothing anyone
  trusts).

No runtime dependencies, no request code, nothing runs at import. Node 20 or later; ESM and
CommonJS. Most products install [`@ever-co/connect-sdk`](https://www.npmjs.com/package/@ever-co/connect-sdk),
which depends on this package at the same version.

## Install

```sh
npm install @ever-co/connect-contracts@next   # pnpm add / yarn add work the same way
```

`1.0.0-rc.5` is a release candidate, published under the `next` dist-tag. Pin the exact version:
the contracts follow semantic versioning, and the SDK and the contracts always carry the same one.

```ts
import { CONSTANTS, INTEGRATIONS, type EntitlementV1 } from '@ever-co/connect-contracts';
import statsSchema from '@ever-co/connect-contracts/schemas/ever.stats.v1.json' with { type: 'json' };
```

## Licence

See the [LICENSE](https://github.com/ever-co/ever-connect-sdk/blob/main/LICENSE) file at the root of the repository.
