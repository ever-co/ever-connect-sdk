# @ever-co/connect-sdk

The Ever Platform client of an Ever product installation, and the pieces it is built from:

- `createEverPlatformClient`: every call an installation makes, over the operation table generated
  from the contract, behind an egress guard (only the configured base URL, no redirects, no
  cookies), with the instance token kept in memory;
- the **verifier**: `verifyKeyManifest`, `KeySet`, `verifyEntitlement` and `entitlementStatus`
  ([docs/entitlements.md](../../../docs/entitlements.md));
- the connect key and the client assertion: `generateInstanceKeyPair`, `makeNodeSigner`,
  `signClientAssertion`, `signKeyRotation`, `subjectHash`;
- lookup normalisation and hashing: `normalizeIdentifier`, `lookupHash`, `checkTestVectors`;
- `ever.usage.v1` readings: `validateUsageReading`;
- the anonymous statistics signer and sender (`signStatsReport`, `sendStatsReport`) and the
  managed-operation runner.

Nothing runs at import. Node 20 or later; ESM and CommonJS. One runtime dependency besides
`@ever-co/connect-contracts`.

## Install

Until the first release on npm, depend on the repository at a commit:

```jsonc
// package.json
"@ever-co/connect-sdk": "github:ever-co/ever-connect-sdk#<commit>&path:packages/ts/connect-sdk"
```

## The client

```ts
import { createEverPlatformClient, generateInstanceKeyPair, makeNodeSigner, KeySet } from '@ever-co/connect-sdk';

// Once: the connect key. Store the private key as a secret; never use it for statistics.
const { publicJwk, privateKeyPkcs8Der } = generateInstanceKeyPair();

const client = createEverPlatformClient({
  baseUrl: process.env.EVER_PLATFORM_API_URL!, // https (http only for a local host)
  userAgentProduct: { product: 'gauzy', version: '96.2.1' },
  signer: makeNodeSigner(privateKeyPkcs8Der),
  registryInstanceId: () => store.registryInstanceId, // null before the first redeem
});

// Connect: redeem a code the organization created in app.ever.co.
const redeemed = await client.connect.redeem(
  { code, product: 'gauzy', version: '96.2.1', install_source: 'self-hosted', public_jwk: publicJwk },
  idempotencyKey,
);
store.registryInstanceId = redeemed.instance_id;

// Keys and the entitlement document.
const { keySet } = await client.keys.refresh(store.keySet); // a refused manifest keeps the previous set
const answer = await client.instances.entitlement(store.entitlement?.seq);
if (!('notModified' in answer)) {
  const verified = client.verifyEntitlement(answer.document, { keySet, cached: store.entitlement });
  store.entitlement = { seq: verified.seq, iat: verified.claims.iat, jws: verified.jws };
}
```

Behaviour, for every call:

- the URL is the base URL plus a path of the generated table; anything else is refused before any
  I/O (`EgressRefusedError`), and a redirect is never followed;
- a write without its `Idempotency-Key`, a per-link call without its link id, a body that breaks
  its schema (unknown fields included), a statistics body over 16 KiB or a mirror batch over 4 MiB
  is refused before any I/O (`RequestRefusedError`);
- the first call that needs the instance token signs a client assertion; before the first redeem
  it throws `NotConnectedError` without sending anything; a 401 gets a new token and one retry;
  `401 credential_revoked` is answered at once;
- a non-2xx answer is a `ProblemError` (`status`, `code`, `detail`, `instance`, `errors`,
  `retryAfterS`); a 304 is `{ notModified: true }`; deadlines are 6 s for reads, 10 s for writes
  and `waitS + 5` s for the event long poll (`TimeoutError`);
- no error, `JSON.stringify` or `inspect` output carries a token, an assertion or a key.

`client.call(operationId, input)` reaches every operation of the table the namespaces do not name.

## Roots for local runs

The pinned roots are in `CONSTANTS.root_keys`, one per issuer. The `rootKeys` and `issuer`
options and `EVER_PLATFORM_ROOT_KEYS_FILE` (a JWKS of extra roots) are honoured only when the base
URL is a local host (CI against the mock platform); otherwise they are ignored with one warning.

## Lookup, usage, statistics

```ts
import { hashIdentifier, checkTestVectors, validateUsageReading } from '@ever-co/connect-sdk';

checkTestVectors(await client.lookup.testVectors()); // in CI: the published vectors
const salt = (await client.lookup.salt()).active[0];
const hash = hashIdentifier('vat', ' bg 123 456 789 ', salt); // LookupInputError: never hashed or sent
await client.lookup.query(linkId, { salt_version: salt.version, hashes: [hash.hash] });

validateUsageReading(reading); // counts and timestamps only
```

Statistics are signed with their own key (`signStatsReport`) and sent with `client.stats.sendReport`
or `sendStatsReport`: the exact bytes that were signed, never with a token.
