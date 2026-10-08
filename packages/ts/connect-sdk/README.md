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
  managed-operation runner;
- the compact JWS helpers for what a product signs or reads back itself: `signCompactJws`
  (EdDSA over Ed25519 only) and `claimsOfVerifiedJws` (the claims of a document you already
  verified; it never verifies).

Nothing runs at import. Node 20 or later; ESM and CommonJS. One runtime dependency besides
`@ever-co/connect-contracts`.

## Install

```sh
npm install @ever-co/connect-sdk@next                     # pnpm add / yarn add work the same way
npm install --save-dev @ever-co/connect-tools@next        # the mock platform and the egress audit, for tests
```

`1.0.0-rc.1` is a release candidate, published under the `next` dist-tag with npm provenance. Pin
the exact version; the SDK depends on `@ever-co/connect-contracts` at the same version, so there is
nothing else to add:

```jsonc
// package.json of the product
"dependencies": { "@ever-co/connect-sdk": "1.0.0-rc.1" },
"devDependencies": { "@ever-co/connect-tools": "1.0.0-rc.1" }
```

Do not copy the sources into a product: depend on the package, so every product verifies with the
same code and picks up fixes by bumping one version.

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

// Keys: a stored set is verified again after a restart, for this client's issuer only.
const stored = store.keySet ? KeySet.restore(store.keySet, { issuer: client.issuer }) : undefined;
let { keySet } = await client.keys.refresh(stored); // a refused manifest keeps the previous set

// The entitlement document: when the manifest expired, or on an unknown key id (at most every
// 10 minutes), the set is refreshed and the document verified again.
const answer = await client.instances.entitlement(store.entitlement?.seq);
if (!('notModified' in answer)) {
  const result = await client.verifyEntitlementRefreshing(answer.document, { keySet, cached: store.entitlement });
  store.entitlement = { seq: result.verified.seq, iat: result.verified.claims.iat, jws: result.verified.jws };
  keySet = result.keySet;
}
store.keySet = keySet.toJSON();
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
- the entitlement reads keep the platform's account (a bucket of 6 per path, one back every
  10 minutes; a 429's `Retry-After`): a read the platform would refuse is held back without being
  sent (`RateLimitedError` with `retryAfterS`);
- a non-2xx answer is a `ProblemError` (`status`, `code`, `detail`, `instance`, `errors`,
  `retryAfterS`, and `lastId` for `410 resync_required`); a 304 is `{ notModified: true }`;
  deadlines are 6 s for reads, 10 s for writes and `waitS + 5` s for the event long poll
  (`TimeoutError`);
- no error, `JSON.stringify` or `inspect` output carries a token, an assertion or a key.

`client.call(operationId, input)` reaches every operation of the table the namespaces do not name.

The event feed answers `410 resync_required` when the cursor is older than what Ever Platform keeps;
the error carries where to continue (`lastId`):

```ts
import { ProblemError } from '@ever-co/connect-sdk';

try {
  const page = await client.instances.events(store.feedCursor, { waitS: 25 });
  // ... handle page.events, then ack page.last_id and store it
} catch (error) {
  if (!(error instanceof ProblemError && error.status === 410 && error.code === 'resync_required')) throw error;
  await rereadState(); // the integration states and the entitlement documents, through REST
  if (error.lastId) await client.instances.ackEvents(error.lastId);
  store.feedCursor = error.lastId ?? null; // no position named: read the feed again from its start
}
```

## Compact JWS helpers

```ts
import { CONSTANTS, claimsOfVerifiedJws, signCompactJws } from '@ever-co/connect-sdk';

// The stats_link statement, signed with the statistics key (a StatsSigner, an InstanceSigner, or
// any function that answers the 64-byte Ed25519 signature of the bytes it is given).
const statement = await signCompactJws(statsSigner, { typ: CONSTANTS.stats_link_typ }, claims);

// The claims of an entitlement document stored after verifyEntitlement accepted it, to show them.
const shown = claimsOfVerifiedJws(store.entitlement.jws);
```

`signCompactJws` always writes `alg: EdDSA` first and refuses a header that names another `alg` or
`crit`, a signature that is not 64 bytes, and anything the verifiers would not decode.
`claimsOfVerifiedJws` **never verifies**: it is for documents the verifier accepted before they were
stored, never for a document just received (verify that one; the verifier answers its claims).

## Roots for local runs

The pinned roots are in `CONSTANTS.root_keys`, one per issuer; no TEST root is pinned. The
`rootKeys` and `issuer` options and `EVER_PLATFORM_ROOT_KEYS_FILE` (a JWKS of extra roots, each
with its `iss`) are honoured only when the base URL is a local host (CI against the mock
platform); otherwise they are ignored with one warning.

`verifyKeyManifest` and `KeySet.verify` / `restore` / `update` require the `issuer` option;
their `unsafeRootKeys` option replaces the pinned roots and is for tests and offline tools only.
A `KeySet` comes only from those calls or `client.keys.refresh`; `verifyEntitlement` refuses any
other object.

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
