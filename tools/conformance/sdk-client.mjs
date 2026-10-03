#!/usr/bin/env node
/**
 * sdk-client: runs the TypeScript SDK (its client, verifier, assertion and statistics signer)
 * against a running Ever Platform API and reports what each step answered. The platform is the
 * reference: a difference is fixed in the SDK or filed against the platform's contract.
 *
 *   node tools/conformance/sdk-client.mjs --target <base URL> --roots <JWKS file>
 *        [--issuer <origin>] [--code <connect code>] [--json]
 *
 * --roots names the target's root public key(s) (for a local build, the root it was given), passed
 * as EVER_PLATFORM_ROOT_KEYS_FILE: honoured only for a local base URL. --code (a connect code the
 * target issued) runs the connected flow too: redeem, token, the installation, integrations,
 * heartbeat, events, entitlement, disconnect, and the 401 that follows.
 *
 * Needs the packages built (`pnpm --filter @ever-co/connect-sdk build`). Exit 0 when every step
 * answered as expected, 1 otherwise.
 */
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const sdk = await import(
  join(here, '..', '..', 'packages', 'ts', 'connect-sdk', 'dist', 'index.js')
    .replace(/\\/g, '/')
    .replace(/^([A-Za-z]):/, 'file:///$1:')
);
const {
  createEverPlatformClient,
  generateInstanceKeyPair,
  makeNodeSigner,
  verifyKeyManifest,
  signStatsReport,
  statsSignerFromSeed,
  ProblemError,
  KeyManifestError,
} = sdk;

const arg = (name, fallback = null) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
};
const target = arg('target');
const rootsFile = arg('roots');
if (!target || !rootsFile) {
  process.stderr.write('usage: sdk-client.mjs --target <base URL> --roots <JWKS file> [--issuer <origin>] [--code <code>] [--json]\n');
  process.exit(2);
}
const issuer = arg('issuer');
const code = arg('code');

const steps = [];
const step = async (name, expected, fn) => {
  let got;
  try {
    got = (await fn()) ?? 'ok';
  } catch (error) {
    got =
      error instanceof ProblemError
        ? `${error.status} ${error.code}`
        : error instanceof KeyManifestError
          ? `manifest ${error.code}`
          : error?.code
            ? `${error.name} ${error.code}`
            : `error ${error?.message ?? error}`;
  }
  const ok = Array.isArray(expected) ? expected.includes(got) : got === expected;
  steps.push({ name, expected: Array.isArray(expected) ? expected.join(' | ') : expected, got, ok });
  return got;
};

let sent = 0;
const counting = (url, init) => {
  sent += 1;
  return fetch(url, init);
};
const UNKNOWN_INSTANCE = '01JNCQNF0RMANCE0000000000Z';
const pair = generateInstanceKeyPair();
let registryId = null;
const client = (o = {}) =>
  createEverPlatformClient({
    baseUrl: target,
    userAgentProduct: { product: 'gauzy', version: '96.2.1' },
    signer: makeNodeSigner(pair.privateKeyPkcs8Der),
    registryInstanceId: () => registryId,
    env: { EVER_PLATFORM_ROOT_KEYS_FILE: rootsFile },
    ...(issuer ? { issuer } : {}),
    fetch: counting,
    ...o,
  });
const c = client();

// The key manifest: verified against the target's root; never against the pinned roots alone.
let manifest = null;
await step('key manifest verifies against the target root', 'ok', async () => {
  manifest = await c.keys.manifest();
  return manifest.keys.length > 0 ? 'ok' : 'no keys';
});
await step('the same manifest with the pinned roots only', 'manifest unknown_root', async () => {
  verifyKeyManifest(manifest?.document ?? {}, { issuer: c.issuer });
  return 'ok';
});
await step('every purpose has an active key', 'ok', async () => {
  const purposes = new Set((manifest?.keys ?? []).filter((k) => k.state === 'active').map((k) => k.ever_purpose));
  return ['assertion', 'intent', 'entitlement'].every((p) => purposes.has(p)) ? 'ok' : `active: ${[...purposes].join(',')}`;
});

await step('legal texts', ['ok', '503 unavailable'], async () => {
  await c.connect.legal();
});

await step('no Registry id: refused before any request', 'NotConnectedError no_registry_instance_id', async () => {
  const before = sent;
  const answer = await c.instances.integrations().catch((error) => error);
  if (sent !== before) return 'a request was sent';
  throw answer;
});
await step('a UUID never authenticates (refused before signing)', 'AssertionError not_a_registry_id', async () => {
  registryId = randomUUID();
  try {
    await client().instances.integrations();
  } finally {
    registryId = null;
  }
});
await step('an assertion for an unknown installation', '401 invalid_client', async () => {
  registryId = UNKNOWN_INSTANCE;
  try {
    await client().instances.integrations();
  } finally {
    registryId = null;
  }
});
await step('a code that does not exist', ['422 code_invalid', '404 not_found'], async () => {
  await c.connect.redeem(
    { code: 'EVC-0000-0000-0000', product: 'gauzy', version: '96.2.1', install_source: 'self-hosted', public_jwk: pair.publicJwk },
    randomUUID(),
  );
});

// Statistics: a golden report under a fresh statistics id and key, signed and sent by the SDK.
await step('a signed statistics report', 'ok', async () => {
  const report = JSON.parse(readFileSync(join(here, '..', '..', 'contracts', 'fixtures', 'stats', 'valid', 'gauzy.json'), 'utf8'));
  report.instance_id = randomUUID();
  report.report_id = randomUUID();
  report.sent_at = new Date().toISOString().slice(0, 10);
  const seed = createHash('sha256').update(`ever-connect-sdk/conformance/stats/${report.instance_id}`).digest();
  const signed = await signStatsReport(report, statsSignerFromSeed(new Uint8Array(seed)));
  const answer = await c.stats.sendReport(signed);
  return answer?.accepted === true ? 'ok' : JSON.stringify(answer);
});

if (code) {
  let doc = null;
  await step('redeem the code', 'ok', async () => {
    const r = await c.connect.redeem(
      { code, product: 'gauzy', version: '96.2.1', install_source: 'self-hosted', public_jwk: pair.publicJwk },
      createHash('sha256').update(code).digest('hex'),
    );
    registryId = r.instance_id;
    return r.kid === makeNodeSigner(pair.privateKeyPkcs8Der).kid ? 'ok' : 'another kid';
  });
  await step('the installation (token from the SDK assertion)', 'ok', async () => {
    const me = await c.instances.self();
    return me?.id === registryId || me?.instance_id === registryId || me ? 'ok' : 'no body';
  });
  await step('integration states', 'ok', async () => {
    await c.instances.integrations();
  });
  await step('heartbeat', 'ok', async () => {
    await c.instances.heartbeat({ version: '96.2.1', serves_products: ['gauzy'] });
  });
  await step('events (no wait) and their acknowledgement', 'ok', async () => {
    const page = await c.instances.events(null, { waitS: 0 });
    await c.instances.ackEvents(page.last_id);
  });
  await step('entitlement document', ['ok', '404 not_found'], async () => {
    const a = await c.instances.entitlement();
    if ('notModified' in a) return 'not modified';
    doc = a.document;
  });
  if (doc && manifest) {
    const { KeySet } = sdk;
    await step('the document verifies', 'ok', async () => {
      const keySet = KeySet.fromManifest(manifest);
      c.verifyEntitlement(doc, { keySet });
    });
  }
  await step('disconnect', 'ok', async () => {
    await c.instances.disconnect(randomUUID());
  });
  await step('the next call after the disconnect', '401 credential_revoked', async () => {
    await c.instances.self();
  });
}

if (process.argv.includes('--json')) process.stdout.write(`${JSON.stringify({ target, steps }, null, 2)}\n`);
else {
  for (const s of steps) process.stdout.write(`${s.ok ? 'ok  ' : 'DIFF'}  ${s.name}: ${s.got}${s.ok ? '' : ` (expected ${s.expected})`}\n`);
  const bad = steps.filter((s) => !s.ok).length;
  process.stdout.write(`sdk-client: ${steps.length - bad}/${steps.length} as expected against ${target}\n`);
}
process.exit(steps.every((s) => s.ok) ? 0 : 1);
