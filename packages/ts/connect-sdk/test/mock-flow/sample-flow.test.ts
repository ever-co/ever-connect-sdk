// The sample flow of an installation, through the SDK client only, against the mock platform:
// manifest -> redeem -> token (assertion iss = the redeemed Registry id) -> entitlement verified
// -> integrations -> heartbeat -> events and ack -> tenant link -> lookup salt and vectors ->
// key-manifest rotation and a reissued document -> connect-key rotation -> disconnect -> the next
// call is 401 credential_revoked. The mock's call log must equal the documented rows.
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
// @ts-expect-error: a plain ES module of the repository tools (no type declarations).
import { createMockPlatform } from '../../../../../tools/mock-platform/src/server.mjs';
import {
  checkTestVectors,
  createEverPlatformClient,
  generateInstanceKeyPair,
  type LookupTestVectors,
  makeNodeSigner,
  ProblemError,
  signKeyRotation,
} from '../../src/index';
import { FIXTURES, fixture } from '../helpers';

// The offline fixtures and the mock share the TEST root pinned for this issuer (keys/roots.json).
const ISSUER = 'https://mock-platform.test';
const ROOTS_FILE = join(FIXTURES, 'keys', 'roots.json');

let close: (() => Promise<void>) | null = null;
afterEach(async () => {
  await close?.();
  close = null;
});

const idem = (...parts: string[]) => createHash('sha256').update(parts.join('|')).digest('hex');

describe('sample flow against the mock, through the SDK client', () => {
  it('connects, verifies, links, reads, rotates, disconnects; every call is a documented row', async () => {
    const mock = createMockPlatform({ config: { issuer: ISSUER } });
    const { url } = await mock.listen(0, '127.0.0.1');
    close = () => mock.close();
    const now = () => mock.state.now() as number;
    const admin = async (path: string, body: unknown) => {
      const res = await fetch(`${url}/__mock/${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      expect(res.status, path).toBeLessThan(300);
      return res.json();
    };

    const pair = generateInstanceKeyPair();
    let signer = makeNodeSigner(pair.privateKeyPkcs8Der);
    let registryId: string | null = null;
    const client = () =>
      createEverPlatformClient({
        baseUrl: url,
        issuer: ISSUER,
        env: { EVER_PLATFORM_ROOT_KEYS_FILE: ROOTS_FILE },
        userAgentProduct: { product: 'gauzy', version: '96.2.1' },
        signer,
        registryInstanceId: () => registryId,
        now,
      });
    let c = client();

    // Row 1: the key manifest, verified against the TEST root before anything is trusted.
    let keySet = (await c.keys.refresh()).keySet;
    expect(keySet.find('test-entitlement-1', 'entitlement', now())).not.toBeNull();

    // Row 3: redeem a connect code with the connect key.
    const redeemed = await c.connect.redeem(
      {
        code: 'EVC-TEST-0000-0001',
        product: 'gauzy',
        version: '96.2.1',
        install_source: 'self-hosted',
        kind: 'self_hosted',
        public_jwk: pair.publicJwk,
        tenant: { product_tenant_id: 'tenant-1', product_org_id: 'org-1' },
      },
      idem('redeem', 'EVC-TEST-0000-0001'),
    );
    registryId = redeemed.instance_id;
    expect(redeemed.kid).toBe(signer.kid);

    // Rows 4 and 8: the token comes lazily; the entitlement document verifies.
    const answer = await c.instances.entitlement();
    if ('notModified' in answer) throw new Error('no document');
    const first = c.verifyEntitlement(answer.document, { keySet, now: now() });
    expect(first.status).toBe('valid');
    expect(first.claims.ever.instance_id).toBe(registryId);
    expect(await c.instances.entitlement(first.seq)).toEqual({ notModified: true });

    // Rows 9, 6, 7: integrations, heartbeat, events and their acknowledgement.
    const states = await c.instances.integrations();
    expect(states.instance.stats_link?.state).toBe('available');
    await c.instances.heartbeat({ version: '96.2.1', serves_products: ['gauzy'] });
    const page = await c.instances.events(null, { waitS: 0 });
    expect(page.events.map((e) => e.type)).toContain('ever.registry.instance.connected');
    await c.instances.ackEvents(page.last_id);

    // Row 5: a tenant link.
    const link = await c.instances.tenantLinks.create(
      { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 'tenant-2' },
      idem('link', 'tenant-2'),
    );
    expect(link.id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);

    // Row 13: the lookup salt and the published vectors, reproduced.
    const salt = await c.lookup.salt();
    expect(salt.normalization_version).toBe(1);
    checkTestVectors((await c.lookup.testVectors()) as unknown as LookupTestVectors);

    // Rotation of the platform's entitlement key: the previous key still verifies the old
    // document, the reissued one has a higher seq, and the old one is stale against it.
    await admin('keys/rotate', {});
    const update = await c.keys.refresh(keySet);
    expect(update.replaced).toBe(true);
    keySet = update.keySet;
    expect(c.verifyEntitlement(first.jws, { keySet, now: now() }).kid).toBe('test-entitlement-1');
    await admin('entitlement/reissue', { instance_id: registryId });
    const again = await c.instances.entitlement(first.seq);
    if ('notModified' in again) throw new Error('no new document');
    const second = c.verifyEntitlement(again.document, { keySet, cached: { seq: first.seq, iat: first.claims.iat }, now: now() });
    expect(second.seq).toBe(first.seq + 1);
    expect(second.kid).toBe('test-entitlement-2');
    expect(() => c.verifyEntitlement(first.jws, { keySet, cached: { seq: second.seq, iat: second.claims.iat }, now: now() })).toThrow(
      expect.objectContaining({ code: 'entitlement_stale' }) as unknown as EntitlementError,
    );

    // Row 16: rotate the connect key; the next token is signed with the new key.
    const nextPair = generateInstanceKeyPair();
    const next = makeNodeSigner(nextPair.privateKeyPkcs8Der);
    const rotation = await signKeyRotation({ current: signer, next, registryInstanceId: registryId, issuer: ISSUER, now: now() });
    await c.instances.rotateKey(rotation, idem('rotate', next.kid));
    signer = next;
    c = client();
    await admin('clock', { advance: 120 }); // one heartbeat a minute at most
    await c.instances.heartbeat({ version: '96.2.1' });

    // Row 16: disconnect; the next call (its token request) is 401 credential_revoked, never retried.
    await c.instances.disconnect(idem('disconnect'));
    const revoked = await c.instances.self().catch((e) => e);
    expect(revoked).toBeInstanceOf(ProblemError);
    expect(revoked).toMatchObject({ status: 401, code: 'credential_revoked' });

    // The call log: exactly these rows, each request on a documented endpoint of its row.
    const log = (await (await fetch(`${url}/__mock/requests`)).json()) as {
      method: string;
      path_template: string;
      row: number;
      status: number;
      user_agent: string;
    }[];
    expect(log.map((x) => x.row)).toEqual([1, 3, 4, 8, 8, 9, 6, 7, 7, 5, 13, 13, 1, 8, 16, 4, 6, 16, 4]);
    const calls = fixture<{ rows: { row: number; endpoints: { method: string; path: string }[] }[] }>('../generated/outbound-calls.json');
    for (const entry of log) {
      const row = calls.rows.find((r) => r.row === entry.row);
      expect(
        row?.endpoints.some((e) => e.method === entry.method && e.path === entry.path_template),
        `${entry.method} ${entry.path_template}`,
      ).toBe(true);
      expect(entry.user_agent).toMatch(/^ever-connect-sdk\/[^ ]+ \(gauzy\/96\.2\.1\)$/);
      expect(entry.status, `${entry.method} ${entry.path_template}`).not.toBe(422);
    }
  });
});

describe('verifyEntitlementRefreshing against the mock', () => {
  it('refreshes the key set once on an unknown key id and verifies again; a second unknown id is final', async () => {
    const mock = createMockPlatform({ config: { issuer: ISSUER } });
    const { url } = await mock.listen(0, '127.0.0.1');
    close = () => mock.close();
    const now = () => mock.state.now() as number;
    const admin = (path: string, body: unknown) =>
      fetch(`${url}/__mock/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const pair = generateInstanceKeyPair();
    let registryId: string | null = null;
    const c = createEverPlatformClient({
      baseUrl: url,
      issuer: ISSUER,
      env: { EVER_PLATFORM_ROOT_KEYS_FILE: ROOTS_FILE },
      userAgentProduct: { product: 'gauzy', version: '96.2.1' },
      signer: makeNodeSigner(pair.privateKeyPkcs8Der),
      registryInstanceId: () => registryId,
      now,
    });
    const before = (await c.keys.refresh()).keySet;
    const redeemed = await c.connect.redeem(
      { code: 'EVC-TEST-0000-0001', product: 'gauzy', version: '96.2.1', install_source: 'self-hosted', public_jwk: pair.publicJwk },
      idem('redeem', 'refreshing'),
    );
    registryId = redeemed.instance_id;
    // The platform rotates its entitlement key and re-issues: the cached set does not list the new key.
    await admin('keys/rotate', {});
    await admin('entitlement/reissue', { instance_id: registryId });
    const answer = await c.instances.entitlement();
    if ('notModified' in answer) throw new Error('no document');
    // Inside 10 minutes of the fetch the set is not fetched again: the unknown id is final for now.
    await expect(c.verifyEntitlementRefreshing(answer.document, { keySet: before })).rejects.toMatchObject({ code: 'unknown_kid' });
    await admin('clock', { advance: 601 });
    const { verified, keySet } = await c.verifyEntitlementRefreshing(answer.document, { keySet: before });
    expect(verified.kid).toBe('test-entitlement-2');
    expect(keySet).not.toBe(before);
    expect(keySet.has('test-entitlement-2')).toBe(true);
  });
});
