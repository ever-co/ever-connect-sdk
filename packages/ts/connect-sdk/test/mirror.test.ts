// The apps mirror (row 15) and the install status report (row 28): the client sends the tenant
// link as `Ever-Link-Id` (optional on the mirror, Ever Platform's any_link gate; required on the
// install status), and the mirror's open vocabularies (statuses, environments, outcomes) pass
// through as the platform's contract leaves them: as strings.
import { describe, expect, it } from 'vitest';
import { createEverPlatformClient, makeNodeSigner, OPERATIONS, RequestRefusedError } from '../src/index';

const INSTANCE = '01JNE7V9J03J6XQ2WN8H0Z88R5';
const LINK = '01JHGF4PAY0P5JJ7J2A56VSRZM';
const INSTALL = '01JMQCK0INSTA11000000000A1';
const SIGNER = makeNodeSigner(new Uint8Array(32).fill(11));
const TOKEN = 'evit_secret-token-value-0006';
const BASE = 'https://api.ever.test';

interface Seen {
  readonly path: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body: unknown;
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function platform(answer: (seen: Seen) => Response = () => json(200, { results: [] })) {
  const seen: Seen[] = [];
  const fetch = (async (url: string, init: RequestInit) => {
    if (url.endsWith('/v1/instances/token')) return json(200, { access_token: TOKEN, token_type: 'Bearer', expires_in: 3600 });
    const call: Seen = {
      path: url.slice(BASE.length),
      method: init.method ?? 'GET',
      headers: Object.fromEntries(Object.entries((init.headers as Record<string, string>) ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
      body: init.body ? JSON.parse(Buffer.from(init.body as Uint8Array).toString('utf8')) : null,
    };
    seen.push(call);
    return answer(call);
  }) as unknown as typeof globalThis.fetch;
  const client = createEverPlatformClient({
    baseUrl: BASE,
    userAgentProduct: { product: 'works', version: '1.2.3' },
    signer: SIGNER,
    registryInstanceId: () => INSTANCE,
    fetch,
    now: () => 1793613600,
  });
  return { client, seen };
}

/** An app's fields the contract requires, with `extra` on top. */
const app = (extra: Record<string, unknown> = {}) => ({
  product_tenant_id: 'tenant-1',
  kind: 'app',
  name: 'Cal',
  slug: 'cal',
  base_kind: 'none',
  status: 'live',
  ...extra,
});

const upsert = (data: Record<string, unknown>, kind = 'app') => ({
  op: 'upsert' as const,
  kind: kind as 'app' | 'deployment',
  external_id: `${kind}-1`,
  external_version: 1,
  occurred_at: '2026-11-20T10:00:00Z',
  ...(kind === 'deployment' ? { app_external_id: 'app-1' } : {}),
  data,
});

describe('Ever-Link-Id on the apps mirror', () => {
  it('push sends the link it is given, and no header without one', async () => {
    const p = platform();
    const batch = { ops: [upsert(app())] } as never;
    await p.client.instances.mirrorApps.push(batch, LINK);
    await p.client.instances.mirrorApps.push(batch);
    expect(p.seen.map((s) => [s.method, s.path, s.headers['ever-link-id']])).toEqual([
      ['POST', '/v1/instances/me/mirror/apps', LINK],
      ['POST', '/v1/instances/me/mirror/apps', undefined],
    ]);
  });

  it('list sends its link filter as Ever-Link-Id too', async () => {
    const p = platform(() => json(200, { items: [], next_cursor: null }));
    await p.client.instances.mirrorApps.list(undefined, 50, LINK);
    await p.client.instances.mirrorApps.list('c1');
    expect(p.seen.map((s) => [s.path, s.headers['ever-link-id']])).toEqual([
      [`/v1/instances/me/mirror/apps?limit=50&link=${LINK}`, LINK],
      ['/v1/instances/me/mirror/apps?cursor=c1', undefined],
    ]);
  });

  it('a link that is not a tenant link id is refused before sending', async () => {
    const p = platform();
    await expect(p.client.instances.mirrorApps.push({ ops: [] } as never, 'not-a-link')).rejects.toMatchObject({
      code: 'invalid_parameter',
      errors: [{ path: 'Ever-Link-Id', code: 'pattern' }],
    });
    expect(p.seen).toEqual([]);
  });

  it('the table declares the header on every mirror operation, and requires it on the install status report', () => {
    expect(OPERATIONS.instanceMirrorApps.linkHeader).toBe('optional');
    expect(OPERATIONS.instanceListMirroredApps.linkHeader).toBe('optional');
    expect(OPERATIONS.instanceReportInstallStatus.linkHeader).toBe('required');
  });
});

describe('Ever-Link-Id on the install status report', () => {
  it('reportStatus sends the link; a call without one never leaves', async () => {
    const p = platform(() => json(200, { install_id: INSTALL, state: 'installing' }));
    await p.client.instances.installs.reportStatus(INSTALL, LINK, { state: 'installing' } as never);
    expect(p.seen.map((s) => [s.path, s.headers['ever-link-id']])).toEqual([[`/v1/installs/${INSTALL}/status`, LINK]]);
    await expect(
      p.client.call('instanceReportInstallStatus', { path: { install: INSTALL }, body: { state: 'installing' } as never }),
    ).rejects.toBeInstanceOf(RequestRefusedError);
    expect(p.seen).toHaveLength(1);
  });
});

describe('the mirror vocabularies are open, as in the platform contract', () => {
  it('a product status, environment, owner or kind the SDK does not list is sent as it is', async () => {
    const p = platform();
    const ops = [
      upsert(app({ status: 'active', kind: 'work', base_kind: 'fork', work_kind: 'portfolio' })),
      upsert({ target: 'vercel', managed_by: 'partner', environment: 'staging', status: 'INITIALIZING' }, 'deployment'),
    ];
    await p.client.instances.mirrorApps.push({ ops } as never, LINK);
    expect(p.seen).toHaveLength(1);
    expect(p.seen[0]?.body).toEqual({ ops });
  });

  it('an outcome or refusal code the SDK does not list reaches the caller unchanged', async () => {
    const results = [
      { external_id: 'app-1', outcome: 'deferred', app_id: null, code: null },
      { external_id: 'app-2', outcome: 'rejected', app_id: null, code: 'quota_exceeded' },
    ];
    const p = platform(() => json(200, { results }));
    const answer = await p.client.instances.mirrorApps.push({ ops: [upsert(app())] } as never);
    expect(answer).toEqual({ results });
  });
});
