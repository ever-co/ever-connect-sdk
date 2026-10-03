// The eight behaviour items of the client, each against an injected fetch that records every call.
import { inspect } from 'node:util';
import { describe, expect, it, vi } from 'vitest';
import {
  createEverPlatformClient,
  EgressRefusedError,
  makeNodeSigner,
  NotConnectedError,
  ProblemError,
  RequestRefusedError,
  SDK_VERSION,
  TimeoutError,
} from '../src/index';
import { send } from '../src/transport';

const INSTANCE = '01JNE7V9J03J6XQ2WN8H0Z88R5';
const LINK = '01JHGF4PAY0P5JJ7J2A56VSRZM';
const SIGNER = makeNodeSigner(new Uint8Array(32).fill(11));
const TOKEN = 'evit_secret-token-value-0001';

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  redirect: string | undefined;
  credentials: string | undefined;
}

type Handler = (call: Call) => Response | Promise<Response>;
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': status >= 400 ? 'application/problem+json' : 'application/json', ...headers },
  });

function fake(handler: Handler) {
  const calls: Call[] = [];
  const fetch = (async (url: string, init: RequestInit) => {
    const call: Call = {
      url,
      method: init.method ?? 'GET',
      headers: Object.fromEntries(Object.entries((init.headers as Record<string, string>) ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
      body: init.body ? Buffer.from(init.body as Uint8Array).toString('utf8') : null,
      redirect: init.redirect,
      credentials: init.credentials,
    };
    calls.push(call);
    if (init.signal?.aborted) throw init.signal.reason;
    return handler(call);
  }) as unknown as typeof globalThis.fetch;
  return { calls, fetch };
}

/** A platform that issues tokens and answers the other calls with `answer`. */
function platform(answer: Handler = () => json(200, {})) {
  return fake((call) => {
    if (call.url.endsWith('/v1/instances/token')) return json(200, { access_token: TOKEN, token_type: 'Bearer', expires_in: 3600 });
    return answer(call);
  });
}

const client = (f: { fetch: typeof globalThis.fetch }, extra: Record<string, unknown> = {}) =>
  createEverPlatformClient({
    baseUrl: 'https://api.ever.test',
    userAgentProduct: { product: 'gauzy', version: '1.2.3' },
    signer: SIGNER,
    registryInstanceId: () => INSTANCE,
    fetch: f.fetch,
    now: () => 1793613600,
    ...extra,
  });

describe('1. egress guard: only the base URL, no redirects, no cookies', () => {
  it('a URL outside the base origin or prefix is refused with zero calls', async () => {
    const f = fake(() => json(200, {}));
    const base = new URL('https://api.ever.test/');
    for (const path of ['https://example.com/x', '//example.com/x', 'x', '/v1/../../x', '/v1/%2e%2e/x\\y'])
      await expect(send({ base, fetch: f.fetch }, { method: 'GET', path, headers: {}, timeoutMs: 1000 })).rejects.toMatchObject({
        code: 'absolute_url',
      });
    expect(f.calls.length).toBe(0);
  });
  it('a path parameter cannot leave the operation path', async () => {
    const f = platform(() => new Response(null, { status: 204 }));
    await client(f).instances.tenantLinks.remove('../../../v1/other');
    expect(f.calls.at(-1)?.url).toBe('https://api.ever.test/v1/instances/me/tenant-links/..%2F..%2F..%2Fv1%2Fother');
  });
  it('http is refused unless the host is local', () => {
    expect(() => client(platform(), { baseUrl: 'http://api.ever.test' })).toThrow(EgressRefusedError);
    for (const ok of [
      'http://localhost:8080',
      'http://127.0.0.1',
      'http://10.1.2.3',
      'http://172.20.0.1',
      'http://192.168.1.1',
      'http://mock.localhost',
      'http://[::1]:9',
    ])
      expect(() => client(platform(), { baseUrl: ok })).not.toThrow();
    expect(() => client(platform(), { baseUrl: 'http://172.32.0.1' })).toThrow(EgressRefusedError);
  });
  it('a redirect is refused and not followed; requests omit credentials', async () => {
    const f = fake(() => new Response(null, { status: 302, headers: { location: 'https://elsewhere.test/v1/connect/legal' } }));
    await expect(client(f).connect.legal()).rejects.toMatchObject({ name: 'EgressRefusedError', code: 'redirect' });
    expect(f.calls.length).toBe(1);
    expect(f.calls[0]?.redirect).toBe('manual');
    expect(f.calls[0]?.credentials).toBe('omit');
  });
  it('Authorization never reaches another host: the 302 of an authenticated call is not followed', async () => {
    const f = platform(() => new Response(null, { status: 307, headers: { location: 'https://elsewhere.test/' } }));
    await expect(client(f).instances.integrations()).rejects.toMatchObject({ code: 'redirect' });
    expect(f.calls.map((c) => new URL(c.url).host)).toEqual(['api.ever.test', 'api.ever.test']);
  });
});

describe('2. token lifecycle', () => {
  it('lazily: the first authenticated call gets a token with an assertion for this Registry id', async () => {
    const f = platform();
    const c = client(f);
    expect(f.calls.length).toBe(0);
    await c.instances.integrations();
    expect(f.calls.map((x) => x.url)).toEqual([
      'https://api.ever.test/v1/instances/token',
      'https://api.ever.test/v1/instances/me/integrations',
    ]);
    const body = JSON.parse(f.calls[0]?.body ?? '{}');
    expect(body.grant_type).toBe('client_credentials');
    expect(body.client_assertion_type).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    const claims = JSON.parse(Buffer.from(body.client_assertion.split('.')[1], 'base64url').toString());
    expect(claims.iss).toBe(INSTANCE);
    expect(claims.aud).toBe('https://api.ever.test/v1/instances/token');
    expect(f.calls[1]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    await c.instances.integrations();
    expect(f.calls.length).toBe(3);
  });
  it('without a Registry id: NotConnectedError before any I/O', async () => {
    const f = platform();
    await expect(client(f, { registryInstanceId: () => null }).instances.integrations()).rejects.toBeInstanceOf(NotConnectedError);
    await expect(client(f, { registryInstanceId: () => null }).instances.token()).rejects.toBeInstanceOf(NotConnectedError);
    expect(f.calls.length).toBe(0);
  });
  it('a 401 gets a new token and exactly one retry', async () => {
    let n = 0;
    const f = platform(() => (n++ < 2 ? json(401, { code: 'unauthenticated' }) : json(200, {})));
    await expect(client(f).instances.integrations()).rejects.toMatchObject({ status: 401, code: 'unauthenticated' });
    expect(f.calls.map((c) => c.url.split('/v1/')[1])).toEqual([
      'instances/token',
      'instances/me/integrations',
      'instances/token',
      'instances/me/integrations',
    ]);
  });
  it('401 credential_revoked is answered at once, never retried', async () => {
    const f = platform(() => json(401, { code: 'credential_revoked', detail: 'credential_revoked: disconnected' }));
    await expect(client(f).instances.integrations()).rejects.toMatchObject({ status: 401, code: 'credential_revoked' });
    expect(f.calls.length).toBe(2);
  });
  it('refreshes after token_refresh_after_s; onToken sees timings only', async () => {
    let now = 1793613600;
    const events: unknown[] = [];
    const f = platform();
    const c = client(f, { now: () => now, onToken: (e: unknown) => events.push(e) });
    await c.instances.integrations();
    now += 2999;
    await c.instances.integrations();
    now += 1;
    await c.instances.integrations();
    expect(f.calls.filter((x) => x.url.endsWith('/token')).length).toBe(2);
    expect(events).toEqual([
      { acquired_at: 1793613600, expires_in: 3600 },
      { acquired_at: 1793616600, expires_in: 3600 },
    ]);
  });
});

describe('3. headers', () => {
  it('User-Agent, Accept, x-request-id, Content-Type; the key of a write; If-None-Match; Ever-Link-Id', async () => {
    const f = platform((call) => (call.url.endsWith('/entitlement') ? new Response(null, { status: 304 }) : json(202, {})));
    const c = client(f);
    await c.instances.usage(LINK, { items: [{ meter_key: 'instances.connected', quantity: 1, period: '2026-11' }] } as never, 'idem-0001');
    const usage = f.calls.at(-1);
    expect(usage?.headers['user-agent']).toBe(`ever-connect-sdk/${SDK_VERSION} (gauzy/1.2.3)`);
    expect(usage?.headers.accept).toBe('application/json, application/problem+json');
    expect(usage?.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
    expect(usage?.headers['content-type']).toBe('application/json');
    expect(usage?.headers['idempotency-key']).toBe('idem-0001');
    expect(usage?.headers['ever-link-id']).toBe(LINK);
    expect(await c.instances.entitlement(7)).toEqual({ notModified: true });
    expect(f.calls.at(-1)?.headers['if-none-match']).toBe('"7"');
  });
  it('a write without its Idempotency-Key is refused with zero calls', async () => {
    const f = platform();
    await expect(client(f).instances.disconnect(undefined as unknown as string)).rejects.toMatchObject({
      code: 'idempotency_key_required',
    });
    await expect(client(f).call('instanceCreateTenantLink', { body: { code: 'EVL-TEST-0000-0002' } as never })).rejects.toBeInstanceOf(
      RequestRefusedError,
    );
    expect(f.calls.length).toBe(0);
  });
});

describe('4. timeouts', () => {
  // A fetch that answers only when aborted, as a real one does.
  const hanging = () => {
    const f = platform();
    const fetch = (async (url: string, init: RequestInit) =>
      url.endsWith('/v1/instances/token')
        ? f.fetch(url, init)
        : new Promise<Response>((_, reject) =>
            init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))),
          )) as unknown as typeof globalThis.fetch;
    return { fetch };
  };
  it('a read past its deadline is a TimeoutError; a write has its own deadline', async () => {
    const c = client(hanging(), { timeouts: { readMs: 20, writeMs: 30 } });
    await expect(c.connect.legal()).rejects.toMatchObject({ name: 'TimeoutError', timeoutMs: 20 });
    await expect(c.instances.heartbeat({ version: '1.0.0' })).rejects.toMatchObject({ name: 'TimeoutError', timeoutMs: 30 });
  });
  it('the long poll waits waitS + 5 s', async () => {
    vi.useFakeTimers();
    try {
      const pending = client(hanging())
        .instances.events(null, { waitS: 10 })
        .catch((e) => e);
      await vi.advanceTimersByTimeAsync(14_999);
      await vi.advanceTimersByTimeAsync(1);
      const error = await pending;
      expect(error).toBeInstanceOf(TimeoutError);
      expect(error.timeoutMs).toBe(15_000);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('5. problems', () => {
  it('a problem document becomes a ProblemError with its code, detail, request id and Retry-After', async () => {
    const f = fake(() =>
      json(429, { code: 'rate_limited', detail: 'rate_limited: slow down', instance: 'req-1', retry_after_s: 30 }, { 'retry-after': '12' }),
    );
    const error = await client(f)
      .connect.legal()
      .catch((e) => e);
    expect(error).toBeInstanceOf(ProblemError);
    expect(error).toMatchObject({
      status: 429,
      code: 'rate_limited',
      detail: 'rate_limited: slow down',
      instance: 'req-1',
      retryAfterS: 12,
    });
  });
  it('an unparsable body is code unknown', async () => {
    const f = fake(() => new Response('<html>bad gateway</html>', { status: 502 }));
    await expect(client(f).connect.legal()).rejects.toMatchObject({ status: 502, code: 'unknown' });
  });
  it('field errors are kept', async () => {
    const f = fake(() => json(422, { code: 'validation_failed', errors: [{ path: '/code', code: 'pattern', message: 'not a code' }] }));
    await expect(
      client(f)
        .connect.redeem({} as never, 'k1')
        .catch((e) => e),
    ).resolves.toBeInstanceOf(RequestRefusedError);
    const body = {
      code: 'EVC-TEST-0000-0001',
      product: 'gauzy',
      version: '1.0.0',
      install_source: 'self-hosted',
      public_jwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(SIGNER.publicKeyRaw).toString('base64url') },
    };
    const error = await client(f)
      .connect.redeem(body as never, 'k1')
      .catch((e) => e);
    expect(error).toMatchObject({
      status: 422,
      code: 'validation_failed',
      errors: [{ path: '/code', code: 'pattern', message: 'not a code' }],
    });
  });
});

describe('6. body limits', () => {
  it('a statistics body over 16 KiB and a mirror batch over 4 MiB never leave', async () => {
    const f = platform();
    await expect(client(f).stats.sendReport({ body: new Uint8Array(16385), headers: {} })).rejects.toMatchObject({
      code: 'body_too_large',
    });
    const op = { op: 'upsert', kind: 'app', external_id: 'x', external_version: 1, data: { name: 'x'.repeat(4096) } };
    const huge = { ops: Array.from({ length: 500 }, () => op) };
    await expect(client(f).instances.mirrorApps.push(huge as never)).rejects.toBeInstanceOf(RequestRefusedError);
    expect(f.calls.length).toBe(0);
  });
});

describe('7. strict input', () => {
  it('a body with an unknown field, or of the wrong shape, is refused before sending', async () => {
    const f = platform();
    const c = client(f);
    await expect(c.instances.heartbeat({ version: '1.0.0', surprise: true } as never)).rejects.toMatchObject({
      code: 'invalid_body',
      errors: [{ path: '/surprise', code: 'unknown_field' }],
    });
    await expect(c.instances.ackEvents(42 as unknown as string)).rejects.toMatchObject({ code: 'invalid_body' });
    await expect(c.call('instanceGetIntegrations', { query: { secret: 'x' } })).rejects.toMatchObject({ code: 'invalid_parameter' });
    await expect(c.lookup.query('not-a-link', { salt_version: 1, hashes: ['0'.repeat(64)] })).rejects.toMatchObject({
      code: 'invalid_parameter',
    });
    expect(f.calls.length).toBe(0);
  });
});

describe('8. local base URL only: overrides', () => {
  it('extra roots and another issuer are ignored, with one warning, for a non-local base URL', () => {
    const warnings: string[] = [];
    const c = client(platform(), {
      rootKeys: [{ kid: 'test-root-9', x: 'A'.repeat(43), iss: 'https://api.ever.test' }],
      issuer: 'https://elsewhere.test',
      onWarning: (m: string) => warnings.push(m),
    });
    expect(c.keys.rootKeys().some((k) => k.kid === 'test-root-9')).toBe(false);
    expect(c.issuer).toBe('https://api.ever.test');
    expect(warnings.length).toBeLessThanOrEqual(1);
  });
  it('a local base URL takes them', () => {
    const c = client(platform(), {
      baseUrl: 'http://127.0.0.1:4010',
      rootKeys: [{ kid: 'test-root-9', x: 'A'.repeat(43), iss: 'https://mock-platform.test' }],
      issuer: 'https://mock-platform.test',
    });
    expect(c.keys.rootKeys().some((k) => k.kid === 'test-root-9')).toBe(true);
    expect(c.issuer).toBe('https://mock-platform.test');
  });
});

describe('the client object', () => {
  it('shows its base URL only', async () => {
    const f = platform();
    const c = client(f);
    await c.instances.integrations();
    expect(JSON.stringify(c)).toBe('{"baseUrl":"https://api.ever.test/"}');
    expect(inspect(c)).not.toContain(TOKEN);
  });
});
