// No secret in logs, errors, toString(), JSON.stringify or inspect output: the instance token,
// the client assertion, the private key, a client secret, and the claims of a document.
import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createEverPlatformClient,
  EntitlementError,
  KeySet,
  makeNodeSigner,
  ProblemError,
  type RootKey,
  verifyEntitlement,
} from '../src/index';
import { redact } from '../src/transport';
import { fixture, fixtureText } from './helpers';

const INSTANCE = '01JNE7V9J03J6XQ2WN8H0Z88R5';
const TOKEN = 'evit_secret-token-value-0002';
const SEED = new Uint8Array(32).fill(11);
const SIGNER = makeNodeSigner(SEED);

const logged: string[] = [];
beforeEach(() => {
  logged.length = 0;
  for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const)
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      logged.push(args.map((a) => (typeof a === 'string' ? a : inspect(a, { depth: 8 }))).join(' '));
    });
});
afterEach(() => vi.restoreAllMocks());

function run(answer: (url: string, body: string) => Response) {
  const assertions: string[] = [];
  const fetch = (async (url: string, init: RequestInit) => {
    const body = init.body ? Buffer.from(init.body as Uint8Array).toString() : '';
    if (url.endsWith('/v1/instances/token')) {
      assertions.push(JSON.parse(body).client_assertion);
      return new Response(JSON.stringify({ access_token: TOKEN, token_type: 'Bearer', expires_in: 3600 }), { status: 200 });
    }
    return answer(url, body);
  }) as unknown as typeof globalThis.fetch;
  const client = createEverPlatformClient({
    baseUrl: 'https://api.ever.test',
    userAgentProduct: { product: 'works', version: '1.0.0' },
    signer: SIGNER,
    registryInstanceId: () => INSTANCE,
    fetch,
  });
  return { client, assertions };
}

const everything = (...values: unknown[]) =>
  [...values.map((v) => `${String(v)}\n${safeJson(v)}\n${inspect(v, { depth: 8, showHidden: true })}`), ...logged].join('\n');
const safeJson = (v: unknown) => {
  try {
    return JSON.stringify(v);
  } catch {
    return '';
  }
};

describe('redaction', () => {
  it('a token glued to the start of something that looks like a document is still redacted', () => {
    expect(redact('x eyJab_evit_SECRET y')).toBe('x eyJab_[redacted] y');
    expect(redact('evit_a.eyJh.eyJp.c evit_b')).not.toMatch(/evit_[ab]/);
  });
  it('a problem that echoes the token, the assertion or a client secret keeps none of them', async () => {
    let echoed = '';
    const { client, assertions } = run(() => {
      echoed = `${TOKEN} ${assertions[0]}`;
      return new Response(
        JSON.stringify({
          code: 'validation_failed',
          detail: `validation_failed: ${echoed}`,
          errors: [
            { path: '/client_assertion', code: 'pattern', message: assertions[0] },
            { path: '/client_secret', code: 'pattern', message: 'cs_live_0123456789' },
            { path: '/version', code: 'pattern', message: `bad ${TOKEN}` },
          ],
        }),
        { status: 422, headers: { 'content-type': 'application/problem+json' } },
      );
    });
    const error = (await client.instances.heartbeat({ version: '1.0.0' }).catch((e) => e)) as ProblemError;
    expect(error).toBeInstanceOf(ProblemError);
    expect(error.errors?.map((e) => e.path)).toEqual(['/version']);
    const text = everything(error, client, error.detail, error.errors);
    expect(text).not.toContain(TOKEN);
    expect(text).not.toContain(assertions[0]);
    expect(text).not.toContain('cs_live_0123456789');
    expect(text).toContain('[redacted]');
  });

  it('the client, its tokens and its signer show no secret', async () => {
    const { client, assertions } = run(() => new Response('{}', { status: 200 }));
    await client.instances.integrations();
    const text = everything(client, SIGNER, client.keys, client.instances);
    expect(text).not.toContain(TOKEN);
    expect(text).not.toContain(assertions[0]);
    expect(text).not.toContain(Buffer.from(SEED).toString('base64url'));
    expect(text).not.toContain(Buffer.from(SEED).toString('hex'));
  });

  it('a refused document names the code, never a claim value', () => {
    const roots = fixture<{ keys: RootKey[] }>('keys/roots.json').keys;
    const ctx = fixture('entitlement/context.json');
    const keySet = KeySet.verify(fixture('keys/manifest.valid.json'), { unsafeRootKeys: roots, issuer: ctx.expected_issuer, now: ctx.now });
    for (const file of ['wrong-instance', 'wrong-subject', 'extra-claim', 'stale-seq', 'wrong-issuer']) {
      const jws = fixtureText(`entitlement/invalid/${file}.jws`).trim();
      const error = (() => {
        try {
          verifyEntitlement(jws, {
            keySet,
            expectedIssuer: ctx.expected_issuer,
            expectedInstanceId: ctx.expected_instance_id,
            expectedSubject: ctx.expected_subject,
            cached: ctx.cached,
            now: ctx.now,
          });
        } catch (e) {
          return e;
        }
      })();
      expect(error).toBeInstanceOf(EntitlementError);
      const text = everything(error);
      expect(text).not.toContain(jws);
      expect(text).not.toContain('01JNE7V9J0');
      expect(text).not.toContain('acme');
      expect(text).not.toContain('api.example.com');
    }
  });
});
