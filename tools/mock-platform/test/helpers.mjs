// Test helpers: a mock on a free port, plain fetch calls, and an installation connected with the
// TEST connect key.
import { createHash } from 'node:crypto';
import { signClientAssertion, signRotationProof, testKey } from '../src/keys.mjs';
import { createMockPlatform } from '../src/server.mjs';
import { validateResponse } from '../src/validate.mjs';

export const ISSUER = 'http://mock.test';
let jtiCounter = 0;

export async function startMock(config = {}) {
  const mock = createMockPlatform({ config: { issuer: ISSUER, ...config } });
  const { url } = await mock.listen(0, '127.0.0.1');
  const api = {
    url,
    mock,
    state: mock.state,
    now: () => mock.state.now(),
    async call(method, path, { body, token, headers = {}, raw, contentType } = {}) {
      const h = { 'user-agent': 'ever-connect-sdk/0.0.0-test (gauzy/96.2.1)', ...headers };
      if (token) h.authorization = `Bearer ${token}`;
      let payload;
      if (raw !== undefined) {
        payload = raw;
        h['content-type'] = contentType ?? 'application/json';
      } else if (body !== undefined) {
        payload = JSON.stringify(body);
        h['content-type'] = 'application/json';
      }
      const res = await fetch(`${url}${path}`, { method, headers: h, body: payload });
      const text = await res.text();
      let parsed = null;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = text;
      }
      return { status: res.status, body: parsed, text, headers: res.headers };
    },
    async admin(path, body) {
      const r = await api.call('POST', `/__mock/${path}`, { body: body ?? {} });
      if (r.status >= 300) throw new Error(`/__mock/${path}: ${r.status} ${r.text}`);
      return r.body;
    },
    assertion({ key = testKey('connect'), instanceId, ttl = 300, iat, audience = `${ISSUER}/v1/instances/token`, jti } = {}) {
      jtiCounter += 1;
      return signClientAssertion({
        key,
        instanceId,
        audience,
        iat: iat ?? mock.state.now(),
        ttl,
        jti: jti ?? `test-jti-${String(jtiCounter).padStart(12, '0')}`,
      });
    },
    /**
     * The body of a key rotation: the new key and its two proofs, signed with the current key and
     * with the new key (`signers` overrides who signs them, `bind` the key the proofs bind).
     */
    rotation(instanceId, { current = testKey('connect'), next = testKey('connectNext'), signers, bind, jtis = [], iat, claims } = {}) {
      jtiCounter += 1;
      const at = iat ?? mock.state.now();
      const n = String(jtiCounter).padStart(12, '0');
      const [bySigner, nextSigner] = signers ?? [current, next];
      const proof = (key, jti) => signRotationProof({ key, instanceId, origin: ISSUER, newX: (bind ?? next).x, iat: at, jti, claims });
      return {
        public_jwk: { kty: 'OKP', crv: 'Ed25519', x: next.x },
        current_key_proof: proof(bySigner, jtis[0] ?? `rotation-current-${n}`),
        new_key_proof: proof(nextSigner, jtis[1] ?? `rotation-new-${n}`),
      };
    },
    async token(instanceId, key = testKey('connect')) {
      const r = await api.call('POST', '/v1/instances/token', {
        body: {
          grant_type: 'client_credentials',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: api.assertion({ key, instanceId }),
        },
      });
      if (r.status !== 200) throw new Error(`token: ${r.status} ${r.text}`);
      return r.body.access_token;
    },
    /** Redeems a code with the TEST connect key and gets a token: {instanceId, token, redeem}. */
    async connect({
      code = 'EVC-TEST-0000-0001',
      product = 'gauzy',
      key = testKey('connect'),
      tenant = { product_tenant_id: 'tenant-1', product_org_id: 'org-1' },
      idem,
    } = {}) {
      const body = {
        code,
        product,
        version: '96.2.1',
        install_source: 'self-hosted',
        kind: 'self_hosted',
        public_jwk: { kty: 'OKP', crv: 'Ed25519', x: key.x },
      };
      if (tenant) body.tenant = tenant;
      const redeem = await api.call('POST', '/v1/connect/redeem', {
        body,
        headers: { 'idempotency-key': idem ?? createHash('sha256').update(`${key.x}|${code}`).digest('hex') },
      });
      if (redeem.status !== 201) throw new Error(`redeem: ${redeem.status} ${redeem.text}`);
      const instanceId = redeem.body.instance_id;
      return { instanceId, token: await api.token(instanceId, key), redeem: redeem.body, linkId: redeem.body.link?.id };
    },
    close: () => mock.close(),
  };
  return api;
}

/** Asserts a problem answer: status, code, problem+json, and the documented response shape. */
export function expectProblem(expect, r, status, code) {
  expect(r.status, `${r.text}`).toBe(status);
  expect(r.body?.code, r.text).toBe(code);
  expect(r.headers.get('content-type')).toBe('application/problem+json');
  expect(r.body.type).toBe(`https://api.ever.co/problems/${code}`);
}

/** Asserts a success answer and that its body matches the contract response schema. */
export function expectOk(expect, r, status, operationId) {
  expect(r.status, `${operationId}: ${r.text}`).toBe(status);
  if (operationId && r.body !== null && r.body !== undefined && r.text !== '') {
    const v = validateResponse(operationId, status, r.body);
    expect(v.errors, `${operationId} ${status} response does not match the contract`).toEqual([]);
  }
}
