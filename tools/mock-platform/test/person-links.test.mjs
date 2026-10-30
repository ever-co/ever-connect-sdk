// Person links (row 19) as the platform answers them: the same report again is the link already
// recorded (no idempotency key needed), and unlinking a reference with no link is done already.
import { afterEach, describe, expect, it } from 'vitest';
import { startMock } from './helpers.mjs';

let env;
afterEach(async () => {
  await env?.close();
  env = null;
});

const report = {
  product_user_ref: 'user-1',
  identity_issuer: 'https://auth.ever.co',
  identity_subject: '275396402232829475',
  link_method: 'explicit',
};

async function setup() {
  env = await startMock();
  const c = await env.connect();
  await env.admin('consent', { integration: 'ever_id_login' });
  return c;
}

describe('person links', () => {
  it('the same report twice, without an idempotency key, answers the same link', async () => {
    const c = await setup();
    const first = await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    const again = await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    expect(first.status).toBe(201);
    expect(again.status).toBe(201);
    expect(again.body.id).toBe(first.body.id);
  });

  it('unlinking twice, or a reference never linked, answers 204', async () => {
    const c = await setup();
    await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    for (const ref of ['user-1', 'user-1', 'nobody']) {
      const r = await env.call('DELETE', `/v1/instances/me/person-links/${ref}`, { token: c.token });
      expect(r.status, ref).toBe(204);
    }
  });
});
