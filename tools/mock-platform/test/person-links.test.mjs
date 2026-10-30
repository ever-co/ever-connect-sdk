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

  it('refuses a link method other than explicit or confirmed, and a tenant link it does not hold', async () => {
    const c = await setup();
    const typo = await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { ...report, link_method: 'typo' },
    });
    expect(typo.status).toBe(422);
    expect(typo.body.code).toBe('validation_failed');
    const foreign = await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { ...report, tenant_link_id: '01JMQCK0RG000000000000000Z' },
    });
    expect(foreign.status).toBe(422);
    expect(foreign.body.code).toBe('link_not_found');
    const own = await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { ...report, tenant_link_id: c.linkId },
    });
    expect(own.status).toBe(201);
  });

  it('resolves only a subject this installation linked', async () => {
    const c = await setup();
    const ask = { issuer: 'https://auth.ever.co', subject: report.identity_subject };
    const unlinked = await env.call('POST', '/v1/identity/resolve', { token: c.token, body: ask });
    expect(unlinked.status, 'known but not linked here').toBe(404);
    await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    const linked = await env.call('POST', '/v1/identity/resolve', { token: c.token, body: ask });
    expect(linked.status).toBe(200);
  });

  it('resolves only the identity linked, not another identity of the same person', async () => {
    env = await startMock({
      people: [
        { issuer: 'https://auth.ever.co', subject: '275396402232829475', person_id: '01JMQCKPERS0N00000000000P1', org_role: 'owner' },
        { issuer: 'https://auth.ever.co', subject: '275396402232829476', person_id: '01JMQCKPERS0N00000000000P1', org_role: 'owner' },
      ],
    });
    const c = await env.connect();
    await env.admin('consent', { integration: 'ever_id_login' });
    await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    const other = await env.call('POST', '/v1/identity/resolve', {
      token: c.token,
      body: { issuer: 'https://auth.ever.co', subject: '275396402232829476' },
    });
    expect(other.status, 'another identity of the same person').toBe(404);
    // That identity is known: once linked, it resolves.
    await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { ...report, product_user_ref: 'user-2', identity_subject: '275396402232829476' },
    });
    const linked = await env.call('POST', '/v1/identity/resolve', {
      token: c.token,
      body: { issuer: 'https://auth.ever.co', subject: '275396402232829476' },
    });
    expect(linked.status).toBe(200);
  });

  it('records changed workspace metadata on the same link', async () => {
    const c = await setup();
    const first = await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    const moved = await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { ...report, tenant_link_id: c.linkId, product_tenant_id: 't-2', display_name: 'Acme' },
    });
    expect(moved.status).toBe(201);
    expect(moved.body.id, 'the same link').toBe(first.body.id);
    expect(moved.body.tenant_link_id).toBe(c.linkId);
    expect(moved.body.product_tenant_id).toBe('t-2');
    expect(moved.body.display_name).toBe('Acme');
  });

  it('keeps one link per Ever ID subject of the same user reference', async () => {
    env = await startMock({
      people: [
        { issuer: 'https://auth.ever.co', subject: '275396402232829475', person_id: '01JMQCKPERS0N00000000000P1', org_role: 'owner' },
        { issuer: 'https://auth.ever.co', subject: '275396402232829476', person_id: '01JMQCKPERS0N00000000000P1', org_role: 'owner' },
      ],
    });
    const c = await env.connect();
    await env.admin('consent', { integration: 'ever_id_login' });
    const a = await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    const b = await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { ...report, identity_subject: '275396402232829476' },
    });
    expect(b.body.id, 'another subject is another link').not.toBe(a.body.id);
    const again = await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    expect(again.body.id, 'the first link is still there').toBe(a.body.id);
    for (const subject of ['275396402232829475', '275396402232829476']) {
      const r = await env.call('POST', '/v1/identity/resolve', { token: c.token, body: { issuer: 'https://auth.ever.co', subject } });
      expect(r.status, subject).toBe(200);
    }
    // Unlinking the user reference removes both.
    await env.call('DELETE', `/v1/instances/me/person-links/${report.product_user_ref}`, { token: c.token });
    const gone = await env.call('POST', '/v1/identity/resolve', {
      token: c.token,
      body: { issuer: 'https://auth.ever.co', subject: '275396402232829476' },
    });
    expect(gone.status).toBe(404);
  });

  it('compares the issuer too: the same subject under another issuer resolves only once reported', async () => {
    env = await startMock({
      people: [
        { issuer: 'https://auth.ever.co', subject: '275396402232829475', person_id: '01JMQCKPERS0N00000000000P1', org_role: 'owner' },
        { issuer: 'https://id.example', subject: '275396402232829475', person_id: '01JMQCKPERS0N00000000000P1', org_role: 'owner' },
      ],
    });
    const c = await env.connect();
    await env.admin('consent', { integration: 'ever_id_login' });
    await env.call('POST', '/v1/instances/me/person-links', { token: c.token, body: report });
    const other = { issuer: 'https://id.example', subject: '275396402232829475' };
    expect((await env.call('POST', '/v1/identity/resolve', { token: c.token, body: other })).status).toBe(404);
    await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { ...report, identity_issuer: 'https://id.example' },
    });
    expect((await env.call('POST', '/v1/identity/resolve', { token: c.token, body: other })).status).toBe(200);
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
