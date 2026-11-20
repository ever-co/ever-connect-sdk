// A tenant link's members on the mock (row 38): the configured people until an organization is
// seeded, pages in a stable order with an opaque cursor, the product user of a person link, and
// the platform's refusals (an unknown cursor, a link the installation no longer holds, a deployment
// that sends no membership events).
import { afterEach, describe, expect, it } from 'vitest';
import { expectOk, expectProblem, startMock } from './helpers.mjs';

let env;
afterEach(async () => {
  await env?.close();
  env = null;
});

const ISSUER = 'https://auth.ever.co';
const members = (n) =>
  Array.from({ length: n }, (_, i) => ({
    identity_issuer: ISSUER,
    identity_subject: `subject-${String(i).padStart(2, '0')}`,
    role: i === 0 ? 'owner' : 'member',
  }));
const page = (c, query = '') => env.call('GET', `/v1/instances/me/tenant-links/${c.linkId}/memberships${query}`, { token: c.token });

describe('the members of a tenant link', () => {
  it('answers the configured people until the organization is seeded', async () => {
    env = await startMock();
    const c = await env.connect();
    const r = await page(c);
    expectOk(expect, r, 200, 'instanceListLinkMemberships');
    expect(r.body).toEqual({
      tenant_link_id: c.linkId,
      items: [{ identity_issuer: ISSUER, identity_subject: '275396402232829475', role: 'owner' }],
      next_cursor: null,
    });
  });

  it('hands every seeded member out once, page by page, with the cursor of the previous page', async () => {
    env = await startMock();
    const c = await env.connect();
    await env.admin('memberships', { members: members(5).reverse() });
    const seen = [];
    let cursor = null;
    for (let n = 0; n < 5; n += 1) {
      const r = await page(c, `?limit=2${cursor ? `&cursor=${cursor}` : ''}`);
      expectOk(expect, r, 200, 'instanceListLinkMemberships');
      seen.push(...r.body.items.map((m) => m.identity_subject));
      cursor = r.body.next_cursor;
      if (cursor === null) break;
    }
    expect(seen).toEqual(['subject-00', 'subject-01', 'subject-02', 'subject-03', 'subject-04']);
    expect(cursor).toBeNull();
  });

  it('names the product user a person link of the installation holds for the member', async () => {
    env = await startMock();
    const c = await env.connect();
    await env.admin('consent', { integration: 'ever_id_login' });
    const linked = await env.call('POST', '/v1/instances/me/person-links', {
      token: c.token,
      body: { product_user_ref: 'user-1', identity_issuer: ISSUER, identity_subject: '275396402232829475', link_method: 'explicit' },
    });
    expect(linked.status).toBe(201);
    const r = await page(c);
    expectOk(expect, r, 200, 'instanceListLinkMemberships');
    expect(r.body.items).toEqual([
      { identity_issuer: ISSUER, identity_subject: '275396402232829475', product_user_ref: 'user-1', role: 'owner' },
    ]);
  });

  it('refuses a cursor it never handed out and a limit outside 1..100 (422), and a link it no longer holds (404)', async () => {
    env = await startMock();
    const c = await env.connect();
    const cursor = await page(c, '?cursor=bm90LWEtY3Vyc29y');
    expectProblem(expect, cursor, 422, 'validation_failed');
    expect(cursor.body.errors.map((e) => e.path)).toEqual(['?cursor']);
    expectProblem(expect, await page(c, '?limit=0'), 422, 'validation_failed');
    const removed = await env.call('DELETE', `/v1/instances/me/tenant-links/${c.linkId}`, { token: c.token });
    expect(removed.status).toBe(204);
    expectProblem(expect, await page(c), 404, 'not_found');
  });

  it('answers 404 module_disabled while the deployment sends no membership events', async () => {
    env = await startMock();
    const c = await env.connect();
    await env.admin('faults', { memberships_module_disabled: true });
    expectProblem(expect, await page(c), 404, 'module_disabled');
    await env.admin('faults', { memberships_module_disabled: false });
    expectOk(expect, await page(c), 200, 'instanceListLinkMemberships');
  });

  it('refuses a seed that is not a list of members, or names an Ever ID twice', async () => {
    env = await startMock();
    await env.connect();
    const r = await env.call('POST', '/__mock/memberships', { body: { members: [{ identity_issuer: ISSUER, role: 'boss' }] } });
    expectProblem(expect, r, 422, 'validation_failed');
    const twice = await env.call('POST', '/__mock/memberships', { body: { members: [...members(2), members(1)[0]] } });
    expectProblem(expect, twice, 422, 'validation_failed');
  });
});
