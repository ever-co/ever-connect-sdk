// The App Launcher's feeds on the mock (rows 36, 37): with a person's token carrying apps:read,
// the organization the person reaches through the calling installation answers what was seeded;
// without the scope 403 session_required; another organization 404.
import { describe, expect, test } from 'vitest';
import { expectOk, expectProblem, startMock } from './helpers.mjs';

describe('the App Launcher feeds', () => {
  test('answer the seeded feeds for a reachable organization with apps:read only', async () => {
    const env = await startMock();
    try {
      const { instanceId } = await env.connect();
      const org = env.state.instance(instanceId).org.id;
      const install = {
        id: '01JMQCK0INSTA11000000000A1',
        listing_id: '01JMQCK0L1ST1NG00000000A01',
        listing_type: 'app',
        listing_slug: 'cal',
        listing_title: 'Cal',
        mechanism: 'external_link',
        state: 'installed',
        created_at: '2026-11-02T10:00:00Z',
        next_action_url: 'https://cal.example/',
      };
      await env.admin('launcher', { org_id: org, installs: [install] });
      const token = async (scope) => (await env.admin('person-token', { azp: `inst-${instanceId}`, ...(scope ? { scope } : {}) })).token;

      const scoped = await token('openid apps:read');
      const installs = await env.call('GET', `/v1/orgs/${org}/installs`, { token: scoped });
      expectOk(expect, installs, 200, 'listInstalls');
      expect(installs.body.items.map((i) => i.listing_slug)).toEqual(['cal']);
      const apps = await env.call('GET', `/v1/orgs/${org}/apps`, { token: scoped });
      expectOk(expect, apps, 200, 'listOrganizationApps');
      expect(apps.body.items).toEqual([]);

      const plain = await token();
      expectProblem(expect, await env.call('GET', `/v1/orgs/${org}/installs`, { token: plain }), 403, 'session_required');
      expectProblem(expect, await env.call('GET', '/v1/orgs/01JMQCK0RG00000000000000ZZ/apps', { token: scoped }), 404, 'not_found');
    } finally {
      await env.close();
    }
  });
});
