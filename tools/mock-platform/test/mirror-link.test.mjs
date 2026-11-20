// The apps mirror's gate (row 15), as Ever Platform's `any_link`: `Ever-Link-Id` is optional. Named,
// app_sync must be enabled for that link; not named, for at least one active link. A per-link route
// (the install status report, row 28) still needs the header.
import { afterEach, describe, expect, it } from 'vitest';
import { expectOk, expectProblem, startMock } from './helpers.mjs';

let env;
afterEach(async () => {
  await env?.close();
  env = null;
});

const batch = { ops: [{ op: 'upsert', kind: 'app', external_id: 'w-1', external_version: 1, occurred_at: '2026-11-02T10:00:00Z' }] };
const push = (c, headers = {}) => env.call('POST', '/v1/instances/me/mirror/apps', { token: c.token, body: batch, headers });
const list = (c, headers = {}) => env.call('GET', '/v1/instances/me/mirror/apps', { token: c.token, headers });

describe('the apps mirror gate (any link)', () => {
  it('answers without Ever-Link-Id while app_sync is enabled for an active link', async () => {
    env = await startMock();
    const c = await env.connect();
    await env.admin('consent', { integration: 'app_sync' });
    expectOk(expect, await push(c), 200, 'instanceMirrorApps');
    expectOk(expect, await list(c), 200, 'instanceListMirroredApps');
    expectOk(expect, await push(c, { 'ever-link-id': c.linkId }), 200, 'instanceMirrorApps');
  });

  it('refuses without Ever-Link-Id when no link has app_sync, and a named link that has it off', async () => {
    env = await startMock();
    const c = await env.connect();
    expectProblem(expect, await push(c), 403, 'integration_disabled');
    await env.admin('consent', { integration: 'app_sync' });
    expectProblem(expect, await list(c, { 'ever-link-id': '01JMQCK0RG000000000000000E' }), 403, 'integration_disabled');
    expectProblem(expect, await list(c, { 'ever-link-id': 'not-a-link' }), 422, 'validation_failed');
  });

  it('keeps the per-link rule on the install status report', async () => {
    env = await startMock();
    const c = await env.connect();
    await env.admin('consent', { integration: 'marketplace_installs' });
    const { install_id } = await env.admin('install', {});
    const report = (headers) =>
      env.call('POST', `/v1/installs/${install_id}/status`, { token: c.token, body: { state: 'installing' }, headers });
    const without = await report({});
    expectProblem(expect, without, 422, 'validation_failed');
    expect(without.body.errors.map((e) => e.path)).toEqual(['#Ever-Link-Id']);
    expectOk(expect, await report({ 'ever-link-id': c.linkId }), 200, 'instanceReportInstallStatus');
  });
});
