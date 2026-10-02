// Scenario managed-backup: an owner asks the installation for a backup; a fixture executor built on
// the SDK's managed-operation runner reads the request from the feed and posts exactly one result.
// Without the managed_operations integration the mock refuses (403 integration_disabled); past
// expires_at the operation is expired, takes no result and the runner does not run it.
import { createManagedOperationRunner } from '@ever-co/connect-sdk';
import { describe, expect, test } from 'vitest';
import { expectOk, expectProblem, startMock } from './helpers.mjs';

const REQUESTED = 'ever.registry.managed_operation.requested';
const STATE_CHANGED = 'ever.registry.managed_operation.state_changed';

/** A fixture executor: records the hooks it was called with and never touches anything. */
function fixtureExecutor(outcome = { status: 'succeeded', artefact_ref: 'bk-20261102-1000', size_bytes: 734003200 }) {
  const calls = [];
  return {
    calls,
    kinds: () => ['backup', 'update', 'health_report'],
    async dryRun() {
      calls.push('dryRun');
      return { ok: true };
    },
    async backupBeforeUpdate() {
      calls.push('backupBeforeUpdate');
      return { ok: true, artefact_ref: 'bk-pre-update', size_bytes: 1024 };
    },
    async execute() {
      calls.push('execute');
      // A careless executor's extra fields never leave the installation (the runner drops them).
      return { ...outcome, file_name: '/srv/backups/acme.tar.gz' };
    },
  };
}

async function connectedWith(env, integrations) {
  const c = await env.connect();
  for (const integration of integrations) await env.admin('consent', { integration });
  return c;
}

async function feed(env, token, after) {
  const r = await env.call('GET', `/v1/instances/me/events?wait=0${after ? `&after=${encodeURIComponent(after)}` : ''}`, { token });
  expectOk(expect, r, 200, 'instancePollEvents');
  return r.body;
}

function runnerFor(env, token, executor, posted) {
  return createManagedOperationRunner({
    executor,
    now: env.now,
    postResult: async (operationId, result) => {
      const r = await env.call('POST', `/v1/instances/me/managed-operations/${operationId}/result`, { token, body: result });
      expectOk(expect, r, 200, 'instanceReportManagedOperationResult');
      posted.push({ operationId, result });
    },
  });
}

describe('scenario managed-backup', () => {
  test('the SDK runner receives the backup request and posts one result', async () => {
    const env = await startMock();
    try {
      const { token } = await connectedWith(env, ['managed_operations']);
      const before = await feed(env, token);
      const mark = env.mock.recorder.entries.length;
      const requested = await env.admin('managed/request', { kind: 'backup', params: {} });

      const page = await feed(env, token, before.last_id);
      const notices = page.events.filter((e) => e.type === REQUESTED);
      expect(notices).toHaveLength(1);
      expect(notices[0].data).toMatchObject({ operation_id: requested.operation_id, kind: 'backup', params: {} });

      const executor = fixtureExecutor();
      const posted = [];
      const runner = runnerFor(env, token, executor, posted);
      const report = await runner.handle(notices[0]);
      expect(report.outcome).toBe('executed');
      expect(executor.calls).toEqual(['dryRun', 'execute']);
      expect(posted).toEqual([
        { operationId: requested.operation_id, result: { status: 'succeeded', artefact_ref: 'bk-20261102-1000', size_bytes: 734003200 } },
      ]);
      // A repeated delivery of the same notice posts nothing more.
      expect((await runner.handle(notices[0])).outcome).toBe('duplicate');
      expect(posted).toHaveLength(1);

      const ops = await env.call('GET', '/__mock/managed/operations');
      expect(ops.body).toEqual([
        expect.objectContaining({ operation_id: requested.operation_id, kind: 'backup', state: 'succeeded', size_bytes: 734003200 }),
      ]);
      expect(ops.body[0].results).toHaveLength(1);
      const next = await feed(env, token, page.last_id);
      expect(next.events.map((e) => e.type)).toEqual([STATE_CHANGED]);
      expect(next.events[0].data).toMatchObject({
        operation_id: requested.operation_id,
        state: 'succeeded',
        artefact_ref: 'bk-20261102-1000',
      });

      // After the request the installation made only feed reads (row 7) and the result call (row 34).
      const rows = [...new Set(env.mock.recorder.entries.slice(mark).map((e) => e.row))].sort((a, b) => a - b);
      expect(rows).toEqual([7, 34]);
    } finally {
      await env.close();
    }
  });

  test('an update takes the backup before it runs; a dry-run-only update changes nothing', async () => {
    const env = await startMock();
    try {
      const { token } = await connectedWith(env, ['managed_operations']);
      const executor = fixtureExecutor({ status: 'succeeded', version: '96.3.0' });
      const posted = [];
      const runner = runnerFor(env, token, executor, posted);
      const update = await env.admin('managed/request', { kind: 'update', params: { target_version: '96.3.0' } });
      const dry = await env.admin('managed/request', { kind: 'update', params: { dry_run_only: true } });
      const notices = (await feed(env, token)).events.filter((e) => e.type === REQUESTED);
      expect((await runner.handle(notices.find((n) => n.data.operation_id === update.operation_id))).calls).toEqual([
        'dryRun',
        'backupBeforeUpdate',
        'execute',
      ]);
      expect((await runner.handle(notices.find((n) => n.data.operation_id === dry.operation_id))).outcome).toBe('dry_run_only');
      expect(posted.map((p) => p.result)).toEqual([{ status: 'succeeded', version: '96.3.0' }, { status: 'succeeded' }]);
    } finally {
      await env.close();
    }
  });
});

test('without the managed_operations integration the mock answers 403 integration_disabled', async () => {
  const env = await startMock();
  try {
    const { token } = await env.connect();
    expectProblem(
      expect,
      await env.call('POST', '/__mock/managed/request', { body: { kind: 'backup', params: {} } }),
      403,
      'integration_disabled',
    );
    const result = await env.call('POST', '/v1/instances/me/managed-operations/01JMQCK0RG000000000000000D/result', {
      token,
      body: { status: 'succeeded' },
    });
    expectProblem(expect, result, 403, 'integration_disabled');
  } finally {
    await env.close();
  }
});

test('past expires_at the operation is expired: no result is taken and the runner does not run it', async () => {
  const env = await startMock();
  try {
    const { token } = await connectedWith(env, ['managed_operations']);
    const { operation_id: id } = await env.admin('managed/request', { kind: 'backup', params: {}, expires_in_s: 600 });
    const notice = (await feed(env, token)).events.find((e) => e.type === REQUESTED);
    await env.admin('clock', { advance: 601 });

    const ops = await env.call('GET', '/__mock/managed/operations');
    expect(ops.body.find((o) => o.operation_id === id).state).toBe('expired');
    const late = await env.call('POST', `/v1/instances/me/managed-operations/${id}/result`, { token, body: { status: 'succeeded' } });
    expectProblem(expect, late, 409, 'illegal_transition');

    const executor = fixtureExecutor();
    const posted = [];
    const report = await runnerFor(env, token, executor, posted).handle(notice);
    expect(report.outcome).toBe('expired');
    expect(executor.calls).toEqual([]);
    expect(posted).toEqual([]);
  } finally {
    await env.close();
  }
});
