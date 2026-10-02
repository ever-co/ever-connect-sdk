import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ManagedOperationResult } from '@ever-co/connect-contracts';
import { describe, expect, it } from 'vitest';
import {
  createManagedOperationRunner,
  MANAGED_REQUESTED,
  type ManagedOperation,
  type ManagedOperationExecutor,
  type ManagedOperationKind,
} from '../src/index';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'contracts', 'fixtures', 'feed');
const fixtureEvent = (name: string) => JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), 'utf8')).events[0];
const NOW = Date.UTC(2026, 10, 2, 12, 0, 0) / 1000;

function recorder(
  kinds: readonly ManagedOperationKind[] = ['update', 'backup', 'restore_check', 'health_report'],
  overrides: Partial<ManagedOperationExecutor> = {},
) {
  const calls: string[] = [];
  const results: Array<{ id: string; result: ManagedOperationResult }> = [];
  const executor: ManagedOperationExecutor = {
    kinds: () => kinds,
    dryRun: async (op: ManagedOperation) => {
      calls.push(`dryRun:${op.kind}`);
      return { ok: true };
    },
    backupBeforeUpdate: async () => {
      calls.push('backupBeforeUpdate');
      return { ok: true, artefact_ref: 'bk-1', size_bytes: 1024 };
    },
    execute: async (op: ManagedOperation) => {
      calls.push(`execute:${op.kind}`);
      return { status: 'succeeded', version: op.kind === 'update' ? '1.5.0' : undefined, size_bytes: 2048 };
    },
    ...overrides,
  };
  const runner = createManagedOperationRunner({
    executor,
    now: () => NOW,
    postResult: async (id, result) => {
      results.push({ id, result });
    },
  });
  return { runner, calls, results };
}

describe('managed operations', () => {
  it('a backup runs the dry run, executes and posts exactly one result', async () => {
    const r = recorder();
    const report = await r.runner.handle(fixtureEvent('managed-operation-requested.backup'));
    expect(report.outcome).toBe('executed');
    expect(r.calls).toEqual(['dryRun:backup', 'execute:backup']);
    expect(r.results).toHaveLength(1);
    expect(r.results[0]?.result).toEqual({ status: 'succeeded', size_bytes: 2048 });
  });

  it('an update always takes the backup before it executes', async () => {
    const r = recorder();
    await r.runner.handle(fixtureEvent('managed-operation-requested.update'));
    expect(r.calls).toEqual(['dryRun:update', 'backupBeforeUpdate', 'execute:update']);
    expect(r.results[0]?.result).toEqual({ status: 'succeeded', version: '1.5.0', size_bytes: 2048 });
  });

  it('a failed backup stops the update: one failed result, no execute', async () => {
    const r = recorder(undefined, { backupBeforeUpdate: async () => ({ ok: false }) });
    const report = await r.runner.handle(fixtureEvent('managed-operation-requested.update'));
    expect(report.outcome).toBe('backup_failed');
    expect(report.calls).toEqual(['dryRun', 'backupBeforeUpdate']);
    expect(r.results.map((x) => x.result.status)).toEqual(['failed']);
  });

  it('an unknown kind gives one failed result and no execute call', async () => {
    const r = recorder(['backup']);
    const report = await r.runner.handle(fixtureEvent('managed-operation-requested.health-report'));
    expect(report.outcome).toBe('refused_kind');
    expect(r.calls).toEqual([]);
    expect(r.results.map((x) => x.result)).toEqual([{ status: 'failed' }]);
  });

  it('out-of-schema params give one failed result and nothing runs', async () => {
    for (const name of [
      'managed-operation-requested.update.invalid-unknown-param',
      'managed-operation-requested.backup.invalid-unknown-param',
    ]) {
      const r = recorder();
      const report = await r.runner.handle(fixtureEvent(name));
      expect(report.outcome, name).toBe('refused_invalid');
      expect(r.calls, name).toEqual([]);
      expect(
        r.results.map((x) => x.result),
        name,
      ).toEqual([{ status: 'failed' }]);
    }
  });

  it('one result per operation: a repeated delivery is ignored', async () => {
    const r = recorder();
    const event = fixtureEvent('managed-operation-requested.backup');
    await r.runner.handle(event);
    const again = await r.runner.handle(event);
    expect(again.outcome).toBe('duplicate');
    expect(r.results).toHaveLength(1);
  });

  it('a failed dry run, an executor exception and an expired operation never execute', async () => {
    const dry = recorder(undefined, { dryRun: async () => ({ ok: false, reason: 'maintenance window closed' }) });
    expect((await dry.runner.handle(fixtureEvent('managed-operation-requested.backup'))).outcome).toBe('dry_run_failed');
    expect(dry.calls).toEqual([]);
    const boom = recorder(undefined, {
      execute: async () => {
        throw new Error('disk full');
      },
    });
    expect((await boom.runner.handle(fixtureEvent('managed-operation-requested.backup'))).outcome).toBe('execute_failed');
    expect(boom.results.map((x) => x.result)).toEqual([{ status: 'failed' }]);
    const late = recorder();
    const event = fixtureEvent('managed-operation-requested.backup');
    const expired = await late.runner.handle({ ...event, data: { ...event.data, expires_at: '2026-11-02T11:00:00Z' } });
    expect(expired.outcome).toBe('expired');
    expect(late.results).toEqual([]);
  });

  it('results carry status, version and sizes only: anything else is dropped', async () => {
    const r = recorder(undefined, {
      execute: async () =>
        ({
          status: 'succeeded',
          artefact_ref: 'bk-20261102',
          size_bytes: 10,
          file_name: 'acme-backup.tar.gz',
          path: '/srv/backups',
        }) as never,
    });
    await r.runner.handle(fixtureEvent('managed-operation-requested.backup'));
    expect(r.results[0]?.result).toEqual({ status: 'succeeded', artefact_ref: 'bk-20261102', size_bytes: 10 });
  });

  it('other event types are acknowledged and ignored', async () => {
    const r = recorder();
    expect((await r.runner.handle({ type: 'ever.registry.instance.seen', data: {} })).outcome).toBe('ignored');
    expect(MANAGED_REQUESTED).toBe('ever.registry.managed_operation.requested');
    expect(r.results).toEqual([]);
  });

  it('the runner opens no listener and makes no request of its own', () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'managed', 'runner.ts'), 'utf8');
    expect(source).not.toMatch(/node:(http|https|net)|createServer|\.listen\(|fetch\(/);
  });
});
