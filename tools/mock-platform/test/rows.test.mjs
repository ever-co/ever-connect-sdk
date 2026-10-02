// Every row of the outbound-call table, table-driven from contracts/generated/row-coverage.json:
// the good path of each operation and every documented (row, status, code) pair. A pair without a
// scenario is reported as uncovered and fails the suite.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { validateEventData } from '../src/validate.mjs';
import { expectOk, expectProblem, startMock } from './helpers.mjs';
import { ERRORS, OK } from './scenarios.mjs';

const REPO = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..');
const coverage = JSON.parse(readFileSync(join(REPO, 'contracts/generated/row-coverage.json'), 'utf8')).rows;

const pairs = coverage.flatMap((r) => r.errors.map((e) => ({ row: r.row, ...e, key: `${r.row}:${e.status}:${e.code}` })));
const operations = coverage.flatMap((r) => r.operations.map((o) => ({ row: r.row, ...o })));
const uncovered = [
  ...pairs.filter((p) => !ERRORS[p.key]).map((p) => p.key),
  ...operations.filter((o) => !OK[o.operation_id]).map((o) => o.operation_id),
];

let env;
afterEach(async () => {
  await env?.close();
  env = null;
});

describe('row coverage', () => {
  it('reports 0 uncovered (row, status, code) pairs and operations', () => {
    expect(uncovered).toEqual([]);
    expect(pairs.length).toBeGreaterThanOrEqual(120);
    expect(new Set(coverage.map((r) => r.row)).size).toBe(34);
  });
});

for (const row of coverage) {
  describe(`row ${row.row}`, () => {
    for (const op of row.operations) {
      it(`${op.method} ${op.path} (${op.operation_id}) answers ${op.success.join(' or ')}`, async () => {
        env = await startMock();
        const r = await OK[op.operation_id](env);
        expect(op.success, `${op.operation_id}: ${r.status} ${r.text}`).toContain(r.status);
        expectOk(expect, r, r.status, op.operation_id);
        // Every event the mock put on any feed matches its catalog schema.
        for (const instance of env.state.instances.values())
          for (const event of instance.feed) expect(validateEventData(event.type, event.data).errors, `${event.type}`).toEqual([]);
      });
    }
    for (const e of row.errors) {
      it(`${e.status} ${e.code}${e.documented ? '' : ' (pending in the platform contract)'}`, async () => {
        env = await startMock();
        const r = await ERRORS[`${row.row}:${e.status}:${e.code}`](env);
        expectProblem(expect, r, e.status, e.code);
      });
    }
  });
}
