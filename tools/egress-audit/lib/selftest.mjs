// The harness self-test: fixture products with known behaviour, so the harness is seen failing a
// leaky product and passing only with the evidence a pass needs, before any product trusts it.
import { join } from 'node:path';
import { HARNESS_DIR, loadConfig, runAudit } from './runner.mjs';

export const SELFTEST_RUNS = [
  { name: 'off/quiet', fixture: 'quiet', mode: 'off', expect: 0 },
  // The failing control: a DNS query for an Ever host and a connection attempt, both seen.
  { name: 'off/leaky', fixture: 'leaky', mode: 'off', expect: 1, rules: ['dns_ever_host', 'egress_attempt'] },
  { name: 'positive_stats/stats-sender', fixture: 'stats-sender', mode: 'positive_stats', expect: 0 },
  // Without the mock the positive run must not pass: nothing can have been accepted.
  { name: 'positive_stats/no-mock', fixture: 'stats-sender', mode: 'positive_stats', noMock: true, expect: 'non-zero' },
  { name: 'positive_managed/managed-executor', fixture: 'managed-executor', mode: 'positive_managed', expect: 0 },
];

export function judge(run, report) {
  const problems = [];
  if (run.expect === 'non-zero' ? report.exit === 0 : report.exit !== run.expect)
    problems.push(`exit ${report.exit}, expected ${run.expect}`);
  for (const rule of run.rules ?? []) if (!report.violations.some((v) => v.rule === rule)) problems.push(`no ${rule} violation was seen`);
  return problems;
}

export async function selftest({ artifactsDir, only, log = () => {}, print = (l) => process.stdout.write(`${l}\n`) }) {
  const { config, configDir } = loadConfig(join(HARNESS_DIR, 'selftest', 'egress-audit.config.json'));
  const runs = SELFTEST_RUNS.filter((r) => !only || only.includes(r.name) || only.includes(r.fixture));
  const results = [];
  for (const run of runs) {
    print(`ever-egress-audit self-test: ${run.name} ...`);
    let report;
    try {
      report = await runAudit({
        config: { ...config, project: `ever-audit-selftest-${run.fixture}` },
        configDir,
        modeName: run.mode,
        noMock: Boolean(run.noMock),
        artifactsDir: join(artifactsDir, run.fixture),
        composeEnv: { EVER_SELFTEST_FIXTURE: run.fixture },
        log,
      });
    } catch (error) {
      report = { exit: 2, violations: [], faults: [error.message] };
    }
    const problems = judge(run, report);
    results.push({ ...run, exit: report.exit, problems, faults: report.faults, violations: report.violations.map((v) => v.rule) });
    for (const f of report.faults ?? []) print(`  fault: ${f}`);
    for (const v of report.violations ?? []) print(`  violation: ${JSON.stringify(v)}`);
  }
  print('');
  print('ever-egress-audit self-test summary');
  for (const r of results)
    print(
      `  ${`${r.name}=${r.exit}`.padEnd(40)} expected ${String(r.expect).padEnd(9)} ${r.problems.length === 0 ? 'ok' : `FAILED: ${r.problems.join('; ')}`}`,
    );
  const ok = results.every((r) => r.problems.length === 0);
  print(ok ? 'self-test passed: the harness sees egress and passes only proven runs' : 'self-test FAILED');
  return { ok, results };
}
