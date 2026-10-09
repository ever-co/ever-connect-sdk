// The harness self-test: fixture products with known behaviour, so the harness is seen failing a
// leaky product and passing only with the evidence a pass needs, before any product trusts it.
// The API runs use the fixture config without its web keys; the browser runs (fixtures ui-*) use it
// as it is, so the browser leg walks the toy web app.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { harLeaks } from './har.mjs';
import { HARNESS_DIR, loadConfig, runAudit } from './runner.mjs';

const ACCOUNT_PASSWORD = 'selftest-password-0e6a';
/** The web fixture's session cookie (lib/web.mjs): `session=` and 32 hex digits. */
const SESSION_COOKIE = /session=[0-9a-f]{32}/;
const WEB_KEYS = [
  'web_service',
  'web_url',
  'ui_routes',
  'route_params',
  'ui_baseline',
  'idle_pages',
  'idle_s',
  'ui_page_timeout_s',
  'ui_skip_routes',
  'ui_expected_requests',
];

export const SELFTEST_RUNS = [
  { name: 'off/quiet', fixture: 'quiet', mode: 'off', expect: 0 },
  // The failing control: a DNS query for an Ever host, a SYN, a UDP datagram and a DNS question sent
  // straight to an outside resolver, each seen.
  {
    name: 'off/leaky',
    fixture: 'leaky',
    mode: 'off',
    expect: 1,
    rules: ['dns_ever_host', 'egress_attempt'],
    attempts: [
      { proto: 'tcp', dst: '203.0.113.10', port: 443 },
      { proto: 'udp', dst: '203.0.113.10', port: 443 },
      { proto: 'udp', dst: '198.51.100.53', port: 53 },
    ],
  },
  { name: 'positive_stats/stats-sender', fixture: 'stats-sender', mode: 'positive_stats', expect: 0 },
  // Without the mock the positive run must not pass: nothing can have been accepted.
  { name: 'positive_stats/no-mock', fixture: 'stats-sender', mode: 'positive_stats', noMock: true, expect: 'non-zero' },
  { name: 'positive_managed/managed-executor', fixture: 'managed-executor', mode: 'positive_managed', expect: 0 },
  // The browser leg. A quiet UI passes with no name outside the compose services looked up by the
  // browser, every route opened (one with a parameter only the run knows) and the idle page held.
  { name: 'off/ui-quiet', fixture: 'ui-quiet', mode: 'off', browser: true, expect: 0, quiet: true },
  // Its failing control: the DNS query from the browser, the HAR entry, the DOM src and the
  // connection attempt to a documentation address, each seen.
  {
    name: 'off/ui-leaky',
    fixture: 'ui-leaky',
    mode: 'off',
    browser: true,
    expect: 1,
    rules: ['browser_dns_never_allowed', 'har_never_allowed', 'dom_never_allowed', 'browser_egress_attempt'],
    browserAttempts: [{ proto: 'tcp', dst: '203.0.113.10', port: 443 }],
  },
  // A rendered link is a finding of the DOM check alone; the product's baseline excuses it.
  {
    name: 'off/ui-link(no baseline)',
    fixture: 'ui-link',
    mode: 'off',
    browser: true,
    expect: 1,
    rules: ['dom_never_allowed'],
    onlyRules: true,
  },
  {
    name: 'off/ui-link(baseline)',
    fixture: 'ui-link',
    artifact: 'ui-link-baseline',
    mode: 'off',
    browser: true,
    config: { ui_baseline: 'ui-baseline.link.json' },
    expect: 0,
  },
  // The positive control: the status call seen from the browser, and nothing outside compose names.
  { name: 'positive_stats/ui-stats', fixture: 'ui-stats', mode: 'positive_stats', browser: true, expect: 0, expectedSeen: true },
  // Without the mock the API leg fails as above, while the browser still records the status call.
  {
    name: 'positive_stats/ui-stats(no mock)',
    fixture: 'ui-stats',
    artifact: 'ui-stats-nomock',
    mode: 'positive_stats',
    noMock: true,
    browser: true,
    expect: 'non-zero',
    expectedSeen: true,
  },
  // A sign-in that fails (a wrong password, no check of where it ended): every route lands on the
  // sign-in page, which is a fault, never a pass.
  {
    name: 'off/ui-quiet(failed sign-in)',
    fixture: 'ui-quiet',
    artifact: 'ui-quiet-failed-sign-in',
    mode: 'off',
    browser: true,
    config: { adapter: 'adapter.bad-sign-in.mjs' },
    expect: 2,
    faults: [/ended on the sign-in page/],
  },
  // A config with a web_service run without the browser leg proves the API side only: never a pass.
  {
    name: 'off/ui-quiet(--legs api)',
    fixture: 'ui-quiet',
    artifact: 'ui-quiet-api-only',
    mode: 'off',
    browser: true,
    legs: ['api'],
    expect: 2,
  },
];

/**
 * Every file of a run's artefacts (dotfiles included, binary files read byte for byte) that holds
 * one of the secrets or matches one of the patterns: the fixture password and the session cookie
 * must be in none of them, whatever the leg wrote or failed to clean up.
 */
export function artifactLeaks(dir, secrets = [], patterns = []) {
  const problems = [];
  if (!existsSync(dir)) return problems;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else {
        const text = readFileSync(p, 'latin1');
        const file = relative(dir, p).split(sep).join('/');
        for (const s of secrets) if (s && text.includes(s)) problems.push(`${file} holds the fixture password`);
        for (const re of patterns) if (re.test(text)) problems.push(`${file} holds the session cookie`);
      }
    }
  };
  walk(dir);
  return problems;
}

export function judge(run, report, { harText, leaks = [] } = {}) {
  const problems = [];
  for (const re of run.faults ?? [])
    if (!(report.faults ?? []).some((f) => re.test(f))) problems.push(`no fault matching ${re} was seen`);
  problems.push(...leaks);
  if (run.expect === 'non-zero' ? report.exit === 0 : report.exit !== run.expect)
    problems.push(`exit ${report.exit}, expected ${run.expect}`);
  for (const rule of run.rules ?? []) if (!report.violations.some((v) => v.rule === rule)) problems.push(`no ${rule} violation was seen`);
  if (run.onlyRules) for (const v of report.violations) if (!run.rules.includes(v.rule)) problems.push(`an unexpected ${v.rule} violation`);
  for (const a of run.attempts ?? [])
    if (!report.violations.some((v) => v.rule === 'egress_attempt' && v.proto === a.proto && v.dst === a.dst && v.port === a.port))
      problems.push(`no ${a.proto} attempt to ${a.dst}:${a.port} was seen`);
  for (const a of run.browserAttempts ?? [])
    if (!report.violations.some((v) => v.rule === 'browser_egress_attempt' && v.proto === a.proto && v.dst === a.dst && v.port === a.port))
      problems.push(`no ${a.proto} attempt to ${a.dst}:${a.port} was seen from the browser`);
  const browser = report.summary?.browser;
  if (run.browser && !(run.legs && !run.legs.includes('browser'))) {
    if (!browser || browser.leg !== 'ran') problems.push('the browser leg did not run');
    else {
      if (browser.loaded < 4) problems.push(`the browser opened ${browser.loaded} routes, expected 4`);
      if (run.quiet) {
        if (browser.checks.e.outside !== 0)
          problems.push(`the browser looked up ${browser.checks.e.outside} names outside the compose services`);
        if (browser.checks.e.dns_queries === 0) problems.push('the browser looked up no name at all (is its DNS captured?)');
      }
      if (run.expectedSeen && !browser.expected.every((e) => e.seen)) problems.push('the browser did not record the expected status call');
      if (harText === undefined) problems.push('no browser.har was written');
      else problems.push(...harLeaks(harText, [ACCOUNT_PASSWORD]));
    }
  }
  return problems;
}

export async function selftest({ artifactsDir, only, legs, log = () => {}, print = (l) => process.stdout.write(`${l}\n`) }) {
  const { config, configDir } = loadConfig(join(HARNESS_DIR, 'selftest', 'egress-audit.config.json'));
  const apiConfig = Object.fromEntries(Object.entries(config).filter(([k]) => !WEB_KEYS.includes(k)));
  const withBrowser = !legs || legs.includes('browser');
  const runs = SELFTEST_RUNS.filter((r) => (!only || only.includes(r.name) || only.includes(r.fixture)) && (withBrowser || !r.browser));
  const results = [];
  for (const run of runs) {
    print(`ever-egress-audit self-test: ${run.name} ...`);
    const dir = join(artifactsDir, run.artifact ?? run.fixture);
    let report;
    try {
      report = await runAudit({
        config: { ...(run.browser ? config : apiConfig), ...run.config, project: `ever-audit-selftest-${run.artifact ?? run.fixture}` },
        configDir,
        modeName: run.mode,
        noMock: Boolean(run.noMock),
        artifactsDir: dir,
        composeEnv: { EVER_SELFTEST_FIXTURE: run.fixture },
        legs: run.legs ?? (run.browser ? ['api', 'browser'] : ['api']),
        log,
      });
    } catch (error) {
      report = { exit: 2, violations: [], faults: [error.message] };
    }
    const runDir = join(dir, `${run.mode}${run.noMock ? '-nomock' : ''}`);
    const harFile = join(runDir, 'browser', 'browser.har');
    const harText = existsSync(harFile) ? readFileSync(harFile, 'utf8') : undefined;
    const leaks = run.browser ? artifactLeaks(runDir, [ACCOUNT_PASSWORD], [SESSION_COOKIE]) : [];
    const problems = judge(run, report, { harText, leaks });
    results.push({ ...run, exit: report.exit, problems, faults: report.faults, violations: report.violations.map((v) => v.rule) });
    for (const f of report.faults ?? []) print(`  fault: ${f}`);
    for (const v of report.violations ?? []) print(`  violation: ${JSON.stringify(v)}`);
  }
  print('');
  print('ever-egress-audit self-test summary');
  for (const r of results)
    print(
      `  ${`${r.name}=${r.exit}`.padEnd(44)} expected ${String(r.expect).padEnd(9)} ${r.problems.length === 0 ? 'ok' : `FAILED: ${r.problems.join('; ')}`}`,
    );
  const ok = results.length > 0 && results.every((r) => r.problems.length === 0);
  print(ok ? 'self-test passed: the harness sees egress and passes only proven runs' : 'self-test FAILED');
  return { ok, results };
}
