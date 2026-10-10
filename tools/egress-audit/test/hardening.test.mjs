// The browser leg's hardening: a web service that must be watched, a sign-in that must hold, a raw
// HAR that never reaches the evidence, redacted plans and logs, a static gate that a baseline or an
// opt-in cannot switch off per host, configuration that cannot shrink the walk, and images pinned by
// digest. The walk tests use a stub browser, so they run anywhere.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { walk } from '../browser.mjs';
import { loadOptinHosts } from '../hosts.mjs';
import { harLeaks, redactUrl } from '../lib/har.mjs';
import {
  BROWSER_BASE_IMAGE,
  browserDockerfile,
  checkRouteList,
  checkWebUrl,
  HARNESS_DIR,
  loadConfig,
  redactValues,
  scrubLog,
  tokenShapedFixtures,
  UsageError,
} from '../lib/runner.mjs';
import { artifactLeaks, judge, SELFTEST_RUNS } from '../lib/selftest.mjs';
import { scanHostnames } from '../static-hostnames.mjs';

const PASSWORD = 'fixture-password-77';
const COOKIE = 'session=0123456789abcdef0123456789abcdef';

/** What Playwright's raw HAR keeps with content 'omit': cookies, header values and form fields. */
const RAW_HAR = {
  log: {
    version: '1.2',
    entries: [
      {
        request: {
          method: 'POST',
          url: 'http://web:3000/sign-in',
          headers: [{ name: 'cookie', value: COOKIE }],
          cookies: [{ name: 'session', value: COOKIE }],
          postData: {
            mimeType: 'application/x-www-form-urlencoded',
            text: `password=${PASSWORD}`,
            params: [{ name: 'password', value: PASSWORD }],
          },
        },
        response: { status: 303, headers: [{ name: 'set-cookie', value: COOKIE }], cookies: [], content: { size: 0 } },
      },
    ],
  },
};

/**
 * A stub of playwright-core's chromium: pages answer 200; when signedIn() is false every page but
 * the sign-in page redirects to it; idle waits (1 s or more) reject when idleRejects is set; the
 * context writes RAW_HAR to its recordHar path when it closes.
 */
function stubChromium({ signedIn = () => true, idleRejects = false } = {}) {
  return {
    launch: async () => ({
      newContext: async (opts) => {
        const listeners = {};
        let current = 'about:blank';
        const page = {
          url: () => current,
          goto: async (url) => {
            const u = new URL(url);
            current = !signedIn() && u.pathname !== '/sign-in' ? `${u.origin}/sign-in` : url;
            for (const f of listeners.load ?? []) f();
            return { status: () => 200 };
          },
          waitForLoadState: async () => {},
          waitForTimeout: async (ms) => {
            if (idleRejects && ms >= 1000) throw new Error('Target page, context or browser has been closed\nmore');
          },
          on: (e, f) => {
            listeners[e] = [...(listeners[e] ?? []), f];
          },
          off: (e, f) => {
            listeners[e] = (listeners[e] ?? []).filter((x) => x !== f);
          },
          frames: () => [],
          mainFrame: () => null,
          fill: async () => {},
          click: async () => {},
        };
        return {
          on: () => {},
          exposeBinding: async () => {},
          addInitScript: async () => {},
          newPage: async () => page,
          close: async () => writeFileSync(opts.recordHar.path, JSON.stringify(RAW_HAR)),
        };
      },
      close: async () => {},
    }),
  };
}

const PLAN = {
  web_url: 'http://web:3000',
  routes: [{ path: '/' }, { path: '/about' }, { path: '/settings' }],
  idle_pages: ['/settings'],
  idle_s: 1,
  page_timeout_s: 5,
};
const signIn = {
  async uiLogin(page, ctx) {
    await page.goto(`${ctx.baseUrl}/sign-in`);
    await page.fill('input[name=password]', PASSWORD);
    await page.click('button');
  },
};

const allFiles = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((d) => (d.isDirectory() ? allFiles(join(dir, d.name)) : [join(dir, d.name)]));

test('a sign-in that does not hold faults the walk: every route that ends on the sign-in page is named', async () => {
  const r = await walk({
    chromium: stubChromium({ signedIn: () => false }),
    plan: PLAN,
    adapter: signIn,
    outDir: mkdtempSync(join(tmpdir(), 'ever-w-')),
  });
  assert.equal(r.ok, false);
  assert.equal(r.signInPath, '/sign-in');
  assert.ok(
    r.faults.some((f) => /3 route\(s\) ended on the sign-in page \/sign-in \(\/, \/about, \/settings\)/.test(f)),
    r.faults.join('; '),
  );
  assert.deepEqual(r.redirected, ['/ -> /sign-in', '/about -> /sign-in', '/settings -> /sign-in']);
  // A sign-in that holds: no fault, nothing redirected.
  const ok = await walk({ chromium: stubChromium(), plan: PLAN, adapter: signIn, outDir: mkdtempSync(join(tmpdir(), 'ever-w-')) });
  assert.deepEqual(ok.faults, []);
  assert.deepEqual(ok.redirected, []);
  // A uiLogin that opens no page never reaches the sign-in page at all.
  const none = await walk({
    chromium: stubChromium(),
    plan: PLAN,
    adapter: { uiLogin: async () => {} },
    outDir: mkdtempSync(join(tmpdir(), 'ever-w-')),
  });
  assert.ok(none.faults.some((f) => /uiLogin opened no page/.test(f)));
});

test('the raw HAR never lands in the evidence: kept outside outDir and deleted, also when the walk fails', async () => {
  const outDir = mkdtempSync(join(tmpdir(), 'ever-w-'));
  const tmp = mkdtempSync(join(tmpdir(), 'ever-tmp-'));
  // The probe of the review: the idle wait rejects (a page that closes itself during it).
  const r = await walk({ chromium: stubChromium({ idleRejects: true }), plan: PLAN, adapter: signIn, outDir, tmpDir: tmp });
  assert.equal(r.ok, false);
  assert.ok(
    r.faults.some((f) => /^the browser walk failed: Target page, context or browser has been closed$/.test(f)),
    r.faults.join('; '),
  );
  assert.deepEqual(readdirSync(tmp), [], 'the raw recording is deleted');
  const files = allFiles(outDir).map((f) => f.slice(outDir.length + 1).replaceAll('\\', '/'));
  assert.deepEqual(files.sort(), ['browser.har', 'dom-refs.json', 'requests.json', 'visits.json']);
  for (const f of allFiles(outDir)) {
    const text = readFileSync(f, 'utf8');
    assert.ok(!text.includes(PASSWORD), `${f} holds the password`);
    assert.ok(!text.includes(COOKIE), `${f} holds the cookie`);
  }
  assert.deepEqual(harLeaks(readFileSync(join(outDir, 'browser.har'), 'utf8'), [PASSWORD]), []);
  assert.deepEqual(artifactLeaks(outDir, [PASSWORD], [/session=[0-9a-f]{32}/]), []);
});

test('the self-test scans every artefact of a browser run, dotfiles included, and expects the failed sign-in to fault', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ever-art-'));
  mkdirSync(join(dir, 'browser'));
  writeFileSync(join(dir, 'browser', '.raw.har'), `{"text":"password=${PASSWORD}"}`);
  writeFileSync(join(dir, 'browser-walk.log'), `set ${COOKIE}`);
  writeFileSync(join(dir, 'report.json'), '{}');
  assert.deepEqual(artifactLeaks(dir, [PASSWORD], [/session=[0-9a-f]{32}/]).sort(), [
    'browser-walk.log holds the session cookie',
    'browser/.raw.har holds the fixture password',
  ]);
  const failed = SELFTEST_RUNS.find((r) => r.name === 'off/ui-quiet(failed sign-in)');
  assert.equal(failed.expect, 2);
  assert.equal(failed.config.adapter, 'adapter.bad-sign-in.mjs');
  assert.ok(existsSync(join(HARNESS_DIR, 'selftest', failed.config.adapter)));
  const report = { exit: 2, violations: [], faults: [], summary: {} };
  assert.ok(judge({ ...failed, browser: false }, report).includes('no fault matching /ended on the sign-in page/ was seen'));
  assert.deepEqual(
    judge({ ...failed, browser: false }, { ...report, faults: ['browser: 4 route(s) ended on the sign-in page /sign-in (/)'] }),
    [],
  );
  assert.deepEqual(judge({ ...failed, browser: false }, { ...report, faults: ['x'] }, { leaks: ['a leak'] }).slice(-1), ['a leak']);
});

function configs() {
  const dir = mkdtempSync(join(tmpdir(), 'ever-cfg-'));
  const base = {
    product: 'teams',
    compose: ['c.yml'],
    api_service: 'api',
    process_services: ['api'],
    health_url: 'http://api:3000/h',
    module_routes: ['/x'],
  };
  const load = (value) => {
    const file = join(dir, `c${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(file, JSON.stringify({ ...base, ...value }));
    return loadConfig(file).config;
  };
  return { load };
}

test('the web service must be watched: in process_services, or declared static', () => {
  const { load } = configs();
  const web = { web_service: 'web', web_url: 'http://web:3030' };
  assert.throws(
    () => load(web),
    (e) => e instanceof UsageError && /web_service web is not one of process_services/.test(e.message),
  );
  assert.equal(load({ ...web, process_services: ['api', 'web'] }).web_service, 'web');
  assert.equal(load({ ...web, web_static: true }).web_static, true);
  assert.throws(() => load({ ...web, web_static: false }), /not one of process_services/);
  assert.throws(() => load({ web_service: null, no_web_reason: 'x', web_static: true }), /web_static goes with web_service/);
});

test('a product with a UI names its web service, or says why not; an idle page is never skipped', () => {
  const { load } = configs();
  assert.throws(() => load({}), /teams has a UI: name its web_service/);
  assert.throws(() => load({ web_service: null }), /needs no_web_reason/);
  assert.equal(load({ web_service: null, no_web_reason: 'the UI is audited in its own repository' }).web_service, null);
  assert.throws(() => load({ web_service: null, no_web_reason: 'x', web_url: 'http://web:1' }), /web_url needs web_service/);
  assert.throws(() => load({ web_service: 'api', web_url: 'http://api:3000', no_web_reason: 'x' }), /no_web_reason goes with/);
  assert.equal(load({ product: 'demand' }).product, 'demand', 'a product without a UI needs neither');
  const web = { web_service: 'api', web_url: 'http://api:3000' };
  assert.throws(
    () => load({ ...web, idle_pages: ['/settings'], ui_skip_routes: [{ path: '/settings', reason: 'x' }] }),
    /idle page \/settings is also in ui_skip_routes/,
  );
  assert.equal(loadConfig(join(HARNESS_DIR, 'selftest', 'egress-audit.config.json')).config.product, 'selftest');
});

test('web_url names the web service (or one of its aliases), never another service', () => {
  const model = { services: { web: { networks: { default: { aliases: ['ui'] } } }, api: {} } };
  const cfg = (web_url) => ({ web_service: 'web', web_url });
  checkWebUrl(cfg('http://web:3030'), model);
  checkWebUrl(cfg('http://ui:3030/app'), model);
  assert.throws(
    () => checkWebUrl(cfg('http://api:3000'), model),
    /web_url http:\/\/api:3000 does not name web_service web \(its names: ui, web\)/,
  );
  checkWebUrl({}, model);
});

test('the run compares a generated route list with the router; a manual list is reported as unchecked', () => {
  const root = mkdtempSync(join(tmpdir(), 'ever-routes-'));
  for (const p of ['app/page.tsx', 'app/about/page.tsx', 'app/settings/page.tsx']) {
    mkdirSync(join(root, p, '..'), { recursive: true });
    writeFileSync(join(root, p), 'export default function P() { return null; }\n');
  }
  const list = {
    framework: 'next-app',
    entry: 'app',
    routes: [
      { path: '/', source: 'router' },
      { path: '/about', source: 'router' },
    ],
  };
  const r = checkRouteList(list, { ui_routes_root: '.' }, root);
  assert.equal(r.checked, true);
  assert.deepEqual(r.missing, ['/settings']);
  const manual = checkRouteList({ framework: 'manual', routes: [] }, {}, root);
  assert.equal(manual.checked, false);
  assert.match(manual.note, /manual/);
  const broken = checkRouteList({ ...list, entry: 'nope' }, { ui_routes_root: '.' }, root);
  assert.equal(broken.checked, false);
  assert.ok(broken.error);
});

test('the browser plan and the logs keep names, never values; fixtures shaped like a credential are refused', () => {
  assert.deepEqual(redactValues({ EVER_X: 'on', n: 3, nested: { a: ['b'] }, none: null }), {
    EVER_X: '[redacted]',
    n: '[redacted]',
    nested: { a: ['[redacted]'] },
    none: null,
  });
  assert.equal(redactValues(null), null);
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl';
  assert.deepEqual(tokenShapedFixtures({ teamId: 'b3c1-22', token: jwt, auth: 'Bearer abc', list: ['x'.repeat(65)] }), [
    'fixtures.token',
    'fixtures.auth',
    'fixtures.list[0]',
  ]);
  assert.deepEqual(tokenShapedFixtures({ id: 'a'.repeat(64) }), []);
  const log = [
    `cookie: ${COOKIE}`,
    'Set-Cookie: session=abc; HttpOnly',
    'authorization: Basic Zm9vOmJhcg==',
    `GET /x Bearer abc.def-ghi`,
    `token ${jwt} seen`,
    `{"password":"${PASSWORD}","email":"admin@example.test"}`,
    `password=${PASSWORD}&next=/`,
    'open http://web:3000/about (attempt 1): timeout',
  ].join('\n');
  const scrubbed = scrubLog(log);
  for (const secret of [COOKIE, 'session=abc', 'Zm9vOmJhcg', 'abc.def-ghi', jwt, PASSWORD]) assert.ok(!scrubbed.includes(secret), secret);
  assert.match(scrubbed, /open http:\/\/web:3000\/about \(attempt 1\): timeout/);
  assert.match(scrubbed, /"email":"admin@example.test"/);
});

test('the static gate: a baseline excuses its exact URLs only, an opt-in is never a platform service name', () => {
  const root = mkdtempSync(join(tmpdir(), 'ever-static-'));
  const files = {
    'apps/web/footer.tsx': '<a href="https://app.ever.co/">Ever</a>\n',
    'apps/web/token.ts': "fetch('https://api.ever.co/v1/instances/token');\n",
    'apps/web/deep.ts': "const u = 'https://app.ever.co/x';\n",
    'apps/web/bare.ts': "const u = 'https://app.ever.co';\n",
  };
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(join(root, p, '..'), { recursive: true });
    writeFileSync(join(root, p), text);
  }
  // The probe of the review: a baseline entry https://app.ever.co/ no longer accepts the whole host.
  const found = scanHostnames(root, [], { baselineUrls: ['https://app.ever.co/'], allFiles: true });
  assert.deepEqual(found.sort(), ['apps/web/deep.ts:1', 'apps/web/token.ts:1']);
  // The old option (a set of hosts) is not honoured any more.
  assert.equal(scanHostnames(root, [], { baselineHosts: new Set(['app.ever.co']), allFiles: true }).length, 4);
  const optin = (host) => {
    const file = join(root, `optin-${host}.json`);
    writeFileSync(file, JSON.stringify({ hosts: [{ host, setting: 'X=true', reason: 'r' }] }));
    return file;
  };
  for (const host of ['api.ever.co', 'ever.co', 'app.ever.co', 'auth.ever.co', 'apps.ever.co'])
    assert.throws(() => loadOptinHosts(optin(host)), /not a valid opt-in list|Ever Platform service name/, host);
  assert.deepEqual([...loadOptinHosts(optin('updates.gauzy.co'))], ['updates.gauzy.co']);
});

test('every image of the audit is pinned by digest, and the browser runs as pwuser in the pinned image', () => {
  const runner = readFileSync(join(HARNESS_DIR, 'lib', 'runner.mjs'), 'utf8');
  for (const name of ['COREDNS_IMAGE', 'DRIVER_BASE_IMAGE'])
    assert.match(runner, new RegExp(`const ${name} = '[^']+@sha256:[a-f0-9]{64}';`), name);
  assert.match(BROWSER_BASE_IMAGE, /@sha256:[a-f0-9]{64}$/);
  const overlay = readFileSync(join(HARNESS_DIR, 'compose.audit.yml'), 'utf8');
  const images = [...overlay.matchAll(/^\s+image: (\S+)$/gm)].map((m) => m[1]).filter((i) => !/^__\w+__$/.test(i));
  assert.equal(images.length, 2);
  for (const i of images) assert.match(i, /@sha256:[a-f0-9]{64}$/, i);
  const schema = JSON.parse(readFileSync(join(HARNESS_DIR, 'config.schema.json'), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema.properties.browser_image);
  assert.equal(validate('mcr.microsoft.com/playwright:v1.62.1'), false, 'a tag alone');
  assert.equal(validate(BROWSER_BASE_IMAGE), true);
  assert.match(browserDockerfile(BROWSER_BASE_IMAGE), /chown pwuser:pwuser \/out\nUSER pwuser\nENTRYPOINT/);
  assert.doesNotMatch(browserDockerfile('example.test/browser@sha256:' + 'a'.repeat(64)), /USER/);
});

test('URLs keep no phone number, e-mail address or JWT in their path', () => {
  assert.equal(redactUrl('tel:+15551234567'), 'tel:[redacted]');
  assert.equal(redactUrl('sms:+15551234567?body=hi'), 'sms:[redacted]');
  assert.equal(redactUrl('https://app.example.test/users/jane@example.test/profile'), 'https://app.example.test/users/[redacted]/profile');
  assert.equal(
    redactUrl('https://app.example.test/invite/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig'),
    'https://app.example.test/invite/[redacted]',
  );
  assert.equal(redactUrl('https://app.example.test/items/42?tab=1'), 'https://app.example.test/items/42?tab=');
});
