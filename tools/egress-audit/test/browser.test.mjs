// browser.mjs against a local fixture site, with a real browser: sign-in through the form, every
// route opened (one with a parameter), the idle route held for idle_s, the DOM references of every
// frame and shadow root (the planted href, srcset, form action and shadow link), a page that never
// loads retried once and reported as a fault, and a HAR without bodies, cookies or form values.
//
// It needs the browser build of playwright-core: CI runs it inside the pinned Playwright image;
// elsewhere it is skipped unless that browser is installed (npx playwright-core install chromium).
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { walk } from '../browser.mjs';
import { harLeaks } from '../lib/har.mjs';

let chromium = null;
try {
  ({ chromium } = await import('playwright-core'));
  if (!existsSync(chromium.executablePath())) chromium = null;
} catch {
  chromium = null;
}

const PASSWORD = 'selftest-password-0e6a';
const page = (body) => `<!doctype html><html><head><meta charset="utf-8"><title>t</title></head><body>${body}</body></html>`;

function site() {
  const hits = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    hits.push(`${req.method} ${url.pathname}`);
    const html = (status, body, headers = {}) => {
      res.writeHead(status, { 'content-type': 'text/html', ...headers });
      res.end(body);
    };
    const signedIn = /session=ok/.test(req.headers.cookie ?? '');
    if (url.pathname === '/sign-in' && req.method === 'GET')
      return html(
        200,
        page(
          '<form method="post" action="/sign-in"><input name="email"><input name="password" type="password"><button>Go</button></form><a href="https://planted-signin.invalid/terms">terms</a>',
        ),
      );
    if (url.pathname === '/sign-in') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => html(303, '', { location: '/', 'set-cookie': 'session=ok; HttpOnly; Path=/' }));
      return;
    }
    if (url.pathname === '/broken') return html(500, 'no');
    if (url.pathname === '/frame') return html(200, page('<form action="https://planted-frame.invalid/submit"><button>x</button></form>'));
    if (!signedIn) return html(303, '', { location: '/sign-in' });
    if (url.pathname === '/')
      return html(
        200,
        page(
          '<a href="https://planted.invalid/x?token=abc#frag">x</a>' +
            '<img alt="" src="/local.png" srcset="https://planted-set.invalid/a.png 1x, /local.png 2x">' +
            '<div id="host"><template shadowrootmode="open"><a href="https://planted-shadow.invalid/">s</a></template></div>' +
            '<iframe src="/frame"></iframe>',
        ),
      );
    if (url.pathname === '/settings' || url.pathname === '/about' || url.pathname.startsWith('/items/'))
      return html(200, page(`<h1>${url.pathname}</h1>`));
    return html(404, 'nf');
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ server, hits, base: `http://127.0.0.1:${server.address().port}` })),
  );
}

const adapter = {
  async uiLogin(p, ctx) {
    await p.goto(`${ctx.baseUrl}/sign-in`);
    await p.fill('input[name=email]', 'a@example.test');
    await p.fill('input[name=password]', PASSWORD);
    await Promise.all([p.waitForURL(`${ctx.baseUrl}/`), p.click('button')]);
  },
  async routeParams(ctx) {
    return { id: ctx.fixtures.item };
  },
};

test('the walk: sign-in, every route, the idle route held, every frame and shadow root dumped, a HAR without secrets', {
  skip: !chromium && 'no browser for playwright-core here (CI runs this inside the Playwright image)',
  timeout: 180000,
}, async () => {
  const { server, hits, base } = await site();
  const outDir = mkdtempSync(join(tmpdir(), 'ever-browser-'));
  try {
    const t0 = Date.now();
    const r = await walk({
      chromium,
      adapter,
      outDir,
      plan: {
        web_url: base,
        routes: [{ path: '/' }, { path: '/items/:id' }, { path: '/settings' }, { path: '/team/:teamId' }],
        idle_pages: ['/settings'],
        idle_s: 3,
        page_timeout_s: 20,
        skip: [{ path: '/team/:teamId', reason: 'no team in the fixture' }],
        fixtures: { item: 'one' },
      },
    });
    assert.deepEqual(r.faults, []);
    assert.equal(r.counts.loaded, 3);
    assert.deepEqual(
      r.visits.map((v) => `${v.route} ${v.status} ${v.url.replace(base, '')}`),
      ['/ 200 /', '/items/:id 200 /items/one', '/settings 200 /settings'],
    );
    assert.equal(r.visits.find((v) => v.route === '/settings').idle_s, 3);
    assert.ok(Date.now() - t0 >= 3000, 'the idle route was held');
    assert.deepEqual(r.skipped, [{ route: '/team/:teamId', reason: 'no team in the fixture' }]);
    assert.ok(hits.includes('POST /sign-in') && hits.includes('GET /items/one'));
    const refs = JSON.parse(readFileSync(join(outDir, 'dom-refs.json'), 'utf8'));
    const found = (attribute, url) => refs.some((x) => x.route === '/' && x.attribute === attribute && x.url === url);
    assert.ok(found('href', 'https://planted.invalid/x?token='), 'the planted href, without its query value or fragment');
    assert.ok(
      refs.some((x) => x.route === '/sign-in' && x.url === 'https://planted-signin.invalid/terms'),
      'what the sign-in page renders, under its own path',
    );
    assert.ok(found('srcset', 'https://planted-set.invalid/a.png'), 'the planted srcset');
    assert.ok(found('href', 'https://planted-shadow.invalid/'), 'the link in the shadow root');
    assert.ok(
      refs.some(
        (x) =>
          x.route === '/' && x.frame.endsWith('/frame') && x.attribute === 'action' && x.url === 'https://planted-frame.invalid/submit',
      ),
      'the iframe form',
    );
    const harText = readFileSync(join(outDir, 'browser.har'), 'utf8');
    assert.deepEqual(harLeaks(harText, [PASSWORD]), []);
    const har = JSON.parse(harText);
    assert.ok(har.log.entries.length > 0);
    assert.ok(har.log.entries.every((e) => e.response.content.text === undefined));
    assert.ok(
      har.log.entries.some((e) => e.request.url === 'https://planted-set.invalid/a.png'),
      'a failed request is in the HAR',
    );
    assert.ok(!existsSync(join(outDir, '.raw.har')));
  } finally {
    server.close();
  }
});

test('a page that never loads is retried once, then reported as a fault; a parameter without a value is a fault', {
  skip: !chromium && 'no browser for playwright-core here',
  timeout: 120000,
}, async () => {
  const { server, hits, base } = await site();
  try {
    const r = await walk({
      chromium,
      adapter,
      outDir: mkdtempSync(join(tmpdir(), 'ever-browser-')),
      plan: {
        web_url: base,
        routes: [{ path: '/broken' }, { path: '/about' }, { path: '/team/:teamId' }],
        idle_s: 0,
        page_timeout_s: 10,
        fixtures: { item: 'one' },
      },
    });
    const broken = r.visits.find((v) => v.route === '/broken');
    assert.equal(broken.ok, false);
    assert.equal(broken.attempts, 2);
    assert.equal(hits.filter((h) => h === 'GET /broken').length, 2);
    assert.ok(r.faults.some((f) => /route \/broken did not load after one retry/.test(f)));
    assert.ok(r.faults.some((f) => /route \/team\/:teamId has no value for teamId/.test(f)));
    assert.equal(r.ok, false);
  } finally {
    server.close();
  }
});

// A hash-routed app (as Angular useHash): one document at every path; the routes live in the
// fragment. Signed out, every route redirects to #/auth/login, and it does so a moment after the
// load (as a router does once the app has started), so the sign-in page is not the first route the
// load shows. Signing in posts to the API, which sets the session, then routes to #/pages/dashboard.
const HASH_APP = page(`<main id="view"></main><script>
const view = document.getElementById('view');
const signedIn = () => /(^|; )session=ok/.test(document.cookie);
function render() {
  const route = (location.hash.replace(/^#/, '').split('?')[0]) || '/';
  if (!signedIn() && route !== '/auth/login') return void location.replace('#/auth/login');
  if (route === '/' || route === '/auth/login' && signedIn()) return void location.replace('#/pages/dashboard');
  if (route === '/auth/login') {
    view.innerHTML = '<form><input name="email"><input name="password" type="password"><button>Go</button></form><a href="https://planted-hash-signin.invalid/terms">terms</a>';
    view.querySelector('form').addEventListener('submit', async (e) => {
      e.preventDefault();
      await fetch('/api/sign-in', { method: 'POST', body: 'x' });
      location.hash = '#/pages/dashboard';
    });
    return;
  }
  if (['/pages/dashboard', '/pages/settings'].includes(route) || route.startsWith('/pages/items/'))
    view.innerHTML = '<h1>' + route + '</h1><a href="https://planted-hash.invalid/' + route.split('/')[2] + '">x</a>';
  else location.replace('#/pages/dashboard');
}
window.addEventListener('hashchange', render);
setTimeout(render, 150);
</script>`);

function hashSite() {
  const hits = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    hits.push(`${req.method} ${url.pathname}`);
    if (url.pathname === '/api/sign-in' && req.method === 'POST') {
      req.resume();
      res.writeHead(204, { 'set-cookie': 'session=ok; Path=/' });
      return res.end();
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(HASH_APP);
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ server, hits, base: `http://127.0.0.1:${server.address().port}` })),
  );
}

/** Signs in through the hash app's own redirect: it opens the root route, not the sign-in route. */
const hashAdapter = (signIn = true) => ({
  async uiLogin(p, ctx) {
    await p.goto(`${ctx.webUrl}/`);
    await p.waitForSelector('input[name=email]');
    if (!signIn) return;
    await p.fill('input[name=email]', 'a@example.test');
    await p.fill('input[name=password]', PASSWORD);
    await Promise.all([p.waitForURL(/#\/pages\/dashboard$/), p.click('button')]);
  },
  async routeParams() {
    return { id: 'one' };
  },
});

const HASH_ROUTES = [{ path: '/pages/dashboard' }, { path: '/pages/items/:id' }, { path: '/pages/settings' }];

test('hash routing: routes opened in the fragment, the sign-in route read after the app redirects to it, declared, from a web_url ending in #, or detected', {
  skip: !chromium && 'no browser for playwright-core here',
  timeout: 240000,
}, async () => {
  const { server, hits, base } = await hashSite();
  try {
    for (const [web_url, ui_routing] of [
      [base, 'hash'],
      [`${base}/#`, undefined],
      [base, 'auto'],
    ]) {
      const outDir = mkdtempSync(join(tmpdir(), 'ever-browser-hash-'));
      const r = await walk({
        chromium,
        adapter: hashAdapter(),
        outDir,
        plan: { web_url, ui_routing, routes: HASH_ROUTES, idle_s: 0, page_timeout_s: 20 },
      });
      const label = `${web_url} ${ui_routing}`;
      assert.deepEqual(r.faults, [], label);
      assert.equal(r.routing, 'hash', label);
      assert.equal(r.signInPath, '/auth/login', label);
      assert.deepEqual(
        r.visits.map((v) => `${v.route} ${v.url.replace(base, '')} ${v.final_path}`),
        [
          '/pages/dashboard /#/pages/dashboard /pages/dashboard',
          '/pages/items/:id /#/pages/items/one /pages/items/one',
          '/pages/settings /#/pages/settings /pages/settings',
        ],
        label,
      );
      assert.deepEqual(r.redirected, [], label);
      const refs = JSON.parse(readFileSync(join(outDir, 'dom-refs.json'), 'utf8'));
      assert.ok(
        refs.some((x) => x.route === '/pages/items/:id' && x.url === 'https://planted-hash.invalid/items'),
        label,
      );
      assert.ok(
        refs.some((x) => x.route === '/auth/login' && x.url === 'https://planted-hash-signin.invalid/terms'),
        label,
      );
      const visits = JSON.parse(readFileSync(join(outDir, 'visits.json'), 'utf8'));
      assert.equal(visits.routing, 'hash');
      assert.equal(visits.sign_in_path, '/auth/login');
    }
    // One document: a hash route is never asked of the server.
    assert.ok(
      hits.every((h) => h === 'GET /' || h === 'POST /api/sign-in' || h === 'GET /favicon.ico'),
      hits.join(', '),
    );
  } finally {
    server.close();
  }
});

test('hash routing: a sign-in that does not hold is seen; a path-routed walk of a hash app is a fault that names ui_routing', {
  skip: !chromium && 'no browser for playwright-core here',
  timeout: 180000,
}, async () => {
  const { server, base } = await hashSite();
  try {
    const out = await walk({
      chromium,
      adapter: hashAdapter(false),
      outDir: mkdtempSync(join(tmpdir(), 'ever-browser-hash-')),
      plan: { web_url: base, ui_routing: 'hash', routes: HASH_ROUTES, idle_s: 0, page_timeout_s: 20 },
    });
    assert.equal(out.signInPath, '/auth/login');
    assert.ok(
      out.faults.some((f) =>
        /3 route\(s\) ended on the sign-in page \/auth\/login \(\/pages\/dashboard, \/pages\/items\/:id, \/pages\/settings\)/.test(f),
      ),
      out.faults.join('\n'),
    );
    const named = await walk({
      chromium,
      adapter: hashAdapter(false),
      outDir: mkdtempSync(join(tmpdir(), 'ever-browser-hash-')),
      plan: {
        web_url: base,
        ui_routing: 'hash',
        sign_in_route: '/auth/login',
        routes: HASH_ROUTES.slice(0, 1),
        idle_s: 0,
        page_timeout_s: 20,
      },
    });
    assert.ok(
      named.faults.some((f) => /ended on the sign-in page \/auth\/login/.test(f)),
      named.faults.join('\n'),
    );
    const path = await walk({
      chromium,
      adapter: hashAdapter(),
      outDir: mkdtempSync(join(tmpdir(), 'ever-browser-hash-')),
      plan: { web_url: base, ui_routing: 'path', routes: HASH_ROUTES.slice(0, 1), idle_s: 0, page_timeout_s: 20 },
    });
    assert.equal(path.routing, 'path');
    assert.ok(
      path.faults.some((f) => /1 route\(s\) ended on a #\/ fragment route .*set "ui_routing": "hash"/.test(f)),
      path.faults.join('\n'),
    );
  } finally {
    server.close();
  }
});
