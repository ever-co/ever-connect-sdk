// The ui-routes generators on three fixture routers (Angular with a lazy NgModule level, a ROUTES
// factory and a re-exporting barrel through tsconfig paths; the Next app router with groups,
// locales and catch-alls; SolidStart), and the --check control: a router route missing from the
// committed list fails and is named.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { fillRoute, routeParamsFor } from '../browser.mjs';
import { compare, generate } from '../routes/cli.mjs';

const ROUTERS = fileURLToPath(new URL('./fixtures/routers/', import.meta.url));
const RUN = fileURLToPath(new URL('../run.mjs', import.meta.url));
const paths = (g) => g.routes.map((r) => r.path);

test('Angular: children, spreads of a local function, a lazy NgModule level (barrel, routing module), a lazy Routes export and a ROUTES factory', () => {
  const root = join(ROUTERS, 'angular');
  const g = generate({ framework: 'angular', entry: join(root, 'src/app/app.routes.ts'), root });
  assert.deepEqual(paths(g), [
    '/',
    '/auth/login',
    '/auth/register',
    '/pages/dashboard',
    '/pages/employees/:id',
    '/pages/employees/:id/edit',
    '/pages/integrations/ever-platform',
    '/pages/reports/amounts',
    '/pages/reports/time',
    '/pages/settings',
    '/pages/settings/features',
    '/pages/settings/general',
  ]);
  const byPath = Object.fromEntries(g.routes.map((r) => [r.path, r]));
  assert.equal(byPath['/'].redirect_to, 'pages');
  assert.equal(byPath['/pages/settings'].redirect_to, 'general');
  assert.equal(byPath['/auth/login'].file, 'lib/lazy/auth-routing.module.ts:6');
  assert.ok(g.routes.every((r) => r.source === 'router'));
  // What only exists at run time is named, so the product adds those routes by hand.
  assert.ok(g.notes.some((n) => /routes built at run time \(registry\.getRoutes\('page-sections'\)\)/.test(n)));
  assert.ok(g.notes.some((n) => /wildcard route/.test(n)));
});

test('Next app router: groups dropped, dynamic segments as parameters, parallel and private folders skipped, API routes ignored', () => {
  const root = join(ROUTERS, 'next-app');
  const g = generate({ framework: 'next-app', entry: join(root, 'app'), root });
  assert.deepEqual(paths(g), [
    '/:locale',
    '/:locale/catalog/:filters*',
    '/:locale/docs/:slug+',
    '/:locale/settings/team',
    '/:locale/work/:id',
  ]);
  assert.deepEqual(g.notes, [
    "app/[locale]/@modal/(.)photo/page.tsx: parallel route slot @modal is not walked (it renders inside its parent's page)",
  ]);
});

test('SolidStart: index files, groups, optional and catch-all parameters, API routes noted', () => {
  const root = join(ROUTERS, 'solidstart');
  const g = generate({ framework: 'solidstart', entry: join(root, 'src/routes'), root });
  assert.deepEqual(paths(g), ['/', '/:404*', '/about', '/blog/:page?', '/login', '/users/:id']);
  assert.deepEqual(g.notes, ['src/routes/api/hello.ts: an API route (no default export) is not walked']);
});

test('manual entries survive a new generation; compare names missing and stale router routes', () => {
  const root = join(ROUTERS, 'next-app');
  const existing = {
    routes: [
      { path: '/:locale/launcher-slot', source: 'manual' },
      { path: '/:locale/work/:id', source: 'manual' },
    ],
  };
  const g = generate({ framework: 'next-app', entry: join(root, 'app'), root, existing });
  assert.ok(paths(g).includes('/:locale/launcher-slot'));
  assert.equal(g.routes.filter((r) => r.path === '/:locale/work/:id').length, 1);
  const committed = {
    routes: g.routes.filter((r) => r.path !== '/:locale/settings/team').concat([{ path: '/:locale/old', source: 'router' }]),
  };
  assert.deepEqual(compare(g, committed), { missing: ['/:locale/settings/team'], stale: ['/:locale/old'] });
  assert.deepEqual(compare(g, g), { missing: [], stale: [] });
});

test('ever-egress-audit ui-routes writes the list; --check exits 1 naming a router route missing from it', () => {
  const root = join(ROUTERS, 'angular');
  const dir = mkdtempSync(join(tmpdir(), 'ever-ui-routes-'));
  const out = join(dir, 'ui-routes.json');
  const cli = (...extra) =>
    spawnSync(
      process.execPath,
      [RUN, 'ui-routes', '--framework', 'angular', '--root', root, '--entry', 'src/app/app.routes.ts', '--out', out, ...extra],
      {
        encoding: 'utf8',
      },
    );
  const w = cli();
  assert.equal(w.status, 0, w.stderr);
  assert.match(w.stdout, /12 router routes/);
  const written = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(written.framework, 'angular');
  assert.equal(written.entry, 'src/app/app.routes.ts');
  assert.equal(cli('--check').status, 0);
  copyFileSync(out, join(dir, 'full.json'));
  written.routes = written.routes.filter((r) => r.path !== '/pages/integrations/ever-platform');
  writeFileSync(out, JSON.stringify(written));
  const c = cli('--check');
  assert.equal(c.status, 1);
  assert.match(c.stderr, /router route missing from .*ui-routes\.json: \/pages\/integrations\/ever-platform/);
  // --check never writes.
  assert.ok(!readFileSync(out, 'utf8').includes('/pages/integrations/ever-platform'));
  assert.equal(
    spawnSync(process.execPath, [RUN, 'ui-routes', '--framework', 'vue', '--entry', 'x', '--out', out], { encoding: 'utf8' }).status,
    2,
  );
});

test('route parameters: plain values, per-route values, optional and catch-all segments', () => {
  const params = routeParamsFor('/:locale/work/:id', { locale: 'en', id: 'x' }, { '/:locale/work/:id': { id: 'w-1' } });
  assert.deepEqual(params, { locale: 'en', id: 'w-1' });
  assert.deepEqual(fillRoute('/:locale/work/:id', params), { path: '/en/work/w-1', missing: [] });
  assert.deepEqual(fillRoute('/:locale/docs/:slug+', { locale: 'en', slug: 'a/b c' }), { path: '/en/docs/a/b%20c', missing: [] });
  assert.deepEqual(fillRoute('/blog/:page?', {}), { path: '/blog', missing: [] });
  assert.deepEqual(fillRoute('/:locale/catalog/:filters*', { locale: 'en' }), { path: '/en/catalog', missing: [] });
  assert.deepEqual(fillRoute('/:404*', {}), { path: '/', missing: [] });
  assert.deepEqual(fillRoute('/team/:teamId/member/:memberId', { teamId: 't' }), { path: null, missing: ['memberId'] });
});
