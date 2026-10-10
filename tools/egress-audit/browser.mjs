#!/usr/bin/env node
// The browser leg's walk. run.mjs builds it into an image FROM the pinned Playwright image (with
// playwright-core and the product adapter) and runs it once per audit, with `docker compose run`,
// in the namespace of the browser's holder on the sealed audit network: CoreDNS is its only
// resolver and its own sniffer captures every connection attempt.
//
//   1. one browser context records a HAR (no bodies), every request and every WebSocket;
//   2. the adapter's uiLogin(page, ctx) signs in through the product's real sign-in page;
//   3. every route of the product's ui-routes.json is opened, with its parameters from
//      route-params.json and the adapter's routeParams(ctx); a page that fails to load is retried
//      once, then reported as a fault, never as a pass;
//   4. the idle pages (settings, integrations, catalog) stay open for idle_s;
//   5. every frame's DOM references are dumped after each load (and again after the idle time).
//
// Evidence goes to /out (browser.har, requests.json, dom-refs.json, visits.json). No cookie, token,
// header value, form value or query value is written: URLs keep their query names only. Playwright's
// raw HAR (which keeps cookies, header values and form fields) is recorded in a private temporary
// directory outside /out and deleted whatever happens, after browser.har is written from it.
//
// A sign-in that does not hold is a fault: the route of the first page uiLogin opens is the sign-in
// page, and a route that ends there was never rendered signed in.
//
// Routing (plan.ui_routing): "path" (a route is the URL path), "hash" (a route is the path of a `#/`
// fragment: Angular useHash, a hash router; routes are opened at web_url/#/route) or "auto" (the
// default: hash when web_url ends in a fragment or a page of the sign-in shows a `#/` route, else
// path). With hash routing the sign-in page is the route the first page shows until the sign-in
// form is first used or another document loads (the app's own redirect to its sign-in route
// included), unless the plan names it (sign_in_route). A path-routed walk whose routes end on `#/`
// routes is a fault that says so.
//
// The plan comes from EVER_AUDIT_BROWSER_PLAN_B64 (base64 JSON) or plan.json next to this file
// (the harness builds it into the image); the result is one line `EVER_AUDIT_RESULT <json>`.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pageRefs } from './lib/dom-refs.mjs';
import { fragmentRoute, redactRouteUrl, redactUrl, sanitizeHar } from './lib/har.mjs';

const PARAM = /:(\w+)([+*?]?)/g;

/** The path of a page's URL (no query or fragment), the label of what the sign-in pages render. */
export const pathOf = (url) => {
  try {
    return new URL(url).pathname;
  } catch {
    return '(unknown)';
  }
};

/**
 * The route a page shows: its URL path, or with hash routing the path of its `#/` fragment (`/`
 * when it has none, as a hash router reads it). Give it a redacted URL (redactRouteUrl).
 */
export const routeOf = (url, routing = 'path') => {
  if (routing !== 'hash') return pathOf(url);
  try {
    new URL(url);
  } catch {
    return '(unknown)';
  }
  return fragmentRoute(url) ?? '/';
};

/**
 * web_url read for the walk: {base, routing}. base has no fragment and no trailing slash; routing is
 * the declared one ("path" | "hash"), "hash" for a web_url that ends in a fragment (`http://web/#`)
 * under "auto", or null (auto: decided by the pages of the sign-in, else path).
 */
export function webBase(webUrl, routing = 'auto') {
  const text = String(webUrl ?? '');
  const at = text.indexOf('#');
  let base = at < 0 ? text : text.slice(0, at);
  let end = base.length;
  while (end > 0 && base[end - 1] === '/') end -= 1;
  base = base.slice(0, end);
  const declared = routing === 'hash' || routing === 'path' ? routing : at >= 0 ? 'hash' : null;
  return { base, routing: declared };
}

/** The URL a route is opened at: base + path, or with hash routing base + '/#' + path. */
export const routeUrl = (base, path, routing = 'path') => (routing === 'hash' ? `${base}/#${path}` : `${base}${path}`);

/** The parameter values for one route: the plain {name: value} entries, then the route's own {path: {name: value}}. */
export function routeParamsFor(path, ...sources) {
  const out = {};
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue;
    for (const [k, v] of Object.entries(source))
      if (!k.startsWith('/') && (typeof v === 'string' || typeof v === 'number')) out[k] = String(v);
    const own = source[path];
    if (own && typeof own === 'object') for (const [k, v] of Object.entries(own)) out[k] = String(v);
  }
  return out;
}

/**
 * A route pattern filled in: `:name` (one segment), `:name+` / `:name*` (catch-all; `*` may be
 * empty) and `:name?` (optional segment). Answers {path, missing[]}; path is null when a required
 * parameter has no value.
 */
export function fillRoute(pattern, params) {
  const missing = [];
  let path = pattern.replace(PARAM, (m, name, kind) => {
    const v = params[name];
    if (v === undefined || v === '') {
      if (kind === '?' || kind === '*') return '';
      missing.push(name);
      return m;
    }
    return kind === '+' || kind === '*' ? String(v).split('/').map(encodeURIComponent).join('/') : encodeURIComponent(v);
  });
  if (missing.length > 0) return { path: null, missing };
  path = path.replace(/\/{2,}/g, '/');
  if (path.length > 1) path = path.replace(/\/$/, '');
  return { path: path || '/', missing };
}

async function visit(page, url, timeoutMs, log, routing) {
  let last = 'no answer';
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const res = await page.goto(url, { waitUntil: 'load', timeout: timeoutMs });
      const status = res?.status() ?? 200;
      if (status >= 500) throw new Error(`the page answered ${status}`);
      // A single-page app may keep a connection open (polling, a socket): load is enough then.
      await page.waitForLoadState('networkidle', { timeout: Math.min(15000, timeoutMs) }).catch(() => {});
      await page.waitForTimeout(500);
      // A hash route opens in the same document (no load, no answer): the app routes it.
      const final = redactRouteUrl(page.url());
      return { ok: true, status, final, final_path: routeOf(final, routing), attempts: attempt };
    } catch (error) {
      last = String(error.message ?? error)
        .split('\n')[0]
        .slice(0, 200);
      log(`open ${redactUrl(url)} (attempt ${attempt}): ${last}`);
    }
  }
  return { ok: false, error: last, attempts: 2 };
}

const firstLine = (error) =>
  String(error?.message ?? error)
    .split('\n')[0]
    .slice(0, 200);

/**
 * The walk. opts: {chromium, plan, adapter, outDir, log, tmpDir}. plan: {web_url, api_url,
 * routes[{path}], idle_pages[], idle_s, page_timeout_s, skip[{path, reason}], params{}, mode, env{},
 * fixtures, ui_routing?, sign_in_route?}. Answers {ok, faults[], visits[], skipped[], signInPath,
 * routing, redirected[], counts}; an error
 * of the walk itself is a fault, and the evidence gathered until then is still written.
 */
export async function walk({ chromium, plan, adapter = {}, outDir, log = () => {}, tmpDir = tmpdir() }) {
  mkdirSync(outDir, { recursive: true });
  // The raw recording never lands in outDir, which is copied out as evidence.
  const rawDir = mkdtempSync(join(tmpDir, 'ever-audit-har-'));
  const rawHar = join(rawDir, 'raw.har');
  const faults = [];
  const visits = [];
  const skipped = [];
  const refs = [];
  const requests = [];
  const pending = new Map();
  const idle = new Set(plan.idle_pages ?? []);
  const skip = new Map((plan.skip ?? []).map((s) => [s.path, s.reason]));
  const timeoutMs = (plan.page_timeout_s ?? 60) * 1000;
  const { base, routing: declared } = webBase(plan.web_url, plan.ui_routing);
  // null until decided (auto): by a `#/` route on a page of the sign-in, else path.
  let routing = declared;
  let signInPath = plan.sign_in_route ?? null;
  let browser;
  let context;
  try {
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext({
      recordHar: { path: rawHar, content: 'omit', mode: 'full' },
      viewport: { width: 1366, height: 900 },
      serviceWorkers: 'allow',
    });
    context.on('request', (r) => {
      const row = { method: r.method(), url: redactUrl(r.url()), resource: r.resourceType(), status: 0 };
      pending.set(r, row);
      requests.push(row);
    });
    context.on('requestfinished', async (r) => {
      const row = pending.get(r);
      if (!row) return;
      try {
        row.status = (await r.response())?.status() ?? 0;
      } catch {
        // the page went away before its answer was read
      }
    });
    context.on('requestfailed', (r) => {
      const row = pending.get(r);
      if (row) row.failure = String(r.failure()?.errorText ?? 'failed').slice(0, 120);
    });
    const watchSockets = (p) =>
      p.on('websocket', (ws) => requests.push({ method: 'WS', url: redactUrl(ws.url()), resource: 'websocket', status: 0 }));
    context.on('page', watchSockets);
    // With hash (or not yet known) routing, the first use of the sign-in form settles the sign-in
    // route: a trusted input, key, pointer or submit event in any frame, told once per document.
    // The sign-in page is dumped again then: a router renders it after the load.
    let signingIn = false;
    let formUsed = false;
    let onFormUsed = () => {};
    if (routing !== 'path') {
      await context.exposeBinding('__everAuditFormUsed', () => {
        if (!signingIn || formUsed) return;
        formUsed = true;
        onFormUsed();
      });
      await context.addInitScript(() => {
        let told = false;
        const tell = (e) => {
          if (told || !e.isTrusted || typeof window.__everAuditFormUsed !== 'function') return;
          told = true;
          window.__everAuditFormUsed();
        };
        for (const type of ['input', 'change', 'keydown', 'pointerdown', 'submit']) window.addEventListener(type, tell, true);
      });
    }
    const page = await context.newPage();
    const ctx = {
      // baseUrl + a route path is the route's URL (web_url/# with hash routing); so is routeUrl(path).
      baseUrl: routing === 'hash' ? `${base}/#` : base,
      webUrl: base,
      routing: routing ?? 'auto',
      routeUrl: (path) => routeUrl(base, path, routing ?? 'path'),
      apiUrl: plan.api_url,
      mode: plan.mode,
      env: plan.env ?? {},
      fixtures: plan.fixtures ?? null,
      fetch,
      log,
    };

    if (typeof adapter.uiLogin === 'function') {
      // Every page the sign-in goes through is dumped when it loads, and the page it ends on after
      // it, each under its own path (the sign-in page, then the landing page).
      // The first page it loads is the sign-in page; with hash routing, the route that page shows
      // until the form is first used or another document loads (the app's own redirect to its
      // sign-in route included). A sign_in_route of the plan is taken as it is.
      const pending = [];
      let opened = false;
      let settled = signInPath !== null;
      let lastDoc = null;
      const detect = (raw) => {
        if (routing === null && fragmentRoute(raw) !== null) routing = 'hash';
      };
      const onLoad = () => {
        const raw = page.url();
        detect(raw);
        const at = routeOf(redactRouteUrl(raw), routing ?? 'path');
        if (at !== '(unknown)' && !/^about:/.test(raw)) {
          opened = true;
          if (signInPath === null) signInPath = at;
        }
        pending.push(pageRefs(page, at, redactUrl).then((r) => refs.push(...r)));
      };
      const onNavigated = (frame) => {
        if (frame !== page.mainFrame()) return;
        const raw = frame.url();
        detect(raw);
        const doc = raw.split('#')[0];
        const sameDoc = lastDoc === doc;
        lastDoc = doc;
        if (signInPath === null || /^about:/.test(raw)) return;
        if (!sameDoc || formUsed) settled = true;
        if (settled || routing !== 'hash') return;
        const at = routeOf(redactRouteUrl(raw), 'hash');
        if (at !== '(unknown)') signInPath = at;
      };
      onFormUsed = () => {
        const at = routing === 'hash' && signInPath !== null ? signInPath : routeOf(redactRouteUrl(page.url()), routing ?? 'path');
        pending.push(pageRefs(page, at, redactUrl).then((r) => refs.push(...r)));
      };
      page.on('load', onLoad);
      page.on('framenavigated', onNavigated);
      signingIn = true;
      try {
        await adapter.uiLogin(page, ctx);
      } catch (error) {
        faults.push(`adapter uiLogin failed: ${firstLine(error)}`);
      } finally {
        signingIn = false;
        page.off('load', onLoad);
        page.off('framenavigated', onNavigated);
        await Promise.allSettled(pending);
      }
      if (!opened)
        faults.push('adapter uiLogin opened no page: the sign-in must go through the product sign-in page (page.goto, then the form)');
      detect(page.url());
      refs.push(...(await pageRefs(page, routeOf(redactRouteUrl(page.url()), routing ?? 'path'), redactUrl)));
    }
    routing ??= 'path';
    let params = {};
    if (typeof adapter.routeParams === 'function') {
      try {
        params = (await adapter.routeParams(ctx)) ?? {};
      } catch (error) {
        faults.push(`adapter routeParams failed: ${firstLine(error)}`);
      }
    }

    for (const route of plan.routes ?? []) {
      if (skip.has(route.path)) {
        skipped.push({ route: route.path, reason: skip.get(route.path) });
        continue;
      }
      const { path, missing } = fillRoute(route.path, routeParamsFor(route.path, plan.params, params));
      if (!path) {
        faults.push(
          `route ${route.path} has no value for ${missing.join(', ')} (give one in route-params.json or routeParams, or list the route in ui_skip_routes)`,
        );
        skipped.push({ route: route.path, reason: `no value for ${missing.join(', ')}` });
        continue;
      }
      const url = routeUrl(base, path, routing);
      const v = await visit(page, url, timeoutMs, log, routing);
      const row = {
        route: route.path,
        url: redactRouteUrl(url),
        path: routeOf(redactRouteUrl(url), routing),
        idle: idle.has(route.path),
        ...v,
      };
      visits.push(row);
      if (!v.ok) {
        faults.push(`route ${route.path} did not load after one retry: ${v.error}`);
        continue;
      }
      refs.push(...(await pageRefs(page, route.path, redactUrl)));
      if (row.idle) {
        await page.waitForTimeout((plan.idle_s ?? 30) * 1000);
        row.idle_s = plan.idle_s ?? 30;
        refs.push(...(await pageRefs(page, route.path, redactUrl)));
      }
    }
    const loaded = visits.filter((v) => v.ok);
    if (visits.length === 0) faults.push('no route was opened');
    else if (loaded.length > 0 && loaded.every((v) => v.status >= 400))
      faults.push(`every route answered 4xx (for example ${loaded[0].route}: ${loaded[0].status}); web_url or the sign-in is wrong`);
    // A route that ends on the sign-in page was never rendered signed in.
    if (signInPath !== null) {
      const out = loaded.filter((v) => v.final_path === signInPath && v.path !== signInPath).map((v) => v.route);
      if (out.length > 0)
        faults.push(
          `${out.length} route(s) ended on the sign-in page ${signInPath} (${out.slice(0, 5).join(', ')}${out.length > 5 ? ', ...' : ''}): the sign-in failed or did not hold; uiLogin must end signed in (wait for the page after the sign-in)`,
        );
    }
    // A path-routed walk of an app that routes in the fragment opened none of its routes.
    if (routing === 'path') {
      const hashed = loaded.filter((v) => fragmentRoute(v.final) !== null).map((v) => `${v.route} -> #${fragmentRoute(v.final)}`);
      if (hashed.length > 0)
        faults.push(
          `${hashed.length} route(s) ended on a #/ fragment route (${hashed.slice(0, 3).join(', ')}${hashed.length > 3 ? ', ...' : ''}): the product routes in the URL fragment; set "ui_routing": "hash" in the config`,
        );
    }
  } catch (error) {
    faults.push(`the browser walk failed: ${firstLine(error)}`);
  } finally {
    await context?.close().catch((error) => faults.push(`the browser context did not close: ${firstLine(error)}`));
    await browser?.close().catch(() => {});
  }

  // The HAR: sanitized into outDir, then the raw recording is deleted, on every path.
  try {
    if (existsSync(rawHar)) {
      const har = sanitizeHar(JSON.parse(readFileSync(rawHar, 'utf8')));
      writeFileSync(join(outDir, 'browser.har'), `${JSON.stringify(har, null, 1)}\n`);
    } else faults.push('the browser wrote no HAR');
  } catch (error) {
    faults.push(`the browser HAR could not be read: ${firstLine(error)}`);
  } finally {
    rmSync(rawDir, { recursive: true, force: true });
  }
  const unique = [...new Map(refs.map((r) => [`${r.route}|${r.frame}|${r.attribute}|${r.url}`, r])).values()];
  writeFileSync(join(outDir, 'dom-refs.json'), `${JSON.stringify(unique, null, 1)}\n`);
  writeFileSync(join(outDir, 'requests.json'), `${JSON.stringify(requests, null, 1)}\n`);
  writeFileSync(
    join(outDir, 'visits.json'),
    `${JSON.stringify({ routing: routing ?? 'path', sign_in_path: signInPath, visits, skipped }, null, 1)}\n`,
  );
  return {
    ok: faults.length === 0,
    faults,
    visits,
    skipped,
    signInPath,
    routing: routing ?? 'path',
    redirected: visits.filter((v) => v.ok && v.final_path !== v.path).map((v) => `${v.route} -> ${v.final_path}`),
    counts: { visits: visits.length, loaded: visits.filter((v) => v.ok).length, refs: unique.length, requests: requests.length },
  };
}

async function main() {
  const fromEnv = Buffer.from(process.env.EVER_AUDIT_BROWSER_PLAN_B64 ?? '', 'base64').toString('utf8');
  const planFile = new URL('./plan.json', import.meta.url);
  const plan = JSON.parse(fromEnv || (existsSync(planFile) ? readFileSync(planFile, 'utf8') : '{}'));
  const log = (...a) => process.stderr.write(`${a.join(' ')}\n`);
  const result = (value) => process.stdout.write(`EVER_AUDIT_RESULT ${JSON.stringify(value)}\n`);
  let adapter = {};
  try {
    if (existsSync(new URL('./adapter.mjs', import.meta.url))) adapter = (await import('./adapter.mjs')).default ?? {};
  } catch (error) {
    return result({ ok: false, faults: [`the adapter did not load in the browser: ${error.message}`] });
  }
  let chromium;
  try {
    ({ chromium } = await import('playwright-core'));
  } catch (error) {
    return result({ ok: false, faults: [`playwright-core did not load: ${error.message}`] });
  }
  try {
    const r = await walk({ chromium, plan, adapter, outDir: plan.out ?? '/out', log });
    return result({ ok: r.ok, faults: r.faults, counts: r.counts });
  } catch (error) {
    return result({ ok: false, faults: [`the browser walk failed: ${String(error.message ?? error).split('\n')[0]}`] });
  }
}

if (process.argv[1] && process.argv[1].endsWith('browser.mjs')) await main();
