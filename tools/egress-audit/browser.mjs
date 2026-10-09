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
// A sign-in that does not hold is a fault: the path of the first page uiLogin opens is the sign-in
// page, and a route that ends there was never rendered signed in.
//
// The plan comes from EVER_AUDIT_BROWSER_PLAN_B64 (base64 JSON) or plan.json next to this file
// (the harness builds it into the image); the result is one line `EVER_AUDIT_RESULT <json>`.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pageRefs } from './lib/dom-refs.mjs';
import { redactUrl, sanitizeHar } from './lib/har.mjs';

const PARAM = /:(\w+)([+*?]?)/g;

/** The path of a page's URL (no query or fragment), the label of what the sign-in pages render. */
export const pathOf = (url) => {
  try {
    return new URL(url).pathname;
  } catch {
    return '(unknown)';
  }
};

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

async function visit(page, url, timeoutMs, log) {
  let last = 'no answer';
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const res = await page.goto(url, { waitUntil: 'load', timeout: timeoutMs });
      const status = res?.status() ?? 200;
      if (status >= 500) throw new Error(`the page answered ${status}`);
      // A single-page app may keep a connection open (polling, a socket): load is enough then.
      await page.waitForLoadState('networkidle', { timeout: Math.min(15000, timeoutMs) }).catch(() => {});
      await page.waitForTimeout(500);
      const final = redactUrl(page.url());
      return { ok: true, status, final, final_path: pathOf(final), attempts: attempt };
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
 * fixtures}. Answers {ok, faults[], visits[], skipped[], signInPath, redirected[], counts}; an error
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
  const base = String(plan.web_url).replace(/\/$/, '');
  let signInPath = null;
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
    const page = await context.newPage();
    const ctx = {
      baseUrl: base,
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
      // The first page it loads is the sign-in page.
      const pending = [];
      const onLoad = () => {
        const at = pathOf(redactUrl(page.url()));
        if (signInPath === null && at !== '(unknown)' && !/^about:/.test(page.url())) signInPath = at;
        pending.push(pageRefs(page, at, redactUrl).then((r) => refs.push(...r)));
      };
      page.on('load', onLoad);
      try {
        await adapter.uiLogin(page, ctx);
      } catch (error) {
        faults.push(`adapter uiLogin failed: ${firstLine(error)}`);
      } finally {
        page.off('load', onLoad);
        await Promise.allSettled(pending);
      }
      if (signInPath === null)
        faults.push('adapter uiLogin opened no page: the sign-in must go through the product sign-in page (page.goto, then the form)');
      refs.push(...(await pageRefs(page, pathOf(redactUrl(page.url())), redactUrl)));
    }
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
      const url = `${base}${path}`;
      const v = await visit(page, url, timeoutMs, log);
      const row = { route: route.path, url: redactUrl(url), path: pathOf(redactUrl(url)), idle: idle.has(route.path), ...v };
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
  writeFileSync(join(outDir, 'visits.json'), `${JSON.stringify({ sign_in_path: signInPath, visits, skipped }, null, 1)}\n`);
  return {
    ok: faults.length === 0,
    faults,
    visits,
    skipped,
    signInPath,
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
