# Egress audit: the browser leg

**Audience:** engineers who run the egress audit of a product that hosts the Ever Platform modules, and reviewers who read its results.
**Applies to:** `ever-egress-audit` in `@ever-co/connect-tools` (from `1.0.0-rc.3`).
**Prerequisites:** the API leg set up as in [`tools/egress-audit/README.md`](../tools/egress-audit/README.md); Docker with `NET_RAW` and `NET_ADMIN`.

The API leg proves what the product's server processes do. It never sees what the product's UI does in a person's browser, and some products are mostly a UI. The browser leg runs a real browser against the product, in the same sealed Docker setup, and holds it to the same rule: with the modules off, the UI looks up no Ever host, requests none and renders no new link to one.

---

## 1. What it does

A run with a `web_service` in its config (and `--legs api,browser`, the default then) adds three containers:

| Container | What it is |
|---|---|
| the browser's holder | owns the browser's namespace (its interface and routes), at a fixed address inside the sealed setup, with CoreDNS (the audit's only resolver) in its `resolv.conf` |
| the browser's sniffer | `tcpdump` in that namespace from before the browser starts, routing every outside address to a sink so an attempt leaves a SYN to see (`browser.pcap`) |
| the browser | the Playwright image `mcr.microsoft.com/playwright:v1.62.1`, pinned by digest, running `browser.mjs` once |

`browser.mjs`:

1. records a HAR (no bodies), every request and every WebSocket of one browser context;
2. signs in through the product's real sign-in page (the adapter's `uiLogin`);
3. opens every route of the product's `ui-routes.json`, with parameter values from `route-params.json` and the adapter's `routeParams`; a page that fails to load is retried once, then reported as a fault;
4. holds each idle page (settings, integrations, catalog) open for `idle_s` seconds (30 by default);
5. dumps every URL the rendered page points at, in every frame and open shadow root: `href`, `src`, `srcset`, `action`, `formaction`, `poster`, `ping`, `data`, `xlink:href`, a meta refresh and `url()` in a `style` attribute.

The leg runs in the modes `off`, `loaded_off` and `positive_stats`.

## 2. What is checked

| Check | Fails when |
|---|---|
| (e) DNS and capture | the browser looks up a name outside the compose services and `allowed_external_hosts` (the CoreDNS log lines from its address and the questions its sniffer saw), or a connection attempt leaves the sealed setup |
| (f) HAR | a HAR entry, request or WebSocket goes to a never-allowed host |
| (g) DOM | a rendered reference points at a never-allowed host and `ui-baseline.json` does not list the same route, attribute and URL |
| positive control | in a positive mode, a request of `ui_expected_requests` (for example `GET /api/ever-stats/status`) was not made to a compose service |

Exit codes are those of the audit: `0` pass, `1` a violation, `2` a fault with no violation (a page that never loaded, a capture that did not run, the browser leg left out of a run whose config has a `web_service`). A run that leaves the leg out never passes.

## 3. The never-allowed list

`tools/egress-audit/ever-hosts.json` is the one list of the API leg, the browser leg and the static scan:

- **Ever-owned names**: `ever.co`, `ever.team`, `gauzy.co`, `ever.works`, `rec.so`, `traduora.co`, `everdemand.co`, `ever.sh`, `githands.com`;
- **analytics sinks**: `posthog.com`, `i.posthog.com`, `sentry.io`, `jitsu.com`, `google-analytics.com`, `googletagmanager.com`, `chatwoot.com`.

Each entry matches the name and every name under it (`api.`, `app.`, `data.`, ...), compared lower-cased, without a trailing dot and in ASCII form. A product cannot allow-list its way out: the config schema refuses a listed name in `allowed_external_hosts`, and checks (e) and (f) fail on one whatever the configuration says. `EVER_EGRESS_EXTRA_HOSTS` (comma-separated names) adds names to the list for a run; nothing removes one.

The static scan (`ever-egress-audit static-hostnames`) looks for the Ever-owned names only, since analytics clients products already ship stay in their code, switched off by default.

## 4. The product's files

All of them sit next to the product's `egress-audit.config.json`.

### `ui-routes.json`: the routes to open

Generated from the product's router, and checked in CI so a new page cannot escape the walk:

```sh
# Angular: the file that declares the root Routes (name the array with --export when there are several)
npx ever-egress-audit ui-routes --framework angular --entry apps/gauzy/src/app/app.routes.ts --out tools/egress-audit/ui-routes.json
# Next.js app router: the app directory
npx ever-egress-audit ui-routes --framework next-app --entry apps/web/app --out tools/egress-audit/ui-routes.json
# SolidStart: the file routes
npx ever-egress-audit ui-routes --framework solidstart --entry src/routes --out tools/egress-audit/ui-routes.json

# in CI: exits 1 naming each router route missing from the committed list (and each one the router dropped)
npx ever-egress-audit ui-routes --framework next-app --entry apps/web/app --out tools/egress-audit/ui-routes.json --check
```

- Parameters are written `:name` (one segment), `:name?` (optional), `:name+` and `:name*` (catch-all). Next.js `(group)` folders are dropped, `_private` folders, parallel `@slot` and intercepting `(.)` routes are skipped with a note. Angular children, spreads of route arrays, functions that return them, `loadChildren` (a `Routes` export, or an NgModule's `RouterModule.forChild` and `ROUTES` providers, through its imported modules) and `loadComponent` are followed across relative imports and the tsconfig `paths`; guards and redirects are kept as metadata. The Angular generator uses the product's own `typescript`.
- A route only the running app knows (a service that adds routes at start, a route matcher) is printed as a note. Add such routes by hand with `"source": "manual"`: generating again keeps them.
- A route that signs the person out (for example `/auth/logout`) belongs in `ui_skip_routes`, with its reason.

### `route-params.json`: parameter values

`{"locale": "en", "id": "..."}`, or per route: `{"/:locale/team/:teamId": {"teamId": "..."}}`. Values only a run knows (the id of something the adapter created) come from the adapter's `routeParams(ctx)`, merged over this file. A route with a parameter that has no value faults the run unless `ui_skip_routes` lists it.

### `ui-baseline.json`: links that predate the modules

```json
{
  "entries": [
    { "route": "/", "attribute": "href", "url": "https://gauzy.co/", "reason": "footer link to the product site" }
  ]
}
```

Written once, from the branch before the first module change, with only the references that were already there. It may only shrink: `ever-egress-audit check-baseline-shrink --base <ref> --file tools/egress-audit/ui-baseline.json` fails when an entry was added since `<ref>`. An entry excuses that DOM reference and nothing else: never a DNS query, a connection attempt, a HAR entry or a request. The report lists entries no longer seen under `stale_baseline`, so they can be removed.

### `optin-hosts.json`: features an operator turns on

A feature that existed before the modules and can reach an Ever host (an update check, a news feed) is switched off by the product's default configuration, keeps its code, and is documented as an operator opt-in. Its host goes here:

```json
{ "hosts": [{ "host": "updates.example-product.ever.team", "setting": "UPDATE_CHECK_ENABLED=true", "reason": "the release check, off by default" }] }
```

Only the static scan honours this file, so the product's code may keep naming the host. The capture checks never read it: a run that calls the host still fails. Each host must be under an Ever-owned name.

## 5. Config and adapter

Keys of `egress-audit.config.json` for the browser leg (schema: `tools/egress-audit/config.schema.json`):

| Key | Default | Meaning |
|---|---|---|
| `web_service` | none (no browser leg) | the compose service that serves the UI |
| `web_url` | required with `web_service` | the UI's address inside the sealed setup, by service name (for example `http://webapp:4200`) |
| `ui_routes` | `ui-routes.json` | the route list |
| `route_params` | `route-params.json` when present | static parameter values |
| `ui_baseline` | `ui-baseline.json` when present | the DOM baseline |
| `idle_pages` | none | routes held open for `idle_s` |
| `idle_s` | `30` | seconds per idle page |
| `ui_page_timeout_s` | `60` | seconds a page may take to load, before its one retry |
| `ui_skip_routes` | none | `[{path, reason}]`: routes not opened |
| `ui_expected_requests` | none | the positive control per mode, for example `{"positive_stats": ["GET /api/ever-stats/status"]}`; required for `positive_stats` |
| `optin_hosts` | `optin-hosts.json` | the opt-in list (static scan only) |
| `browser_image` | the pinned Playwright image | another image with the same Chromium build |

Adapter hooks (the adapter is copied into the browser image as well as the driver):

```js
export default {
  // ...the API hooks (login, createFixtures, openSettings, ...)
  async createFixtures(ctx) {
    // create what a person would create; what it answers (ids, never a token) reaches the browser hooks
    return { teamId: '...' };
  },
  async uiLogin(page, ctx) {
    // Playwright page; ctx: {baseUrl (web_url), apiUrl, mode, env, fixtures, fetch, log}
    await page.goto(`${ctx.baseUrl}/auth/login`);
    await page.fill('input[name=email]', 'admin@example.test');
    await page.fill('input[name=password]', process.env.SEED_PASSWORD ?? 'admin');
    await Promise.all([page.waitForURL(/\/pages\//), page.click('button[type=submit]')]);
  },
  async routeParams(ctx) {
    return { teamId: ctx.fixtures.teamId };
  },
};
```

The browser reaches the product by service name, so the UI's own API address must be one the browser can reach inside the sealed setup (a compose service name, not `localhost`).

## 6. Running it

```sh
# locally (Docker): the API and browser legs in one run
npx ever-egress-audit --config tools/egress-audit/egress-audit.config.json --mode off --artifacts egress-audit-artifacts
# the harness's own self-test, failing controls included
npx ever-egress-audit --selftest --legs api,browser
```

In CI, on a runner with Docker (`ubuntu-latest` works), after the route check:

```yaml
- run: npx ever-egress-audit ui-routes --framework next-app --entry apps/web/app --out tools/egress-audit/ui-routes.json --check
- run: npx ever-egress-audit check-baseline-shrink --base origin/${{ github.base_ref || 'develop' }} --file tools/egress-audit/ui-baseline.json
- run: npx ever-egress-audit --config tools/egress-audit/egress-audit.config.json --mode off --artifacts egress-audit-artifacts
- if: always()
  uses: actions/upload-artifact@<sha> # pin by commit SHA
  with: { name: egress-audit, path: egress-audit-artifacts }
```

Evidence lands next to the API leg's, in `<artifacts>/<mode>/`: `browser/browser.har`, `browser/requests.json`, `browser/dom-refs.json`, `browser/visits.json`, `browser-plan.json` (what the walk was given), `sniffer-browser.log`, `pcap/browser.pcap`, and a `browser` section in `report.json` with the counts of each check, the expected requests and the stale baseline entries. No artefact holds a cookie, header value, form value, query value or body: URLs keep their query names only.

## 7. Limits

- The image is about 3.5 GB; the first run pulls it (the run faults if the pull fails).
- Only `http://` UIs inside the sealed setup are walked.
- Chromium only. Playwright's launch defaults switch off the browser's own background traffic; the self-test's quiet page proves the browser looks up nothing but the compose names.
- Pages are walked in the order of the list, signed in once; a route that signs out or changes the account must be skipped.
