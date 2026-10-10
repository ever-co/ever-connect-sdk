# Egress audit: the browser leg

**Audience:** engineers who run the egress audit of a product that hosts the Ever Platform modules, and reviewers who read its results.
**Applies to:** `ever-egress-audit` in `@ever-co/connect-tools` (from `1.0.0-rc.3`; the stricter checks below from `1.0.0-rc.5`).
**Prerequisites:** the API leg set up as in [`tools/egress-audit/README.md`](../tools/egress-audit/README.md); Docker with `NET_RAW` and `NET_ADMIN`.

The API leg proves what the product's server processes do. It never sees what the product's UI does in a person's browser, and some products are mostly a UI. The browser leg runs a real browser against the product, in the same sealed Docker setup, and holds it to the same rule: with the modules off, the UI looks up no Ever host, requests none and renders no new link to one.

---

## 1. What it does

A run with a `web_service` in its config (and `--legs api,browser`, the default then) adds three containers:

| Container | What it is |
|---|---|
| the browser's holder | owns the browser's namespace (its interface and routes), at a fixed address inside the sealed setup, with CoreDNS (the audit's only resolver) in its `resolv.conf` |
| the browser's sniffer | `tcpdump` in that namespace from before the browser starts, routing every outside address to a sink so an attempt leaves a SYN to see (`browser.pcap`) |
| the browser | the Playwright image `mcr.microsoft.com/playwright:v1.62.1`, pinned by digest, running `browser.mjs` once as the image's unprivileged `pwuser` |

`browser.mjs`:

1. records a HAR (no bodies), every request and every WebSocket of one browser context;
2. signs in through the product's real sign-in page (the adapter's `uiLogin`); the first page `uiLogin` opens is the sign-in page (with hash routing, the route that page shows until the sign-in form is first used, so the app's own redirect to its sign-in route counts; `ui_sign_in_route` names it instead);
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
| sign-in | a route ends on the sign-in page (the sign-in failed or did not hold), or `uiLogin` opens no page: a fault |
| route list | a list generated from a router (`framework` and `entry`) lacks a route the router has now: a fault |

Exit codes are those of the audit: `0` pass, `1` a violation, `2` a fault with no violation (a page that never loaded, a sign-in that did not hold, a capture that did not run, the browser leg left out of a run whose config has a `web_service`). A run that leaves the leg out never passes. The report's `browser` section also lists the routes that ended somewhere else than asked (`redirected`), the sign-in page (`sign_in_path`) and whether the route list was compared with the router (`route_list`; a `manual` list is not).

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
  "base_commit": "<the product commit the entries were recorded from>",
  "entries": [
    { "route": "/", "attribute": "href", "url": "https://gauzy.co/", "reason": "footer link to the product site" }
  ]
}
```

Written once, from the branch before the first module change, with only the references that were already there; `base_commit` names that commit. It may only shrink, and its diff is reviewed:

- `ever-egress-audit check-baseline-shrink --base <ref> --config tools/egress-audit/egress-audit.config.json` reads the baseline path from the config's `ui_baseline` and fails (exit 1) when an entry was added since `<ref>`, when the file did not exist at `<ref>` (a renamed file is a new file), when the config pointed `ui_baseline` at another path at `<ref>`, or when `base_commit` changed or is not in the history.
- The change that adds the baseline runs it once with `--first-version`, and removes the flag afterwards: with the file present at `<ref>` the flag fails.
- It reads the history, so the CI checkout needs `fetch-depth: 0`.

An entry excuses that DOM reference and nothing else: never a DNS query, a connection attempt, a HAR entry or a request. The report lists entries no longer seen under `stale_baseline`, so they can be removed.

### `optin-hosts.json`: features an operator turns on

A feature that existed before the modules and can reach an Ever host (an update check, a news feed) is switched off by the product's default configuration, keeps its code, and is documented as an operator opt-in. Its host goes here:

```json
{ "hosts": [{ "host": "updates.example-product.ever.team", "setting": "UPDATE_CHECK_ENABLED=true", "reason": "the release check, off by default" }] }
```

Only the static scan honours this file, so the product's code may keep naming the host. The capture checks never read it: a run that calls the host still fails. Each host must be under an Ever-owned name, and none may be an Ever Platform service name (`ever.co`, or `api.`, `app.`, `auth.`, `apps.ever.co` and the names under them): an opt-in is an older default-off feature, never the platform itself. The static scan's `--baseline` accepts the baseline's references as their exact URLs only, never their whole host.

## 5. Config and adapter

Keys of `egress-audit.config.json` for the browser leg (schema: `tools/egress-audit/config.schema.json`):

| Key | Default | Meaning |
|---|---|---|
| `web_service` | required for `gauzy`, `teams`, `works`, `rec`, `traduora` | the compose service that serves the UI; `null` with `no_web_reason` to run a UI product without the leg (reviewed, stated) |
| `web_static` | `false` | `true` only when `web_service` serves static files (for example nginx with the built UI and no `proxy_pass`) |
| `web_url` | required with `web_service` | the UI's address inside the sealed setup, by the name of `web_service` or one of its aliases (for example `http://webapp:4200`) |
| `ui_routing` | `auto` | `path` (a route is the URL path), `hash` (a route is the path of a `#/` fragment, as Angular `useHash`: routes are opened at `web_url/#/route`, and the sign-in page, a route that ends on it and `redirected` are read from the fragment) or `auto` (hash when `web_url` ends in `#` or a page of the sign-in shows a `#/` route, else path). A path-routed walk whose routes end on `#/` routes faults, naming this key |
| `ui_sign_in_route` | taken from `uiLogin` | the route of the sign-in page (for example `/auth/login`), when it should not be taken from the first page `uiLogin` opens |
| `ui_routes` | `ui-routes.json` | the route list |
| `ui_routes_root` | the git repository root | where the route list's `entry` is, so the run can compare it with the router (`ui_routes_export`, `ui_routes_tsconfig`: Angular's `--export` and `--tsconfig`) |
| `route_params` | `route-params.json` when present | static parameter values |
| `ui_baseline` | `ui-baseline.json` when present | the DOM baseline |
| `idle_pages` | none | routes held open for `idle_s` (never also in `ui_skip_routes`) |
| `idle_s` | `30` | seconds per idle page |
| `ui_page_timeout_s` | `60` | seconds a page may take to load, before its one retry |
| `ui_skip_routes` | none | `[{path, reason}]`: routes not opened |
| `ui_expected_requests` | none | the positive control per mode, for example `{"positive_stats": ["GET /api/ever-stats/status"]}`; required for `positive_stats` |
| `optin_hosts` | `optin-hosts.json` | the opt-in list (static scan only) |
| `browser_image` | the pinned Playwright image | another image with the same Chromium build, pinned by digest (`name@sha256:...`) |

**The web service must be watched.** The browser leg watches the browser's own namespace. What the UI's server does (Next.js or SolidStart server rendering, API routes, a Node backend-for-frontend, an nginx `proxy_pass`) is captured, and resolved through the audit resolver, only when `web_service` is one of `process_services`. A config whose `web_service` is not in `process_services` is refused (exit 2) unless it sets `"web_static": true`, which says the service serves static files only. For a Next.js UI, list it in `process_services`:

```json
{ "process_services": ["api", "web"], "web_service": "web", "web_url": "http://web:3030" }
```

Adapter hooks (the adapter is copied into the browser image as well as the driver):

```js
export default {
  // ...the API hooks (login, createFixtures, openSettings, ...)
  async createFixtures(ctx) {
    // create what a person would create; what it answers (ids, never a token) reaches the browser hooks
    return { teamId: '...' };
  },
  async uiLogin(page, ctx) {
    // Playwright page; ctx: {baseUrl, webUrl, routing, routeUrl(route), apiUrl, mode, env, fixtures, fetch, log}.
    // baseUrl + a route is the route's URL: web_url, or web_url/# with "ui_routing": "hash".
    await page.goto(`${ctx.baseUrl}/auth/login`); // the first page opened: the sign-in page
    await page.fill('input[name=email]', 'admin@example.test');
    await page.fill('input[name=password]', SEED_PASSWORD); // a constant of the adapter: the seed account
    // End signed in: wait for the page after the sign-in, so a rejected password fails here.
    await Promise.all([page.waitForURL(/\/pages\//), page.click('button[type=submit]')]);
  },
  async routeParams(ctx) {
    return { teamId: ctx.fixtures.teamId };
  },
};
```

`SEED_PASSWORD` is a constant of the adapter (the seed account of the product's test data), as in `tools/egress-audit/selftest/adapter.mjs`. The browser container gets no product environment, so `process.env` holds nothing of the product there; the product's mode environment reaches the hooks as `ctx.env`. Nothing the hooks print is kept as is: `browser-walk.log` and the driver logs are scrubbed of cookie, authorization and password values.

**Hash routing.** An app that routes in the URL fragment (Angular `RouterModule.forRoot(routes, { useHash: true })`) sets `"ui_routing": "hash"` and gives `web_url` without the `#` (for example `"web_url": "http://webapp:4200", "ui_routing": "hash"`). The route list stays the router's paths (`/pages/dashboard`); the walk opens `http://webapp:4200/#/pages/dashboard`, and the sign-in page, a route that ends on it and the redirects are read from the fragment. A `web_url` ending in `#` (`http://webapp:4200/#`) is read the same way, for configs written before the key existed.

A sign-in that fails must not pass quietly: if `uiLogin` returns before it is signed in (a rejected password re-renders the form, a missing wait), every route redirects to the sign-in page and the run faults, naming them. `createFixtures` answers ids: a value shaped like a credential (a JWT, a `Bearer ` value, more than 64 characters) faults the run.

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
- run: npx ever-egress-audit check-baseline-shrink --base origin/${{ github.base_ref || 'develop' }} --config tools/egress-audit/egress-audit.config.json
- run: npx ever-egress-audit --config tools/egress-audit/egress-audit.config.json --mode off --artifacts egress-audit-artifacts
  env:
    # names kept out of the public files, from a secret (logs mask it; reports print extra#<n>)
    EVER_EGRESS_EXTRA_HOSTS: ${{ secrets.EVER_EGRESS_EXTRA_HOSTS }}
- if: always()
  uses: actions/upload-artifact@<sha> # pin by commit SHA
  with: { name: egress-audit, path: egress-audit-artifacts }
```

The checkout needs the history for the baseline check (`actions/checkout` with `fetch-depth: 0`).

Evidence lands next to the API leg's, in `<artifacts>/<mode>/`: `browser/browser.har`, `browser/requests.json`, `browser/dom-refs.json`, `browser/visits.json`, `browser-plan.json` (what the walk was given), `browser-walk.log`, `sniffer-browser.log`, `pcap/browser.pcap`, and a `browser` section in `report.json` with the counts of each check, the expected requests, the redirected routes, the route-list comparison and the stale baseline entries.

What the evidence keeps:

- The HAR, `requests.json`, `dom-refs.json` and `visits.json` hold no cookie, header value, form value, query value or body: URLs keep their query names only, and a path segment with an e-mail address or a JWT, and a `tel:` or `sms:` number, are redacted. Playwright's raw HAR is never written to the evidence: it is recorded in a private temporary directory and deleted on every path, errors included.
- `browser-plan.json` keeps the names of the mode environment and of the fixtures, never their values.
- `browser-walk.log` and the driver logs are scrubbed of cookie, set-cookie and authorization values, `Bearer` values, JWTs and password, secret and token fields.

Run the audit on seed data only, never on a copy of a production database: the rest of a URL path is kept.

## 7. Limits

- The image is about 3.5 GB; the first run pulls it (the run faults if the pull fails).
- Only `http://` UIs inside the sealed setup are walked.
- Chromium only. Playwright's launch defaults switch off the browser's own background traffic; the self-test's quiet page proves the browser looks up nothing but the compose names.
- Pages are walked in the order of the list, signed in once; a route that signs out or changes the account must be skipped.
