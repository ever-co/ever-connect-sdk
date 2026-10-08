# ever-egress-audit

The egress audit of a product that hosts the Ever Platform modules. It runs the product's own
compose files with every Docker network sealed, watches every DNS query and every connection
attempt of each product process from before the process starts, drives the product from inside the
sealed Docker network, and fails the run when the product looks up an Ever host, tries to reach anything
outside the compose services, answers a module route while the modules are off, or makes an Ever
Platform call its mode does not allow. Its browser leg does the same for the product's UI: a real
browser in its own sniffed namespace signs in, opens every route of the product's router and fails
the run when the UI looks up, requests or links a never-allowed host (see
[Browser leg](#browser-leg) and [docs/egress-audit.md](../../docs/egress-audit.md)).

```sh
ever-egress-audit --config egress-audit.config.json --mode off [--legs api,browser]
ever-egress-audit --selftest
```

In this repository the same commands are `node tools/egress-audit/run.mjs ...`; products use the
`ever-egress-audit` bin of the dev-only `@ever-co/connect-tools` package and keep only their config,
adapter and workflow.

## Modes

| Mode | Product environment | Passes when |
|---|---|---|
| `off` | both modules off | no Ever host looked up, no connection attempt out, every module route answers 404 |
| `loaded_off` | modules loaded, statistics switched off by the operator, not connected | no call at all before an operator acts |
| `positive_stats` | statistics on, against the mock platform | at least one signed, schema-valid report accepted (202), no other call |
| `positive_connect` | connection module on with a mock connect code | exactly the key manifest, redeem, token, heartbeat, event feed, entitlement and integration states |
| `every_trigger` | both modules on, every trigger exercised by the adapter | the call record equals the product's generated outbound-call list, row for row |
| `positive_managed` | connection module on, a managed operation requested | after the request, only the feed read and the result call |

`modes.json` holds the environment of each mode. A product adds its own modes (for example
"connection off, sign-in on") under `modes` in its config, in the same shape and under a name of
its own: a config that redefines one of the modes above is refused. Every mode also asserts the DNS
and connection rules below.

In a mode's environment (and an adapter's `env`), `__MOCK_URL__` is the mock platform's address and
`__MOCK_ISSUER__` the issuer its documents name. The positive modes give the product:

| Variable | Value | Why |
|---|---|---|
| `EVER_PLATFORM_API_URL`, `EVER_STATS_API_URL` | `__MOCK_URL__`: `http://<subnet>.252:8080`, the mock's fixed address on the sealed network | the SDK accepts plain http only from a local address (a private range), never from a bare name such as `mock-platform` |
| `EVER_PLATFORM_ISSUER` | `__MOCK_ISSUER__`: `https://mock-platform.test` (or the `issuer` of `mock_config`) | the documents name an https issuer; the product passes it to the SDK client (`issuer`), which honours it for a local base URL only |
| `EVER_PLATFORM_ROOT_KEYS_FILE` | `/ever-audit/roots.json` | the harness copies the mock's TEST root, for that issuer, to this path before the product starts |

The mock keeps its compose name `mock-platform` as an alias for the driver. A product's own `subnet`
must be a /24 of a private range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) for the mock's
address to count as local (see [docs/mock-platform.md](../../docs/mock-platform.md)).

## What is checked

`assert.mjs` reads the evidence and writes `report.json`:

1. **DNS.** Every name queried, of any record type, must be a compose service name (or alias, or
   container name), or in `allowed_external_hosts`. Any name of the never-allowed list
   (`ever-hosts.json`: the Ever-owned names `ever.co`, `ever.team`, `gauzy.co`, `ever.works`,
   `rec.so`, `traduora.co`, `everdemand.co`, `ever.sh`, `githands.com` and the analytics sinks, each
   with every name under it) fails, whatever the allow-list says (the config schema refuses them).
   Reverse lookups of addresses inside the sealed Docker networks are allowed.
2. **Connection attempts.** No TCP SYN and no UDP datagram to an address outside the
   sealed Docker networks; loopback is inside. A DNS question counts too: one sent to the audit
   resolver stays inside, one sent straight to any other resolver fails, whatever its type.
3. **Product logs.** No `ENOTFOUND`, `ECONNREFUSED`, `EAI_AGAIN`, `ENETUNREACH` or `EHOSTUNREACH`
   for a host outside the compose services and the sealed Docker networks (a database that is not
   up yet is inside).
4. **Module routes.** In `off`, every route in `module_routes` (at least one) answers 404.
5. **Call record.** In positive modes, the mock platform's record matches the mode's rows
   (`assert-call-log.mjs`).

The browser leg adds (e) the browser's DNS queries and capture under rules 1 and 2, (f) no HAR
entry, request or WebSocket to a never-allowed host, (g) no rendered reference to one outside the
product's `ui-baseline.json`, and the positive control of `ui_expected_requests` (see
[Browser leg](#browser-leg)).

Exit codes: `0` pass, `1` a violation, `2` a harness fault or a usage error. A run with a fault and
no violation proves nothing and exits 2, naming the fault (for example `CAP_NET_RAW was refused, so
tcpdump cannot capture`). A proven violation exits 1 even when part of the run faulted.

## How a run works

`run.mjs` adds an overlay (`compose.audit.yml`, filled in per run) after the product's compose
files:

- **Sealed Docker networks.** Every Docker network of the compose files becomes `internal: true` (no route out); the
  default one gets a fixed /24. What the overlay cannot seal is refused before anything starts: a
  Docker network declared `external`, and a service with `network_mode` other than `none` or
  `service:<compose service>` (the host's namespace or another container's).
- **One resolver.** CoreDNS (`Corefile`) is the only resolver of the product processes. It logs
  every query, answers the compose names (through Docker's resolver of its own container) and
  NXDOMAIN for every other name, so nothing outside the compose services can be reached by name.
- **One sniffer per product process.** Each service in `process_services` gets a namespace holder
  that owns its network namespace, carries the service's name as an alias and points the shared
  `resolv.conf` at CoreDNS. A `nicolaka/netshoot` sniffer joins that namespace with `NET_RAW` and
  `NET_ADMIN`, routes every address outside the sealed Docker networks to a sink that forwards nothing
  (so an attempt leaves a SYN to see instead of failing silently), and starts `tcpdump` before the
  product process starts. The product joins the same namespace (`network_mode: service:<holder>`).
- **The mock platform** runs only in positive modes, built from the bundled mock (or `mock_image`),
  with a real-time clock so products sign with their own clock, at the fixed address `<subnet>.252`
  of the sealed default network (the products reach it there; the driver by its alias).
- **The driver.** A small container on the sealed Docker network waits for `health_url`, runs the
  adapter's hooks, requests the managed operation (`positive_managed`), probes the module routes
  and reads the mock's record. Its own traffic never passes through a sniffed namespace.

Nothing is mounted from the host: images are built from their directories and files are copied in
with `docker cp`, so the audit runs the same on a laptop, on `ubuntu-latest` and on self-hosted
Kubernetes runners with Docker.

Evidence lands in `<artifacts>/<mode>/`: `report.json`, `evidence.json`, `dns.log`,
`sniffer-<service>.log`, `pcap/<service>.pcap`, `product-<service>.log`, `requests.json` (positive
modes), the generated overlay and the driver logs. `ever-egress-audit assert --evidence
evidence.json` reproduces the verdict.

## Config

`egress-audit.config.json` (schema: `config.schema.json`; paths relative to the file):

```json
{
  "product": "gauzy",
  "compose": ["docker-compose.yml"],
  "api_service": "api",
  "process_services": ["api", "worker"],
  "health_url": "http://api:3000/api/health",
  "module_routes": ["/api/ever-connect/status", "/api/ever-stats/status"],
  "adapter": "egress-audit.adapter.mjs",
  "wait_s": 120
}
```

`wait_s` is how long the product is watched after the scenario (default 120). Other fields: `services` (what to start; default every service), `build` (`docker compose up
--build`), `health_timeout_s`, `allowed_external_hosts`, `env_prefix` (replaces the leading `EVER_`
of every mode variable, for example `TR_EVER_`), `subnet`, `phase` (the highest phase whose
outbound-call rows apply), `every_trigger_exclude_rows`, `mock_image`, `mock_config`, `modes` and
`artifacts_dir`. The browser leg's keys (`web_service`, `web_url`, `ui_routes`, `route_params`,
`ui_baseline`, `idle_pages`, `idle_s`, `ui_page_timeout_s`, `ui_skip_routes`,
`ui_expected_requests`, `optin_hosts`, `browser_image`) are in [Browser leg](#browser-leg).

## Adapter

An ES module whose default export may define `login`, `createFixtures`, `openSettings`,
`prepareLoadedOff` and `triggerAll` (async, each receiving `{baseUrl, mode, env, fetch, log,
headers}`) and `env` (extra environment per mode). See `adapter.schema.json` and
`selftest/adapter.mjs`. The adapter runs in the driver container, so it reaches the product by its
compose service name. What `createFixtures` answers (ids, never a token) reaches the browser leg's
hooks as `ctx.fixtures`: `uiLogin(page, ctx)` signs in through the product's sign-in page with the
Playwright page, and `routeParams(ctx)` answers the route parameter values only a run knows. The
browser hooks run in the browser container (the adapter is copied there too).

## Self-test

`--selftest` runs fixture products with known behaviour before any product trusts the harness:

| Run | Fixture | Must |
|---|---|---|
| `off/quiet` | no outbound call, module routes 404 | pass (0) |
| `off/leaky` | looks up `api.ever.co`, opens a socket to `203.0.113.10`, sends a UDP datagram to the same address and a DNS question straight to `198.51.100.53`, all at boot | fail (1), with the DNS query, the SYN and both datagrams seen |
| `positive_stats/stats-sender` | posts one signed golden report | pass (0) |
| `positive_stats/no-mock` | the same without the mock platform | not pass |
| `positive_managed/managed-executor` | connects, runs a requested backup, posts one result | pass (0) |
| `off/ui-quiet` | a toy web app: sign-in form, four pages (one with a parameter from the adapter), one idle page | pass (0), every route opened, the browser looks up nothing but the compose names |
| `off/ui-leaky` | the same app with `<img src="https://api.ever.co/pixel.png">` and a request to `203.0.113.10` after load | fail (1), with (e) the browser's DNS query and SYN, (f) the HAR entry and (g) the DOM `src` seen |
| `off/ui-link(no baseline)` | the same app with `<a href="https://app.ever.co">` | fail (1) at (g) alone |
| `off/ui-link(baseline)` | the same, with the link in `selftest/ui-baseline.link.json` | pass (0) |
| `positive_stats/ui-stats` | the page reads `GET /api/ever-stats/status`; the server posts the golden report | pass (0), the status call seen from the browser |
| `positive_stats/ui-stats(no mock)` | the same without the mock platform | not pass, with the status call still seen from the browser |
| `off/ui-quiet(--legs api)` | the web config run without its browser leg | fault (2): never a pass |

The summary prints one line per run (`off/leaky=1`, `positive_stats/no-mock=1`, ...). Every browser
run also checks that its `browser.har` holds no cookie, header value, body or the fixture's password.
`--legs api` runs the API runs only.

## Browser leg

A config that names a `web_service` gets a browser in the run (`--legs api,browser`, the default
then), in the modes `off`, `loaded_off` and `positive_stats`. The browser (the Playwright image
`mcr.microsoft.com/playwright:v1.62.1`, pinned by digest, with `browser.mjs`, `playwright-core`
1.62.1 and the adapter built in) runs in the namespace of its own holder, at the fixed address
`<subnet>.251` of the sealed default network, with CoreDNS as its only resolver and its own
sniffer (`browser.pcap`). It signs in with the adapter's `uiLogin`, opens every route of
`ui-routes.json` (a page that fails to load is retried once, then faults the run), holds the
`idle_pages` open for `idle_s` (30) seconds, and writes `browser/browser.har` (no bodies, cookies,
header values, form or query values), `browser/requests.json`, `browser/dom-refs.json` (every
`href`, `src`, `srcset`, `action`, `formaction`, `poster`, `ping`, `data`, `xlink:href`, meta
refresh and style `url()` of every frame and open shadow root) and `browser/visits.json`.

| Check | Fails when |
|---|---|
| (e) | a CoreDNS line from the browser's address or a question its sniffer saw names something outside the compose services and `allowed_external_hosts` (a never-allowed name always), or a connection attempt leaves the sealed Docker networks |
| (f) | a HAR entry, request or WebSocket goes to a never-allowed host, whatever `allowed_external_hosts` or `optin-hosts.json` says |
| (g) | a DOM reference points at a never-allowed host and `ui-baseline.json` has no entry with the same route, attribute and URL |
| positive control | a request of `ui_expected_requests[mode]` was not made to a compose service (required in `positive_stats`) |

A run of a config with a `web_service` that leaves the browser out (`--legs api`) faults (exit 2),
so it never passes. Config keys:

| Key | Default | Meaning |
|---|---|---|
| `web_service`, `web_url` | none | the compose service of the UI and its address by service name |
| `ui_routes` | `ui-routes.json` | the routes to open (`ui-routes.schema.json`) |
| `route_params` | `route-params.json` when present | `{name: value}` or `{"/path/:name": {name: value}}` |
| `ui_baseline` | `ui-baseline.json` when present | `{entries: [{route, attribute, url, reason}]}`, may only shrink |
| `idle_pages`, `idle_s` | none, `30` | the settings, integrations and catalog routes held open, and for how long |
| `ui_page_timeout_s` | `60` | load timeout per page, before its one retry |
| `ui_skip_routes` | none | `[{path, reason}]`, for example a sign-out route |
| `ui_expected_requests` | none | `{mode: ["GET /api/ever-stats/status"]}` |
| `optin_hosts` | `optin-hosts.json` | operator opt-ins, read by `static-hostnames` only |
| `browser_image` | the pinned image | another image with the same browser build |

`ever-hosts.json` is the never-allowed list of every leg and of `static-hostnames`; each entry
matches the name and every name under it. `EVER_EGRESS_EXTRA_HOSTS` (comma-separated) adds names
for a run; nothing removes one. [docs/egress-audit.md](../../docs/egress-audit.md) has the
product-side steps.

## Static helpers

- `ever-egress-audit static-hostnames --allow-dirs <dirs> [--optin-hosts <file> | --config <file>]
  [--baseline <ui-baseline.json>] [--all-files]`: no Ever-owned host (`ever_owned` of
  `ever-hosts.json`, with every name under it) and no Ever Platform base URL variable outside the
  directories that may name them. The product's `optin-hosts.json` (`{hosts: [{host, setting,
  reason}]}`, each host under an Ever-owned name) lists the hosts of older features that stay off
  until an operator turns them on: the scan accepts exactly those, and no capture check ever reads
  the file. `--baseline` accepts the hosts of the DOM baseline; `--all-files` scans built output
  (for example `.next/static`) instead of the files git tracks.
- `ever-egress-audit ui-routes --framework angular|next-app|solidstart --entry <path> --out
  ui-routes.json [--check]`: writes the route list from the router (entries with `"source":
  "manual"` are kept), or, with `--check`, exits 1 naming each router route missing from the
  committed list and each listed router route the router no longer has. What only the running app
  knows (a route list built by a service, a matcher) is printed as a note to add by hand.
- `ever-egress-audit check-baseline-shrink --base <git ref> [--file ui-baseline.json]`: exits 1
  when the baseline gained an entry since the base commit.
- `ever-egress-audit cloud-inference --dirs <module dirs>`: no module reads a payment secret, a demo
  flag, a cloud-provider variable, a deployment path, a desktop flag or the host name to guess where
  it runs.

## In CI

Run it on a runner with Docker (the sniffer needs `NET_RAW` and `NET_ADMIN`) and upload the
artifacts directory, for example:

```yaml
runs-on: ubuntu-latest
steps:
  - uses: actions/checkout@v5
  - run: pnpm exec ever-egress-audit --config egress-audit.config.json --mode off --artifacts egress-audit-artifacts
  - if: always()
    uses: actions/upload-artifact@v4
    with:
      name: egress-audit
      path: egress-audit-artifacts
```

## Limits

- The browser image is about 3.5 GB; a run that cannot pull it faults. Only Chromium is walked.
- Only the services in `process_services` are sniffed; databases and other third-party services in
  the compose files are sealed but not watched, and they keep Docker's resolver, so their DNS
  queries are not in the log. List every service that runs product code.
- A connection attempt to an IPv6 address fails inside the namespace without a packet; the DNS
  query that would precede it (`AAAA`) is still seen, and so is the `ENETUNREACH` a Node process
  logs for an address written in the code.
- An attempt is seen only while the product is watched: a timer longer than the scenario plus
  `wait_s` never fires in the run, so the modes shorten the statistics interval and products
  shorten their own timers the same way.
