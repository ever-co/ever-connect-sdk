// One audit run: the product's compose files plus the audit overlay, a scenario driven from inside
// the sealed network, the evidence collected, assert.mjs's verdict written to report.json.
import { execFileSync } from 'node:child_process';
import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { testRootEntry } from '../../mock-platform/src/keys.mjs';
import { DEFAULT_CONFIG } from '../../mock-platform/src/state.mjs';
import { evaluate } from '../assert.mjs';
import { generatedRows, loadModes } from '../assert-call-log.mjs';
import { entryLabel, hideExtraHosts, matchNeverAllowed } from '../hosts.mjs';
import { compare as compareRoutes, generate as generateRoutes } from '../routes/cli.mjs';
import { composeRunner, docker, poll } from './docker.mjs';
import { addressing, BROWSER, buildOverlay, composeNames, corefile, MOCK_PORT, modeEnv, productModel } from './overlay.mjs';

const here = dirname(fileURLToPath(import.meta.url));
export const HARNESS_DIR = resolve(here, '..');
export const MOCK_DIR = resolve(HARNESS_DIR, '..', 'mock-platform');
const MOCK_CONTRACTS = join(MOCK_DIR, 'contracts');
export const LOCAL_MOCK_IMAGE = 'ever-mock-platform:audit-local';
// Every image of the audit is pinned by digest (Renovate moves the tag and the digest together).
const COREDNS_IMAGE = 'coredns/coredns:1.12.1@sha256:e8c262566636e6bc340ece6473b0eed193cad045384401529721ddbe6463d31c';
const DRIVER_BASE_IMAGE = 'node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1';
/** The browser leg's image: Playwright 1.62.1 (its Chromium matches the bundled playwright-core), pinned by digest. */
export const BROWSER_BASE_IMAGE =
  'mcr.microsoft.com/playwright:v1.62.1@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e';
/** Seconds the product is watched after the scenario when the config sets no wait_s. */
export const DEFAULT_WAIT_S = 120;
/** Seconds an idle page stays open when the config sets no idle_s. */
export const DEFAULT_IDLE_S = 30;
export const LEGS = ['api', 'browser'];
/** The products with a UI: their config names a web_service, or sets it to null with no_web_reason. */
export const UI_PRODUCTS = ['gauzy', 'teams', 'works', 'rec', 'traduora'];

/** A refusal before anything runs (bad config, unknown mode): exit 2 with the message. */
export class UsageError extends Error {}
/** The harness could not prove anything (no capture, no driver): exit 2 with the reason. */
export class HarnessFault extends Error {}

export function loadConfig(path) {
  const file = resolve(path);
  const config = JSON.parse(readFileSync(file, 'utf8'));
  const schema = JSON.parse(readFileSync(join(HARNESS_DIR, 'config.schema.json'), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
  if (!validate(config))
    throw new UsageError(
      `${path} is not a valid egress audit config:\n  ${validate.errors.map((e) => `${e.instancePath || '/'} ${e.message}`).join('\n  ')}`,
    );
  if (!config.process_services.includes(config.api_service))
    throw new UsageError(`api_service ${config.api_service} must be one of process_services`);
  // The schema refuses the listed names; this also covers names added for the run (EVER_EGRESS_EXTRA_HOSTS).
  for (const host of config.allowed_external_hosts ?? []) {
    const match = matchNeverAllowed(host);
    if (match)
      throw new UsageError(
        hideExtraHosts(`allowed_external_hosts: ${host} is on the never-allowed list (${match.category}: ${entryLabel(match)}) and can never be allowed`),
      );
  }
  if (config.web_service && !config.web_url) throw new UsageError('web_service needs web_url (the UI address inside the sealed network)');
  if (config.web_url && !config.web_service) throw new UsageError('web_url needs web_service (the compose service that serves the UI)');
  if (config.web_service === null && !config.no_web_reason)
    throw new UsageError('"web_service": null needs no_web_reason (why this product runs without the browser leg)');
  if (config.no_web_reason && config.web_service !== null) throw new UsageError('no_web_reason goes with "web_service": null only');
  if (UI_PRODUCTS.includes(config.product) && config.web_service === undefined)
    throw new UsageError(
      `${config.product} has a UI: name its web_service (and web_url) so the browser leg runs, or set "web_service": null with no_web_reason`,
    );
  if (config.web_static !== undefined && !config.web_service) throw new UsageError('web_static goes with web_service');
  // The web service's own requests (server rendering, API routes, a backend-for-frontend, a proxy)
  // are captured, and resolved through the audit resolver, only when it is a process service.
  if (config.web_service && !config.process_services.includes(config.web_service) && config.web_static !== true)
    throw new UsageError(
      `web_service ${config.web_service} is not one of process_services: its own requests (server rendering, API routes, a proxy) would not be captured and would keep Docker's resolver. Add it to process_services, or set "web_static": true if it serves static files only`,
    );
  // An idle page must be opened: skipping it would drop the page the leg holds open.
  const skipped = new Set((config.ui_skip_routes ?? []).map((r) => r.path));
  for (const p of config.idle_pages ?? [])
    if (skipped.has(p)) throw new UsageError(`idle page ${p} is also in ui_skip_routes: an idle page must be opened`);
  // A product adds modes; it never redefines one of the harness's, so `off` means the same everywhere.
  const builtIn = Object.keys(JSON.parse(readFileSync(join(HARNESS_DIR, 'modes.json'), 'utf8')).modes);
  for (const name of Object.keys(config.modes ?? {}))
    if (builtIn.includes(name)) throw new UsageError(`modes.${name} redefines a mode of the harness; give the product mode its own name`);
  return { config, configDir: dirname(file) };
}

function mergeDeep(...objects) {
  const out = {};
  for (const o of objects)
    for (const [k, v] of Object.entries(o ?? {}))
      out[k] = v && typeof v === 'object' && !Array.isArray(v) && out[k] && typeof out[k] === 'object' ? mergeDeep(out[k], v) : v;
  return out;
}

/**
 * The legs of a run: `api` always (the product processes are the base of every run), `browser` on
 * top of it. Default: both when the config names a web_service, else the API leg alone.
 */
export function resolveLegs(config, legs) {
  const list = legs ? [...new Set(legs)] : config.web_service ? ['api', 'browser'] : ['api'];
  for (const l of list) if (!LEGS.includes(l)) throw new UsageError(`unknown leg ${l} (legs: ${LEGS.join(', ')})`);
  if (!list.includes('api')) throw new UsageError('the browser leg runs on top of the API leg: use --legs api,browser');
  if (list.includes('browser') && !config.web_service) throw new UsageError('--legs browser needs web_service and web_url in the config');
  return list;
}

function readValid(file, schemaFile, what) {
  let data;
  try {
    data = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    throw new UsageError(`${what} ${file} could not be read: ${error.message}`);
  }
  const schema = JSON.parse(readFileSync(join(HARNESS_DIR, schemaFile), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
  if (!validate(data))
    throw new UsageError(
      `${file} is not a valid ${what}:\n  ${validate.errors.map((e) => `${e.instancePath || '/'} ${e.message}`).join('\n  ')}`,
    );
  return data;
}

/**
 * What the browser walks and judges: the route list, the static parameters, the baseline, the idle
 * pages, the skipped routes and the positive control of the mode. Refuses a config whose idle or
 * skipped routes are not in the list, or a positive mode without an expected request.
 */
export function loadBrowserInputs(config, configDir, modeName, mode) {
  const at = (p) => resolve(configDir, p);
  const routesFile = at(config.ui_routes ?? 'ui-routes.json');
  if (!existsSync(routesFile))
    throw new UsageError(`the browser leg needs a route list: ${routesFile} is missing (ever-egress-audit ui-routes)`);
  const list = readValid(routesFile, 'ui-routes.schema.json', 'route list');
  const routes = list.routes;
  if (routes.length === 0) throw new UsageError(`${routesFile} lists no route`);
  const paramsFile = at(config.route_params ?? 'route-params.json');
  let params = {};
  if (existsSync(paramsFile)) params = JSON.parse(readFileSync(paramsFile, 'utf8'));
  else if (config.route_params) throw new UsageError(`route_params ${paramsFile} is missing`);
  const baselineFile = at(config.ui_baseline ?? 'ui-baseline.json');
  let baseline = [];
  if (existsSync(baselineFile)) baseline = readValid(baselineFile, 'ui-baseline.schema.json', 'baseline').entries;
  else if (config.ui_baseline) throw new UsageError(`ui_baseline ${baselineFile} is missing`);
  const paths = new Set(routes.map((r) => r.path));
  for (const p of config.idle_pages ?? []) if (!paths.has(p)) throw new UsageError(`idle page ${p} is not in ${routesFile}`);
  for (const s of config.ui_skip_routes ?? [])
    if (!paths.has(s.path)) throw new UsageError(`skipped route ${s.path} is not in ${routesFile}`);
  const expected = config.ui_expected_requests?.[modeName] ?? [];
  if (mode.browser === 'positive' && expected.length === 0)
    throw new UsageError(
      `mode ${modeName} runs the browser leg's positive control: set ui_expected_requests.${modeName} (for example ["GET /api/ever-stats/status"])`,
    );
  return {
    routes: routes.map((r) => ({ path: r.path })),
    params,
    baseline,
    expected,
    idlePages: config.idle_pages ?? [],
    skip: config.ui_skip_routes ?? [],
    routeCheck: checkRouteList(list, config, configDir),
  };
}

/** The root of the git repository holding dir, or null. */
function gitTop(dir) {
  try {
    return execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
}

/**
 * The route list against the router, in the run itself: a list generated from a framework and an
 * entry is generated again (from ui_routes_root, default the repository root) and every router route
 * it lacks is answered in `missing`, which faults the run. A manual list cannot be checked: the
 * summary says so. Answers {framework, checked, missing[], stale[], error?}.
 */
export function checkRouteList(list, config, configDir) {
  const framework = list.framework ?? 'manual';
  if (framework === 'manual' || !list.entry)
    return { framework, checked: false, missing: [], stale: [], note: 'a manual route list is not compared with a router' };
  const root = config.ui_routes_root ? resolve(configDir, config.ui_routes_root) : (gitTop(configDir) ?? configDir);
  try {
    const generated = generateRoutes({
      framework,
      entry: resolve(root, list.entry),
      root,
      exportName: config.ui_routes_export,
      tsconfig: config.ui_routes_tsconfig ? resolve(root, config.ui_routes_tsconfig) : undefined,
      existing: list,
    });
    const { missing, stale } = compareRoutes(generated, list);
    return { framework, checked: true, missing, stale };
  } catch (error) {
    return { framework, checked: false, missing: [], stale: [], error: String(error.message ?? error).split('\n')[0].slice(0, 300) };
  }
}

/** A value with every leaf replaced by [redacted], its keys kept (the names of env and fixtures). */
export function redactValues(value) {
  if (Array.isArray(value)) return value.map(redactValues);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValues(v)]));
  return value === null || value === undefined ? value : '[redacted]';
}

/**
 * The paths of fixture values shaped like a credential (a JWT, a `Bearer ` value, or a string longer
 * than 64 characters): createFixtures hands the browser ids, never a token or a session.
 */
export function tokenShapedFixtures(value, at = 'fixtures') {
  if (Array.isArray(value)) return value.flatMap((v, i) => tokenShapedFixtures(v, `${at}[${i}]`));
  if (value && typeof value === 'object') return Object.entries(value).flatMap(([k, v]) => tokenShapedFixtures(v, `${at}.${k}`));
  if (typeof value !== 'string') return [];
  return /^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(value) || /^bearer\s/i.test(value) || value.length > 64 ? [at] : [];
}

/**
 * A log with what looks like a credential replaced: cookie, set-cookie and authorization values, a
 * Bearer value, a JWT, and the value of a password, secret or token field. The run's own lines
 * never hold one; this covers what a product or an adapter prints.
 */
export function scrubLog(text) {
  return String(text ?? '')
    .replace(/(\b(?:set-cookie|cookie|authorization)["']?\s*[:=]\s*)[^\r\n]*/gi, '$1[redacted]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/g, 'Bearer [redacted]')
    .replace(/\beyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]*/g, '[redacted]')
    .replace(/(\b(?:password|passwd|secret|token)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s&,;}]+)/gi, '$1[redacted]');
}

/** A driver's stdout with the fixtures of its result line redacted (ids stay out of the logs too). */
function redactResultLine(stdout) {
  return String(stdout ?? '')
    .split('\n')
    .map((l) => {
      if (!l.startsWith('EVER_AUDIT_RESULT ')) return l;
      try {
        const r = JSON.parse(l.slice('EVER_AUDIT_RESULT '.length));
        if (r.fixtures) r.fixtures = redactValues(r.fixtures);
        return `EVER_AUDIT_RESULT ${JSON.stringify(r)}`;
      } catch {
        return l;
      }
    })
    .join('\n');
}

/** The directory of the playwright-core the harness depends on (copied into the browser image). */
export function playwrightCoreDir() {
  try {
    return dirname(createRequire(join(HARNESS_DIR, 'package.json')).resolve('playwright-core/package.json'));
  } catch {
    throw new HarnessFault('playwright-core is not installed next to the harness; the browser leg cannot run');
  }
}

/**
 * The browser image of a run: the pinned Playwright image with browser.mjs, its helpers, the
 * adapter, playwright-core and the walk's plan (nothing is mounted).
 */
/**
 * The browser image's Dockerfile. On the pinned Playwright image the walk runs as its unprivileged
 * pwuser, with /out writable for it; another browser_image keeps its own user.
 */
export function browserDockerfile(base) {
  const asUser = base === BROWSER_BASE_IMAGE ? 'RUN mkdir -p /out && chown pwuser:pwuser /out\nUSER pwuser\n' : '';
  return `FROM ${base}\nWORKDIR /browser\nCOPY . .\n${asUser}ENTRYPOINT ["node", "/browser/browser.mjs"]\n`;
}

function buildBrowserImage({ dir, tag, base, adapterFile, plan, log }) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(join(dir, 'lib'), { recursive: true });
  copyFileSync(join(HARNESS_DIR, 'browser.mjs'), join(dir, 'browser.mjs'));
  for (const f of ['dom-refs.mjs', 'har.mjs']) copyFileSync(join(HARNESS_DIR, 'lib', f), join(dir, 'lib', f));
  if (adapterFile) copyFileSync(adapterFile, join(dir, 'adapter.mjs'));
  cpSync(playwrightCoreDir(), join(dir, 'node_modules', 'playwright-core'), { recursive: true, dereference: true });
  writeFileSync(join(dir, 'package.json'), '{"type":"module","private":true}\n');
  writeFileSync(join(dir, 'plan.json'), `${JSON.stringify(plan)}\n`);
  writeFileSync(join(dir, 'Dockerfile'), browserDockerfile(base));
  docker(['build', '-q', '-t', tag, dir], { log, timeoutS: 1800 });
}

const readJson = (file, fallback) => {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
};

/** A /24 per project, so a leftover docker network of another run never overlaps. */
export function defaultSubnet(project) {
  let h = 2166136261;
  for (const c of project) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
  return `10.231.${16 + (h % 220)}.0/24`;
}

export function buildMockImage(log) {
  if (!existsSync(join(MOCK_DIR, 'Dockerfile'))) throw new HarnessFault(`no mock platform at ${MOCK_DIR}; set mock_image`);
  docker(['build', '-q', '-t', LOCAL_MOCK_IMAGE, MOCK_DIR], { log });
  return LOCAL_MOCK_IMAGE;
}

function parseResult(stdout) {
  const line = stdout
    .split('\n')
    .reverse()
    .find((l) => l.startsWith('EVER_AUDIT_RESULT '));
  if (!line) return { ok: false, fault: 'the driver answered nothing' };
  return JSON.parse(line.slice('EVER_AUDIT_RESULT '.length));
}

const writeJson = (file, value) => writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);

/**
 * Runs one mode. Answers the report ({exit, mode, violations, faults, summary}) and writes it, the
 * evidence, the logs and the pcaps under <artifactsDir>/<mode>[-nomock]/.
 */
export async function runAudit({
  config,
  configDir,
  modeName,
  noMock = false,
  artifactsDir,
  keep = false,
  composeEnv = {},
  legs,
  log = () => {},
}) {
  const modes = loadModes(config.modes ?? {});
  const mode = modes[modeName];
  if (!mode) throw new UsageError(`unknown mode ${modeName} (modes: ${Object.keys(modes).join(', ')})`);
  const runLegs = resolveLegs(config, legs);
  // The browser leg runs when the product has a UI (web_service) and the mode asks for it. A run
  // that leaves it out (--legs api) proves the API side only: it faults, so it never passes.
  const browserWanted = Boolean(config.web_service && mode.browser);
  const browserOn = browserWanted && runLegs.includes('browser');
  const browserInputs = browserOn ? loadBrowserInputs(config, configDir, modeName, mode) : null;
  const label = `${modeName}${noMock ? '-nomock' : ''}`;
  const project = `${config.project ?? `ever-audit-${config.product}`}-${label}`.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const out = resolve(artifactsDir, label);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const env = { ...process.env, ...composeEnv };
  const files = config.compose.map((f) => resolve(configDir, f));
  const projectDirectory = dirname(files[0]);
  const useMock = Boolean(mode.mock) && !noMock;
  const prefix = config.env_prefix ?? 'EVER_';
  const subnet = config.subnet ?? defaultSubnet(project);
  const { dnsIp, mockIp, browserIp } = addressing(subnet);
  // The mock's configuration and where the products find it: its fixed address (a local address,
  // which the SDK accepts over plain http) and the https issuer its documents name. Both are known
  // in a run without the mock too, so a product is configured the same way and simply gets no answer.
  const mockConfig = mergeDeep({ clock: { real: true } }, config.mock_config, mode.mock_config);
  const mockAt = { url: `http://${mockIp}:${MOCK_PORT}`, issuer: mockConfig.issuer ?? DEFAULT_CONFIG.issuer };
  const holders = config.process_services.map((s) => `ever-audit-ns-${s}`);
  const sniffers = config.process_services.map((s) => `ever-audit-sniffer-${s}`);
  const dnsImage = `ever-audit-dns:${project}`;
  const driverImage = `ever-audit-driver:${project}`;
  const browserImage = `ever-audit-browser:${project}`;
  const browserBase = config.browser_image ?? BROWSER_BASE_IMAGE;
  const faults = [];
  const evidence = {
    mode,
    modeName: label,
    subnets: [subnet],
    composeNames: [],
    allowedHosts: config.allowed_external_hosts ?? [],
    coredns: '',
    sniffers: {},
    logs: {},
    resolv: {},
    routes: [],
    expectRoutes: mode.module_routes === '404' && (config.module_routes ?? []).length > 0,
    mockExpected: Boolean(mode.mock),
    mockRecord: null,
    mark: null,
    generated: [],
    faults,
    legs: runLegs,
    browser: browserWanted
      ? browserOn
        ? {
            enabled: true,
            required: true,
            positive: mode.browser === 'positive',
            ips: [browserIp],
            sniffer: '',
            har: null,
            requests: [],
            domRefs: [],
            visits: [],
            skipped: [],
            baseline: browserInputs.baseline,
            expected: browserInputs.expected,
            routeCheck: browserInputs.routeCheck,
            signInPath: null,
            faults: [],
          }
        : {
            enabled: false,
            required: true,
            reason: `the browser leg was left out (--legs ${runLegs.join(',')}): this run proves the API side only`,
          }
      : null,
  };
  let full = null;
  try {
    const product = composeRunner({ project, files, projectDirectory, env, log });
    const model = productModel(JSON.parse(product(['config', '--format', 'json']).stdout));
    for (const s of [
      config.api_service,
      ...config.process_services,
      ...(config.services ?? []),
      ...(config.web_service ? [config.web_service] : []),
    ])
      if (!model.services[s]) throw new UsageError(`service ${s} is not in ${config.compose.join(', ')}`);
    // The walk reaches the web service itself, never another service.
    if (config.web_service) {
      const names = composeNames({ [config.web_service]: model.services[config.web_service] });
      const host = new URL(config.web_url).hostname.toLowerCase();
      if (!names.includes(host))
        throw new UsageError(`web_url ${config.web_url} does not name web_service ${config.web_service} (its names: ${names.join(', ')})`);
    }
    if (browserOn) {
      const rc = browserInputs.routeCheck;
      if (rc.error) evidence.browser.faults.push(`the route list could not be compared with the router: ${rc.error}`);
      else if (rc.missing.length > 0)
        evidence.browser.faults.push(
          `router routes missing from the route list (regenerate it with ever-egress-audit ui-routes): ${rc.missing.join(', ')}`,
        );
    }
    // The browser image is large: pull it before anything starts, so a pull that fails is a
    // fault of the run and not a page that never loads.
    if (browserOn && docker(['image', 'inspect', browserBase], { allowFail: true }).status !== 0)
      try {
        docker(['pull', '-q', browserBase], { log, timeoutS: 1800 });
      } catch (error) {
        throw new HarnessFault(`the browser image ${browserBase} could not be pulled: ${error.message.split('\n').slice(-1)[0]}`);
      }

    let adapterEnv = {};
    if (config.adapter) {
      const adapter = (await import(pathToFileURL(resolve(configDir, config.adapter)).href)).default ?? {};
      adapterEnv = adapter.env?.[modeName] ?? {};
    }
    const productEnv = modeEnv({ ...mode.env, ...adapterEnv }, prefix, mockAt);

    let mock = null;
    if (useMock) {
      const image = config.mock_image ?? buildMockImage(log);
      mock = { image, config: mockConfig };
    }

    // CoreDNS: the compose names forwarded to Docker's resolver, NXDOMAIN for everything else.
    evidence.composeNames = composeNames({ ...model.services, ...(useMock ? { 'mock-platform': {} } : {}) });
    mkdirSync(join(out, 'dns'), { recursive: true });
    writeFileSync(join(out, 'dns', 'Corefile'), corefile(evidence.composeNames));
    writeFileSync(join(out, 'dns', 'Dockerfile'), `FROM ${COREDNS_IMAGE}\nCOPY Corefile /Corefile\n`);
    docker(['build', '-q', '-t', dnsImage, join(out, 'dns')], { log });

    // The driver: scenario.mjs and the product adapter, run with `docker compose run` like every
    // other container of the project.
    const driverDir = join(out, 'driver');
    mkdirSync(driverDir, { recursive: true });
    copyFileSync(join(HARNESS_DIR, 'scenario.mjs'), join(driverDir, 'scenario.mjs'));
    if (config.adapter) copyFileSync(resolve(configDir, config.adapter), join(driverDir, 'adapter.mjs'));
    writeFileSync(join(driverDir, 'package.json'), '{"type":"module","private":true}\n');
    writeFileSync(
      join(driverDir, 'Dockerfile'),
      `FROM ${DRIVER_BASE_IMAGE}\nWORKDIR /driver\nCOPY . .\nENTRYPOINT ["node", "scenario.mjs"]\n`,
    );
    docker(['build', '-q', '-t', driverImage, driverDir], { log });
    // The build context holds the adapter (which may name a seed password): it is not evidence.
    rmSync(driverDir, { recursive: true, force: true });

    const overlay = buildOverlay({
      project,
      subnet,
      dnsImage,
      driverImage,
      product: model,
      processServices: config.process_services,
      env: productEnv,
      mock,
      browser: browserOn ? { image: browserImage, webService: config.web_service } : null,
    });
    const overlayPath = join(out, 'compose.audit.generated.yml');
    writeFileSync(overlayPath, overlay);
    full = composeRunner({ project, files: [...files, overlayPath], projectDirectory, env, log });
    full(['down', '-v', '--remove-orphans', '--timeout', '5'], { allowFail: true });

    // 1. The resolver, the namespace holders, the sniffers (and the mock) start first.
    const watched = config.process_services.map((s, i) => ({ svc: s, holder: holders[i], sniffer: sniffers[i] }));
    if (browserOn) watched.push({ svc: 'browser', holder: BROWSER.holder, sniffer: BROWSER.sniffer });
    full(['up', '-d', 'ever-audit-dns', ...watched.flatMap((w) => [w.holder, w.sniffer]), ...(useMock ? ['mock-platform'] : [])]);
    for (const { svc, holder, sniffer } of watched) {
      const status = await poll(
        () => {
          const text = full(['logs', '--no-color', '--no-log-prefix', sniffer], { allowFail: true }).stdout;
          if (/listening on/.test(text)) return 'capturing';
          const state = full(['ps', '-a', '--format', '{{.State}}', sniffer], { allowFail: true }).stdout.trim();
          if (state && state !== 'running' && state !== 'created') return `stopped: ${text.trim().split('\n').slice(-3).join(' | ')}`;
          return null;
        },
        { timeoutS: 120, everyMs: 1000 },
      );
      if (status !== 'capturing') {
        const reason = /NET_ADMIN refused/.test(status ?? '')
          ? 'NET_ADMIN was refused, so connection attempts cannot be routed to the sink'
          : /permission|not permitted|Operation not permitted/i.test(status ?? '')
            ? 'CAP_NET_RAW was refused, so tcpdump cannot capture'
            : `the sniffer of ${svc} never started capturing (${status ?? 'timeout'})`;
        throw new HarnessFault(reason);
      }
      const resolv = full(['exec', '-T', holder, 'cat', '/etc/resolv.conf']).stdout;
      evidence.resolv[svc] = resolv;
      const servers = resolv.split('\n').filter((l) => /^\s*nameserver\s/.test(l));
      if (servers.length !== 1 || servers[0].trim().split(/\s+/)[1] !== dnsIp)
        throw new HarnessFault(`the resolver of ${svc} is not the audit resolver (${servers.join('; ') || 'none'})`);
    }

    // 2. The product: created, given the TEST root file (positive modes), then started.
    const rootsFile = productEnv[`${prefix}PLATFORM_ROOT_KEYS_FILE`];
    if (rootsFile) {
      const rootsDir = join(out, 'roots');
      mkdirSync(rootsDir, { recursive: true });
      // The mock's TEST root, pinned for the mock's issuer: the SDK honours it for a local base URL only.
      writeJson(join(rootsDir, rootsFile.split('/').pop()), { keys: [testRootEntry(mockAt.issuer)] });
      full(['create', ...(config.build ? ['--build'] : []), ...config.process_services]);
      for (const svc of config.process_services) {
        const id = full(['ps', '-a', '-q', svc]).stdout.trim().split('\n')[0];
        docker(['cp', rootsDir, `${id}:${rootsFile.slice(0, rootsFile.lastIndexOf('/')) || '/'}`], { log });
      }
    }
    full(['up', '-d', ...(config.build ? ['--build'] : []), ...(config.services ?? [])]);

    // 3. The scenario, from the driver container on the sealed network.
    const outbound = JSON.parse(readFileSync(join(MOCK_CONTRACTS, 'generated', 'outbound-calls.json'), 'utf8'));
    evidence.generated = generatedRows(outbound, config.product, {
      phase: config.phase ?? 2,
      exclude: config.every_trigger_exclude_rows ?? [],
    });
    const rows = (r) => (r === 'generated' ? evidence.generated : (r ?? []));
    const plan = {
      mode: modeName,
      health_url: config.health_url,
      health_timeout_s: config.health_timeout_s ?? 120,
      env: productEnv,
      prepare: mode.prepare,
      trigger: mode.trigger,
      module_routes: config.module_routes ?? [],
      wait_s: config.wait_s ?? DEFAULT_WAIT_S,
      mock: useMock,
      required_rows: rows(mode.required_rows),
      after_required_rows: mode.after_mark?.required_rows ?? [],
      managed_request: mode.managed_request,
    };
    const driver = (step, extra = {}) => {
      const b64 = Buffer.from(JSON.stringify({ ...plan, ...extra })).toString('base64');
      const r = full(['run', '--rm', '-T', '--no-deps', '-e', `EVER_AUDIT_PLAN_B64=${b64}`, 'ever-audit-driver', step], {
        allowFail: true,
      });
      const res = parseResult(r.stdout);
      writeFileSync(join(out, `driver-${step}.log`), scrubLog(`${redactResultLine(r.stdout)}${r.stderr}`));
      return res;
    };
    const scenario = driver('scenario');
    if (!scenario.ok) faults.push(scenario.fault);
    if (scenario.ok && mode.trigger === 'managed_request' && useMock) {
      const m = driver('managed');
      if (m.ok) evidence.mark = m.mark;
      else faults.push(m.fault);
    }
    // 4. The browser leg: the product UI walked from the browser's own sniffed namespace.
    const tokenShaped = tokenShapedFixtures(scenario.fixtures ?? null);
    if (browserOn && tokenShaped.length > 0)
      evidence.browser.faults.push(
        `createFixtures answered values shaped like a credential (${tokenShaped.join(', ')}): hand the browser ids, never a token or a session; the browser leg did not run`,
      );
    else if (browserOn) {
      if (scenario.ok)
        runBrowser({
          full,
          out,
          evidence,
          plan: {
            web_url: config.web_url,
            api_url: new URL(config.health_url).origin,
            mode: modeName,
            env: productEnv,
            fixtures: scenario.fixtures ?? null,
            routes: browserInputs.routes,
            params: browserInputs.params,
            idle_pages: browserInputs.idlePages,
            idle_s: config.idle_s ?? DEFAULT_IDLE_S,
            page_timeout_s: config.ui_page_timeout_s ?? 60,
            skip: browserInputs.skip,
            out: '/out',
          },
          image: browserImage,
          base: browserBase,
          adapterFile: config.adapter ? resolve(configDir, config.adapter) : null,
          project,
          log,
        });
      else evidence.browser.faults.push('the browser leg did not run: the product never became ready');
    }
    driver('wait', { mark: evidence.mark });
    if (evidence.expectRoutes) evidence.routes = driver('probe').routes ?? [];
    if (useMock) {
      const r = driver('record');
      if (r.ok) evidence.mockRecord = r.entries;
      else faults.push(r.fault);
    } else if (mode.mock) evidence.mockRecord = []; // the mock was left out on purpose: no call can have succeeded
  } catch (error) {
    faults.push(error instanceof HarnessFault || error instanceof UsageError ? error.message : `harness error: ${error.message}`);
    if (error instanceof UsageError) throw error;
  } finally {
    if (full) collect({ full, evidence, config, sniffers, project, out, keep, log });
    for (const image of [dnsImage, driverImage, ...(browserOn ? [browserImage] : [])])
      docker(['image', 'rm', '-f', image], { allowFail: true, log });
  }
  const report = evaluate(evidence);
  writeJson(join(out, 'evidence.json'), evidence);
  writeJson(join(out, 'report.json'), report);
  return report;
}

/**
 * The browser leg's walk: the image built with the plan, one `docker compose run` in the
 * browser holder's namespace, then its evidence copied out of the stopped container into
 * <out>/browser (browser.har, requests.json, dom-refs.json, visits.json) and read into evidence.browser.
 */
function runBrowser({ full, out, evidence, plan, image, base, adapterFile, project, log }) {
  const b = evidence.browser;
  const dir = join(out, 'browser');
  const name = `${project}-browser-walk`;
  const context = join(out, 'browser-image');
  try {
    buildBrowserImage({ dir: context, tag: image, base, adapterFile, plan, log });
  } catch (error) {
    b.faults.push(`the browser image could not be built: ${error.message.split('\n').slice(-1)[0]}`);
    return;
  } finally {
    // The plan stays with the evidence, with the env and fixture values redacted (names kept); the
    // build context (playwright-core and the adapter included) does not.
    writeJson(join(out, 'browser-plan.json'), { ...plan, env: redactValues(plan.env ?? {}), fixtures: redactValues(plan.fixtures ?? null) });
    rmSync(context, { recursive: true, force: true });
  }
  docker(['rm', '-f', name], { allowFail: true, log });
  const pageS = plan.page_timeout_s * 2 + 20;
  const timeoutS = Math.max(900, 300 + plan.routes.length * pageS + plan.idle_pages.length * plan.idle_s);
  const r = full(['run', '-T', '--no-deps', '--name', name, BROWSER.service], { allowFail: true, timeoutS });
  writeFileSync(join(out, 'browser-walk.log'), scrubLog(`${r.stdout}${r.stderr}`));
  const res = r.stdout.includes('EVER_AUDIT_RESULT ')
    ? parseResult(r.stdout)
    : { ok: false, fault: `the browser answered nothing (exit ${r.status ?? 'timeout'}; see browser-walk.log)` };
  for (const f of res.faults ?? (res.fault ? [res.fault] : [])) b.faults.push(f);
  mkdirSync(dir, { recursive: true });
  docker(['cp', `${name}:/out/.`, dir], { allowFail: true, log });
  docker(['rm', '-f', name], { allowFail: true, log });
  b.har = readJson(join(dir, 'browser.har'), null);
  if (!b.har) b.faults.push('no HAR came out of the browser');
  b.requests = readJson(join(dir, 'requests.json'), []);
  b.domRefs = readJson(join(dir, 'dom-refs.json'), []);
  const visits = readJson(join(dir, 'visits.json'), { visits: [], skipped: [] });
  b.visits = visits.visits;
  b.skipped = visits.skipped;
  b.signInPath = visits.sign_in_path ?? null;
  // A raw recording must never reach the evidence (browser.mjs keeps it outside /out).
  for (const f of ['.raw.har', 'raw.har']) rmSync(join(dir, f), { force: true });
}

/** Logs, network subnets and pcaps; then the project is removed (unless keep). */
function collect({ full, evidence, config, sniffers, project, out, keep, log }) {
  const logsOf = (svc) => full(['logs', '--no-color', '--no-log-prefix', svc], { allowFail: true }).stdout;
  evidence.coredns = logsOf('ever-audit-dns');
  writeFileSync(join(out, 'dns.log'), evidence.coredns);
  for (const [i, svc] of config.process_services.entries()) {
    evidence.sniffers[svc] = logsOf(sniffers[i]);
    evidence.logs[svc] = logsOf(svc);
    writeFileSync(join(out, `sniffer-${svc}.log`), evidence.sniffers[svc]);
    writeFileSync(join(out, `product-${svc}.log`), evidence.logs[svc]);
  }
  if (evidence.mockRecord) writeJson(join(out, 'requests.json'), evidence.mockRecord);
  const browserOn = Boolean(evidence.browser?.enabled);
  if (browserOn) {
    evidence.browser.sniffer = logsOf(BROWSER.sniffer);
    writeFileSync(join(out, 'sniffer-browser.log'), evidence.browser.sniffer);
    const state = full(['ps', '-a', '--format', '{{.State}}', BROWSER.sniffer], { allowFail: true }).stdout.trim();
    if (state !== 'running')
      evidence.browser.faults.push(`the browser's sniffer was not running at the end of the run (${state || 'gone'})`);
  }
  // A sniffer that stopped during the run saw only part of it: the run proves nothing.
  for (const [i, svc] of config.process_services.entries()) {
    const state = full(['ps', '-a', '--format', '{{.State}}', sniffers[i]], { allowFail: true }).stdout.trim();
    if (state !== 'running') evidence.faults.push(`the sniffer of ${svc} was not running at the end of the run (${state || 'gone'})`);
  }
  const nets = docker(['network', 'ls', '-q', '--filter', `label=com.docker.compose.project=${project}`], { allowFail: true })
    .stdout.trim()
    .split('\n')
    .filter(Boolean);
  for (const id of nets) {
    const inspect = docker(['network', 'inspect', id, '--format', '{{json .IPAM.Config}}'], { allowFail: true }).stdout.trim();
    try {
      for (const c of JSON.parse(inspect || '[]') ?? [])
        if (c.Subnet && !c.Subnet.includes(':') && !evidence.subnets.includes(c.Subnet)) evidence.subnets.push(c.Subnet);
    } catch {
      // an unreadable docker network adds no subnet
    }
  }
  full(['stop', '--timeout', '5'], { allowFail: true });
  mkdirSync(join(out, 'pcap'), { recursive: true });
  for (const [i, svc] of config.process_services.entries()) {
    const id = full(['ps', '-a', '-q', sniffers[i]], { allowFail: true }).stdout.trim().split('\n')[0];
    if (id) docker(['cp', `${id}:/captures/${svc}.pcap`, join(out, 'pcap', `${svc}.pcap`)], { allowFail: true, log });
  }
  if (browserOn) {
    const id = full(['ps', '-a', '-q', BROWSER.sniffer], { allowFail: true }).stdout.trim().split('\n')[0];
    if (id) docker(['cp', `${id}:/captures/${BROWSER.capture}.pcap`, join(out, 'pcap', 'browser.pcap')], { allowFail: true, log });
  }
  if (!keep) full(['down', '-v', '--remove-orphans', '--timeout', '5'], { allowFail: true });
}
