// One audit run: the product's compose files plus the audit overlay, a scenario driven from inside
// the sealed network, the evidence collected, assert.mjs's verdict written to report.json.
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { evaluate } from '../assert.mjs';
import { generatedRows, loadModes } from '../assert-call-log.mjs';
import { composeRunner, docker, poll } from './docker.mjs';
import { addressing, buildOverlay, composeNames, corefile, modeEnv, productModel } from './overlay.mjs';

const here = dirname(fileURLToPath(import.meta.url));
export const HARNESS_DIR = resolve(here, '..');
export const MOCK_DIR = resolve(HARNESS_DIR, '..', 'mock-platform');
const MOCK_CONTRACTS = join(MOCK_DIR, 'contracts');
export const LOCAL_MOCK_IMAGE = 'ever-mock-platform:audit-local';
const COREDNS_IMAGE = 'coredns/coredns:1.12.1';
const DRIVER_BASE_IMAGE = 'node:24-alpine';

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
  return { config, configDir: dirname(file) };
}

function mergeDeep(...objects) {
  const out = {};
  for (const o of objects)
    for (const [k, v] of Object.entries(o ?? {}))
      out[k] = v && typeof v === 'object' && !Array.isArray(v) && out[k] && typeof out[k] === 'object' ? mergeDeep(out[k], v) : v;
  return out;
}

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
  log = () => {},
}) {
  const modes = loadModes(config.modes ?? {});
  const mode = modes[modeName];
  if (!mode) throw new UsageError(`unknown mode ${modeName} (modes: ${Object.keys(modes).join(', ')})`);
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
  const { dnsIp } = addressing(subnet);
  const holders = config.process_services.map((s) => `ever-audit-ns-${s}`);
  const sniffers = config.process_services.map((s) => `ever-audit-sniffer-${s}`);
  const dnsImage = `ever-audit-dns:${project}`;
  const driverImage = `ever-audit-driver:${project}`;
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
  };
  let full = null;
  try {
    const product = composeRunner({ project, files, projectDirectory, env, log });
    const model = productModel(JSON.parse(product(['config', '--format', 'json']).stdout));
    for (const s of [config.api_service, ...config.process_services, ...(config.services ?? [])])
      if (!model.services[s]) throw new UsageError(`service ${s} is not in ${config.compose.join(', ')}`);

    let adapterEnv = {};
    if (config.adapter) {
      const adapter = (await import(pathToFileURL(resolve(configDir, config.adapter)).href)).default ?? {};
      adapterEnv = adapter.env?.[modeName] ?? {};
    }
    const productEnv = modeEnv({ ...mode.env, ...adapterEnv }, prefix);

    let mock = null;
    if (useMock) {
      const image = config.mock_image ?? buildMockImage(log);
      mock = { image, config: mergeDeep({ clock: { real: true } }, config.mock_config, mode.mock_config) };
    }

    // CoreDNS: the compose names forwarded to Docker's resolver, NXDOMAIN for everything else.
    evidence.composeNames = composeNames({ ...model.services, ...(useMock ? { 'mock-platform': {} } : {}) });
    mkdirSync(join(out, 'dns'), { recursive: true });
    writeFileSync(join(out, 'dns', 'Corefile'), corefile(evidence.composeNames));
    writeFileSync(join(out, 'dns', 'Dockerfile'), `FROM ${COREDNS_IMAGE}\nCOPY Corefile /Corefile\n`);
    docker(['build', '-q', '-t', dnsImage, join(out, 'dns')], { log });

    const overlay = buildOverlay({
      project,
      subnet,
      dnsImage,
      product: model,
      processServices: config.process_services,
      env: productEnv,
      mock,
    });
    const overlayPath = join(out, 'compose.audit.generated.yml');
    writeFileSync(overlayPath, overlay);
    full = composeRunner({ project, files: [...files, overlayPath], projectDirectory, env, log });
    full(['down', '-v', '--remove-orphans', '--timeout', '5'], { allowFail: true });

    // 1. The resolver, the namespace holders, the sniffers (and the mock) start first.
    full(['up', '-d', 'ever-audit-dns', ...holders, ...sniffers, ...(useMock ? ['mock-platform'] : [])]);
    for (const [i, sniffer] of sniffers.entries()) {
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
            : `the sniffer of ${config.process_services[i]} never started capturing (${status ?? 'timeout'})`;
        throw new HarnessFault(reason);
      }
      const resolv = full(['exec', '-T', holders[i], 'cat', '/etc/resolv.conf']).stdout;
      evidence.resolv[config.process_services[i]] = resolv;
      const servers = resolv.split('\n').filter((l) => /^\s*nameserver\s/.test(l));
      if (servers.length !== 1 || servers[0].trim().split(/\s+/)[1] !== dnsIp)
        throw new HarnessFault(`the resolver of ${config.process_services[i]} is not the audit resolver (${servers.join('; ') || 'none'})`);
    }

    // 2. The product: created, given the TEST root file (positive modes), then started.
    const rootsFile = productEnv[`${prefix}PLATFORM_ROOT_KEYS_FILE`];
    if (rootsFile) {
      const constants = JSON.parse(readFileSync(join(MOCK_CONTRACTS, 'constants.json'), 'utf8'));
      const rootsDir = join(out, 'roots');
      mkdirSync(rootsDir, { recursive: true });
      writeJson(join(rootsDir, rootsFile.split('/').pop()), { keys: constants.root_keys });
      full(['create', ...(config.build ? ['--build'] : []), ...config.process_services]);
      for (const svc of config.process_services) {
        const id = full(['ps', '-a', '-q', svc]).stdout.trim().split('\n')[0];
        docker(['cp', rootsDir, `${id}:${rootsFile.slice(0, rootsFile.lastIndexOf('/')) || '/'}`], { log });
      }
    }
    full(['up', '-d', ...(config.build ? ['--build'] : []), ...(config.services ?? [])]);

    // 3. The scenario, from the driver container on the sealed network.
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
      wait_s: config.wait_s ?? 20,
      mock: useMock,
      required_rows: rows(mode.required_rows),
      after_required_rows: mode.after_mark?.required_rows ?? [],
      managed_request: mode.managed_request,
    };
    const driver = (step, extra = {}) => {
      const r = docker(['run', '--rm', '--network', `${project}-audit`, '-e', 'EVER_AUDIT_PLAN', driverImage, step], {
        env: { ...process.env, EVER_AUDIT_PLAN: JSON.stringify({ ...plan, ...extra }) },
        allowFail: true,
        log,
      });
      const res = parseResult(r.stdout);
      writeFileSync(join(out, `driver-${step}.log`), `${r.stdout}${r.stderr}`);
      return res;
    };
    const scenario = driver('scenario');
    if (!scenario.ok) faults.push(scenario.fault);
    if (scenario.ok && mode.trigger === 'managed_request' && useMock) {
      const m = driver('managed');
      if (m.ok) evidence.mark = m.mark;
      else faults.push(m.fault);
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
    for (const image of [dnsImage, driverImage]) docker(['image', 'rm', '-f', image], { allowFail: true, log });
  }
  const report = evaluate(evidence);
  writeJson(join(out, 'evidence.json'), evidence);
  writeJson(join(out, 'report.json'), report);
  return report;
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
  if (!keep) full(['down', '-v', '--remove-orphans', '--timeout', '5'], { allowFail: true });
}
