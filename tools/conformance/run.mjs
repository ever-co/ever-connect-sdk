#!/usr/bin/env node
/**
 * conformance: replays the non-destructive cases of cases.json against a running Ever Platform API
 * and compares the status, the problem code and the required response fields with what the cases
 * expect, and with --against-mock also with what the mock platform answers. The platform is the
 * reference: a difference is fixed in the mock or filed against the platform's contract.
 *
 *   node tools/conformance/run.mjs --target http://localhost:8080 [--against-mock] [--json]
 *   node tools/conformance/run.mjs --target mock                   (the mock against itself)
 *
 * Exit 0 with zero differences, 1 with differences, 2 when the target cannot be reached.
 */
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { b64url, keyPairFromSeed, sha256, signBytes } from '../mock-platform/src/crypto.mjs';
import { signClientAssertion } from '../mock-platform/src/keys.mjs';
import { createMockPlatform } from '../mock-platform/src/server.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(here, '..', '..', 'contracts', 'fixtures');
const USER_AGENT = 'ever-connect-sdk/0.0.0-conformance (gauzy/1.0.0)';

/** Keys from public seeds: they identify the conformance run and sign nothing anyone trusts. */
const conformanceKey = (label) => {
  const pair = keyPairFromSeed(sha256(`ever-connect-sdk/conformance/${label}`));
  return { ...pair, kid: label };
};
const UNKNOWN_INSTANCE = '01JNCQNF0RMANCE0000000000Z';
const STATS_INSTANCE = (() => {
  const h = Buffer.from(sha256('ever-connect-sdk/conformance/stats-instance')).toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
})();

export function loadCases(file = join(here, 'cases.json')) {
  return JSON.parse(readFileSync(file, 'utf8')).cases;
}

function substitute(value, vars) {
  if (typeof value === 'string') return value.startsWith('$') && value.slice(1) in vars ? vars[value.slice(1)] : value;
  if (Array.isArray(value)) return value.map((v) => substitute(v, vars));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substitute(v, vars)]));
  return value;
}

/** The HTTP request of a case for a base URL: {method, path, headers, body}. */
export function buildRequest(c, base) {
  const connect = conformanceKey('connect');
  const vars = {
    conformance_key_x: connect.x,
    unknown_instance_assertion: signClientAssertion({
      key: connect,
      instanceId: UNKNOWN_INSTANCE,
      audience: `${new URL(base).origin}/v1/instances/token`,
      iat: Math.floor(Date.now() / 1000),
      jti: b64url(sha256(`conformance/${randomUUID()}`)).slice(0, 22),
    }),
  };
  const headers = { 'user-agent': USER_AGENT };
  if (c.stats) {
    const report = JSON.parse(readFileSync(join(FIXTURES, c.stats.fixture), 'utf8'));
    if ('instance_id' in report) report.instance_id = STATS_INSTANCE;
    const body = Buffer.from(JSON.stringify(report));
    const key = conformanceKey(c.stats.mutate === 'other-key' ? 'stats-other' : 'stats');
    headers['content-type'] = 'application/json';
    if (c.stats.mutate !== 'no-key') headers['ever-stats-key'] = key.x;
    const signed = c.stats.mutate === 'signature' ? Buffer.from(`${body.toString('utf8')} `) : body;
    headers['ever-stats-signature'] = `ed25519=${signBytes(key.privateKey, signed)}`;
    return { method: 'POST', path: '/v1/stats/reports', headers, body };
  }
  const r = c.request;
  if (r.idempotent) headers['idempotency-key'] = randomUUID();
  let body;
  if (r.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(substitute(r.body, vars));
  }
  return { method: r.method, path: r.path, headers, body };
}

async function send(base, req) {
  const res = await fetch(`${base}${req.path}`, { method: req.method, headers: req.headers, body: req.body, redirect: 'manual' });
  const text = await res.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  return {
    status: res.status,
    code: res.headers.get('content-type')?.startsWith('application/problem+json') ? (body?.code ?? null) : null,
    body,
  };
}

/** Differences of one answer from the expectation (and from the reference answer, when given). */
export function compare(c, answer, reference = null) {
  const diffs = [];
  if (answer.status !== c.expect.status) diffs.push(`status ${answer.status}, expected ${c.expect.status}`);
  if (c.expect.code && answer.code !== c.expect.code) diffs.push(`code ${answer.code}, expected ${c.expect.code}`);
  for (const f of c.expect.required ?? []) if (!answer.body || !(f in answer.body)) diffs.push(`no ${f} in the answer`);
  if (reference) {
    if (answer.status !== reference.status) diffs.push(`status ${answer.status}, the other side ${reference.status}`);
    if (answer.code !== reference.code) diffs.push(`code ${answer.code}, the other side ${reference.code}`);
  }
  return diffs;
}

export async function startMock() {
  const mock = createMockPlatform({ config: { clock: { real: true } } });
  const { url } = await mock.listen(0, '127.0.0.1');
  mock.state.config.issuer = url;
  return { url, close: () => mock.close() };
}

/** Runs every case against the target (and the mock): [{id, row, target, mock, diffs}]. */
export async function run({ target, againstMock = false, cases = loadCases() }) {
  let own = null;
  let base = target;
  if (target === 'mock') {
    own = await startMock();
    base = own.url;
  }
  const mock = againstMock ? await startMock() : null;
  const results = [];
  try {
    for (const c of cases) {
      const answer = await send(base, buildRequest(c, base));
      const reference = mock ? await send(mock.url, buildRequest(c, mock.url)) : null;
      const diffs = compare(c, answer, reference);
      if (reference) diffs.push(...compare(c, reference).map((d) => `mock: ${d}`));
      results.push({
        id: c.id,
        row: c.row,
        target: answer.status + (answer.code ? ` ${answer.code}` : ''),
        mock: reference ? reference.status + (reference.code ? ` ${reference.code}` : '') : null,
        diffs,
      });
    }
  } finally {
    await mock?.close();
    await own?.close();
  }
  return results;
}

async function main(argv) {
  const arg = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const target = arg('target');
  if (!target) {
    process.stderr.write('conformance: --target <url> (or mock) is required\n');
    return 2;
  }
  let results;
  try {
    results = await run({ target: target.replace(/\/$/, ''), againstMock: argv.includes('--against-mock') });
  } catch (error) {
    process.stderr.write(`conformance: the target could not be reached: ${error.cause?.code ?? error.message}\n`);
    return 2;
  }
  if (argv.includes('--json')) process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
  else
    for (const r of results)
      process.stdout.write(
        `${r.diffs.length === 0 ? 'ok  ' : 'DIFF'} row ${String(r.row).padEnd(3)} ${r.id.padEnd(28)} ${r.target}${r.mock ? ` | mock ${r.mock}` : ''}${r.diffs.length ? `\n       ${r.diffs.join('\n       ')}` : ''}\n`,
      );
  const differing = results.filter((r) => r.diffs.length > 0).length;
  process.stdout.write(`conformance: ${results.length} cases, ${differing} with differences\n`);
  return differing === 0 ? 0 : 1;
}

if (process.argv[1]?.endsWith('run.mjs') && process.argv[1].includes('conformance')) process.exit(await main(process.argv.slice(2)));
