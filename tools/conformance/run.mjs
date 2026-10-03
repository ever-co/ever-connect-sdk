#!/usr/bin/env node
/**
 * conformance: replays the non-destructive cases of cases.json against a running Ever Platform API
 * and compares the status, the problem code and the required response fields with what the cases
 * expect, and with --against-mock also with what the mock platform answers. The platform is the
 * reference: a difference is fixed in the mock or filed against the platform's contract.
 *
 *   node tools/conformance/run.mjs --target http://localhost:8080 [--against-mock] [--json]
 *                                  [--issuance on|off] [--modules connect,stats]
 *   node tools/conformance/run.mjs --target mock                   (the mock against itself)
 *
 * --issuance off expects what a deployment that issues no connect codes answers (a well-formed
 * redeem is 404; the mock is switched the same way). --modules runs only the cases of those
 * modules, for a platform that does not serve the others yet.
 *
 * Statistics: besides the cases of cases.json, every fixture of contracts/fixtures/stats is a case
 * (sent byte for byte, its expected status, problem code, errors[0].path and errors[0].code from
 * expected.json). Each run reports under a fresh statistics id, pinned by its first accepted report
 * to a key derived from a public seed, so a run never meets the day window of an earlier one.
 * `target_only` cases (the published schema, byte for byte) are not asked of the mock.
 *
 * Exit 0 with zero differences, 1 with differences, 2 when the target cannot be reached.
 */
import { createHash, randomUUID } from 'node:crypto';
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
// A fresh statistics id per run (a UUID v4).
const STATS_INSTANCE = randomUUID();

/** One case per statistics fixture, with the answer expected.json gives it. */
export function statsFixtureCases() {
  const { fixtures } = JSON.parse(readFileSync(join(FIXTURES, 'stats', 'expected.json'), 'utf8'));
  return Object.entries(fixtures).map(([file, e]) => ({
    id: `stats-fixture:${file.replace(/\.json$/, '')}`,
    row: 17,
    module: 'stats',
    stats: { fixture: `stats/${file}`, raw: true },
    expect: e.status === 202 ? { status: 202, required: ['accepted'] } : { status: e.status, code: e.code, path: e.path, error: e.error },
  }));
}

export function loadCases(file = join(here, 'cases.json')) {
  return [...JSON.parse(readFileSync(file, 'utf8')).cases, ...statsFixtureCases()];
}

/** A fixture's bytes with its statistics id replaced by the run's (textually: nothing else moves). */
function withRunId(bytes) {
  const text = bytes.toString('utf8');
  let id = null;
  try {
    id = JSON.parse(text).instance_id ?? null;
  } catch {
    id = null;
  }
  return typeof id === 'string' && id.length === 36 ? Buffer.from(text.replace(id, STATS_INSTANCE)) : bytes;
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
    // An instance token no platform issued: the shape of one, from a public seed.
    unknown_instance_token: `evit_${b64url(sha256('ever-connect-sdk/conformance/unknown-token'))}`,
  };
  const headers = { 'user-agent': USER_AGENT };
  if (c.stats) {
    const file = readFileSync(join(FIXTURES, c.stats.fixture));
    let body;
    if (c.stats.raw) body = withRunId(file);
    else {
      const report = JSON.parse(file.toString('utf8'));
      if ('instance_id' in report) report.instance_id = STATS_INSTANCE;
      body = Buffer.from(JSON.stringify(report));
    }
    const mutate = c.stats.mutate ?? null;
    const key = conformanceKey(mutate === 'other-key' ? 'stats-other' : 'stats');
    headers['content-type'] = mutate === 'media-type' ? 'text/plain' : 'application/json';
    // A 32-byte value that is no point of the curve (y = 2): not an Ed25519 public key.
    if (mutate === 'not-a-point') headers['ever-stats-key'] = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    else if (mutate !== 'no-key') headers['ever-stats-key'] = key.x;
    const signed = mutate === 'signature' ? Buffer.from(`${body.toString('utf8')} `) : body;
    if (mutate !== 'no-signature') headers['ever-stats-signature'] = `ed25519=${signBytes(key.privateKey, signed)}`;
    if (mutate === 'key-id') headers['ever-stats-key-id'] = 'AAAAAAAAAAA';
    return { method: 'POST', path: '/v1/stats/reports', headers, body };
  }
  const r = c.request;
  if (r.idempotent) headers['idempotency-key'] = randomUUID();
  if (r.bearer) headers.authorization = `Bearer ${substitute(r.bearer, vars)}`;
  let body;
  if (r.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(substitute(r.body, vars));
  }
  return { method: r.method, path: r.path, headers, body };
}

async function send(base, req) {
  const res = await fetch(`${base}${req.path}`, { method: req.method, headers: req.headers, body: req.body, redirect: 'manual' });
  const bytes = Buffer.from(await res.arrayBuffer());
  const text = bytes.toString('utf8');
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  const first = Array.isArray(body?.errors) ? body.errors[0] : undefined;
  return {
    status: res.status,
    code: res.headers.get('content-type')?.startsWith('application/problem+json') ? (body?.code ?? null) : null,
    body,
    error: first ? `${first.path} ${first.code}` : null,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    etag: res.headers.get('etag'),
  };
}

/** What a case expects under a profile ({issuance: 'on' | 'off'}). */
export const expectation = (c, profile = {}) => (profile.issuance === 'off' && c.expect_issuance_off ? c.expect_issuance_off : c.expect);

/** Differences of one answer from the expectation (and from the reference answer, when given). */
export function compare(c, answer, reference = null, profile = {}) {
  const diffs = [];
  const expect = expectation(c, profile);
  if (answer.status !== expect.status) diffs.push(`status ${answer.status}, expected ${expect.status}`);
  if (expect.code && answer.code !== expect.code) diffs.push(`code ${answer.code}, expected ${expect.code}`);
  for (const f of expect.required ?? []) if (!answer.body || !(f in answer.body)) diffs.push(`no ${f} in the answer`);
  for (const f of expect.absent ?? []) if (answer.body && f in answer.body) diffs.push(`${f} in the answer`);
  const first = answer.body?.errors?.[0];
  if (expect.path !== undefined && first?.path !== expect.path) diffs.push(`errors[0].path ${first?.path}, expected ${expect.path}`);
  if (expect.error !== undefined && first?.code !== expect.error) diffs.push(`errors[0].code ${first?.code}, expected ${expect.error}`);
  if (expect.sha256_of !== undefined) {
    const vendored = createHash('sha256')
      .update(readFileSync(join(FIXTURES, '..', expect.sha256_of)))
      .digest('hex');
    if (answer.sha256 !== vendored) diffs.push(`body sha256 ${answer.sha256}, vendored ${expect.sha256_of} ${vendored}`);
    if (expect.etag && answer.etag?.replace(/^W\//, '').replace(/"/g, '') !== vendored)
      diffs.push(`ETag ${answer.etag}, expected "${vendored}"`);
  }
  if (reference) {
    if (answer.status !== reference.status) diffs.push(`status ${answer.status}, the other side ${reference.status}`);
    if (answer.code !== reference.code) diffs.push(`code ${answer.code}, the other side ${reference.code}`);
    if ((answer.error ?? null) !== (reference.error ?? null)) diffs.push(`errors[0] ${answer.error}, the other side ${reference.error}`);
  }
  return diffs;
}

export async function startMock(profile = {}) {
  const mock = createMockPlatform({ config: { clock: { real: true } } });
  const { url } = await mock.listen(0, '127.0.0.1');
  mock.state.config.issuer = url;
  if (profile.issuance === 'off') mock.state.faults.connect_issuance_off = true;
  return { url, close: () => mock.close() };
}

/**
 * Runs the cases against the target (and the mock): [{id, row, module, target, mock, diffs}].
 * profile: {issuance: 'on' | 'off'}; modules: the case modules to run (all when absent).
 */
export async function run({ target, againstMock = false, cases = loadCases(), profile = {}, modules = null }) {
  let own = null;
  let base = target;
  if (target === 'mock') {
    own = await startMock(profile);
    base = own.url;
  }
  const mock = againstMock ? await startMock(profile) : null;
  const results = [];
  try {
    for (const c of cases.filter((x) => (!modules || modules.includes(x.module)) && !(x.target_only && own))) {
      const answer = await send(base, buildRequest(c, base));
      const reference = mock && !c.target_only ? await send(mock.url, buildRequest(c, mock.url)) : null;
      const diffs = compare(c, answer, reference, profile);
      if (reference) diffs.push(...compare(c, reference, null, profile).map((d) => `mock: ${d}`));
      results.push({
        id: c.id,
        row: c.row,
        module: c.module,
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
    const issuance = arg('issuance') ?? 'on';
    if (!['on', 'off'].includes(issuance)) {
      process.stderr.write('conformance: --issuance is on or off\n');
      return 2;
    }
    results = await run({
      target: target.replace(/\/$/, ''),
      againstMock: argv.includes('--against-mock'),
      profile: { issuance },
      modules: arg('modules')?.split(',') ?? null,
    });
  } catch (error) {
    process.stderr.write(`conformance: the target could not be reached: ${error.cause?.code ?? error.message}\n`);
    return 2;
  }
  if (argv.includes('--json')) process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
  else
    for (const r of results)
      process.stdout.write(
        `${r.diffs.length === 0 ? 'ok  ' : 'DIFF'} row ${String(r.row ?? '-').padEnd(3)} ${r.id.padEnd(44)} ${r.target}${r.mock ? ` | mock ${r.mock}` : ''}${r.diffs.length ? `\n       ${r.diffs.join('\n       ')}` : ''}\n`,
      );
  const differing = results.filter((r) => r.diffs.length > 0).length;
  process.stdout.write(`conformance: ${results.length} cases, ${differing} with differences\n`);
  return differing === 0 ? 0 : 1;
}

if (process.argv[1]?.endsWith('run.mjs') && process.argv[1].includes('conformance')) process.exit(await main(process.argv.slice(2)));
