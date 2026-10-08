// Fixture product "managed-executor": connects with the mode's connect code (key manifest, redeem,
// token), reads its feed and runs every managed operation it is asked for with a fixture executor
// that follows the SDK runner's rules: a known kind and closed params, the dry run always, a backup
// before every update, then exactly one result with status and size only. The positive_managed
// mode must see only the feed read and the result call after the request.
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { call, log, serve, sleep } from '../lib/fixture.mjs';

serve();

const base = process.env.EVER_PLATFORM_API_URL;
// The issuer the mock's documents name (https), which differs from the address it serves at: the
// assertion's audience is the issuer's token endpoint, as the SDK signs it.
const issuer = process.env.EVER_PLATFORM_ISSUER || base;
const code = process.env.EVER_CONNECT_CODE;

const b64url = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

/** An RFC 7523 client assertion: iss = sub = the installation id, aud = the token endpoint. */
function clientAssertion(instanceId, privateKey) {
  const iat = Math.floor(Date.now() / 1000);
  const claims = {
    iss: instanceId,
    sub: instanceId,
    aud: `${issuer}/v1/instances/token`,
    jti: randomBytes(16).toString('base64url'),
    iat,
    exp: iat + 300,
  };
  const input = `${b64url({ alg: 'EdDSA', typ: 'JWT' })}.${b64url(claims)}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

const PARAMS = {
  backup: [],
  health_report: [],
  update: ['target_version', 'dry_run_only'],
  restore_check: ['artefact_ref'],
};

/** The fixture executor: never touches anything; reports sizes and timings only. */
const executor = {
  kinds: () => Object.keys(PARAMS),
  async dryRun() {
    return { ok: true };
  },
  async backupBeforeUpdate() {
    return { ok: true, artefact_ref: 'selftest-pre-update', size_bytes: 1024 };
  },
  async execute(op) {
    return op.kind === 'backup' ? { status: 'succeeded', artefact_ref: 'selftest-backup-1', size_bytes: 2048 } : { status: 'succeeded' };
  },
};

async function runOperation(data, token) {
  const allowed = PARAMS[data.kind];
  let result;
  if (!executor.kinds().includes(data.kind) || !allowed || Object.keys(data.params ?? {}).some((k) => !allowed.includes(k)))
    result = { status: 'failed' };
  else if (!(await executor.dryRun(data)).ok) result = { status: 'failed' };
  else if (data.kind === 'update' && data.params?.dry_run_only) result = { status: 'succeeded' };
  else if (data.kind === 'update' && !(await executor.backupBeforeUpdate(data)).ok) result = { status: 'failed' };
  else result = await executor.execute(data);
  const r = await call(base, 'POST', `/v1/instances/me/managed-operations/${data.operation_id}/result`, { token, body: result });
  log(`managed operation ${data.kind}: ${result.status} (${r.status})`);
}

async function connectAndRun() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const x = publicKey.export({ format: 'jwk' }).x;
  const manifest = await call(base, 'GET', '/.well-known/ever-keys.json');
  log(`key manifest: ${manifest.status}`);
  const redeem = await call(base, 'POST', '/v1/connect/redeem', {
    body: {
      code,
      product: 'gauzy',
      version: '1.0.0',
      install_source: 'self-hosted',
      kind: 'self_hosted',
      public_jwk: { kty: 'OKP', crv: 'Ed25519', x },
    },
    headers: { 'idempotency-key': randomUUID() },
  });
  if (redeem.status !== 201) throw new Error(`redeem answered ${redeem.status}`);
  const instanceId = redeem.body.instance_id;
  const tokenAnswer = await call(base, 'POST', '/v1/instances/token', {
    body: {
      grant_type: 'client_credentials',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: clientAssertion(instanceId, privateKey),
    },
  });
  if (tokenAnswer.status !== 200) throw new Error(`token answered ${tokenAnswer.status}`);
  const token = tokenAnswer.body.access_token;
  log('connected');
  let after = null;
  for (;;) {
    const page = await call(base, 'GET', `/v1/instances/me/events?wait=5${after ? `&after=${encodeURIComponent(after)}` : ''}`, { token });
    if (page.status !== 200) {
      log(`feed: ${page.status}`);
      await sleep(2000);
      continue;
    }
    for (const event of page.body.events)
      if (event.type === 'ever.registry.managed_operation.requested') await runOperation(event.data, token);
    if (page.body.events.length > 0)
      await call(base, 'POST', '/v1/instances/me/events/ack', { token, body: { last_id: page.body.last_id } });
    after = page.body.last_id || after;
  }
}

if (process.env.EVER_CONNECT_ENABLED === 'true' && base && code) {
  for (;;) {
    try {
      await connectAndRun();
    } catch (error) {
      log(`connection failed: ${error.cause?.message ?? error.message}`);
      await sleep(5000);
    }
  }
}
