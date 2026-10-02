#!/usr/bin/env node
/**
 * build-signed: writes every generated fixture under contracts/fixtures/, deterministically.
 *
 *   requests/    one valid body per request schema the rows use, each with invalid twins, and
 *                expected.json (schema, verdict, path of the first error)
 *   feed/        one FeedResponse page per instance-audience event type, the managed-operation
 *                requests per kind with invalid twins, and expected.json
 *   keys/        key manifests signed by the TEST root (valid, keys-sha256 mismatch, unknown root),
 *                the TEST root as a JWKS for EVER_PLATFORM_ROOT_KEYS_FILE, and the test context
 *   entitlement/ valid instance and link documents and the invalid set, each with its expected code
 *   consent/     valid and invalid consent records; consent-screen/ the seven blocks per key
 *   connect/     client-assertion vectors with the platform's expected answer
 *   stats/       the provisional statistics fixtures and expected.json
 *
 * Every signature comes from a TEST key derived from a public seed (no private key file exists),
 * and Ed25519 is deterministic, so a rebuild is byte-identical.
 *
 *   node tools/fixtures/build-signed.mjs           write
 *   node tools/fixtures/build-signed.mjs --check   rebuild in memory and compare
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, diffOutputs, readJson, walk, writeText } from '../lib/common.mjs';
import { inlineCommon } from '../lib/schema-prep.mjs';
import { b64url, sha256 } from '../mock-platform/src/crypto.mjs';
import {
  ENTITLEMENT_TYP,
  manifestEntry,
  signClientAssertion,
  signEntitlement,
  signManifest,
  signStatsLinkStatement,
  testKey,
  testRootEntry,
} from '../mock-platform/src/keys.mjs';
import { signJws } from '../mock-platform/src/crypto.mjs';
import { validateComponent, validateEnvelope, validateEventData, validatePending, validateSchema } from '../mock-platform/src/validate.mjs';
import { example } from './example.mjs';
import { NOW, hex64, iso, ulid, uuid } from './ids.mjs';
import { statsFixtures } from './stats.mjs';

// The entitlement schema accepts only https issuers, so the offline fixtures use an https issuer
// (the running mock answers with its own configured issuer).
export const ISSUER = 'https://mock-platform.test';
const FIXTURES = 'contracts/fixtures';
const json = (v) => `${JSON.stringify(v, null, 2)}\n`;

export const IDS = {
  instance: ulid('instance/1'),
  otherInstance: ulid('instance/2'),
  org: ulid('org/acme'),
  tenant: ulid('tenant/acme'),
  link: ulid('link/1'),
  otherLink: ulid('link/2'),
  consent: ulid('consent/1'),
  job: ulid('job/1'),
  statsInstance: uuid('stats/instance/1'),
};

// ------------------------------------------------------------------------------------- requests
function requestCases() {
  const connect = testKey('connect');
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: connect.x };
  const assertion = signClientAssertion({ instanceId: IDS.instance, audience: `${ISSUER}/v1/instances/token`, iat: NOW });
  const statement = signStatsLinkStatement({ statsInstanceId: IDS.statsInstance, iat: NOW });
  const extra = (body, field = 'unexpected_field', value = 'x') => ({ ...body, [field]: value });
  const c = (schema, body, invalid) => ({ schema, body, invalid });
  return {
    redeem: c(
      'RedeemRequest',
      { code: 'EVC-TEST-0000-0001', product: 'gauzy', version: '96.2.1', install_source: 'self-hosted', kind: 'self_hosted', public_jwk: jwk, tenant: { product_tenant_id: 'tenant-1', product_org_id: 'org-1' } },
      {
        'null-id': (b) => [{ ...b, tenant: { ...b.tenant, product_org_id: null } }, '/tenant/product_org_id'],
        'extra-field': (b) => [extra(b, 'public_url', 'https://gauzy.example.com'), '/public_url'],
      },
    ),
    token: c(
      'TokenRequest',
      { grant_type: 'client_credentials', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion },
      { 'extra-field': (b) => [extra(b, 'scope', 'openid'), '/scope'] },
    ),
    'tenant-link': c(
      'TenantLinkCreate',
      { link_code: 'EVL-TEST-0000-0002', product: 'gauzy', product_tenant_id: 'tenant-2', product_org_id: 'org-2' },
      { 'null-id': (b) => [{ ...b, product_org_id: null }, '/product_org_id'], 'extra-field': (b) => [extra(b, 'org_id', IDS.org), '/org_id'] },
    ),
    'tenant-link-rekey': c('TenantLinkRekey', { product_tenant_id: 'org-default' }, { 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    heartbeat: c(
      'HeartbeatBody',
      { version: '96.2.1', module_version: '1.0.0', serves_products: ['gauzy', 'teams'] },
      { 'null-id': (b) => [{ ...b, version: null }, '/version'], 'extra-field': (b) => [extra(b, 'hostname', 'gauzy.example.com'), '/hostname'] },
    ),
    'events-ack': c('FeedAck', { last_id: ulid('event/last') }, { 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    'set-integration': c(
      'InstanceIntegrationPut',
      { enabled: false, reason: 'instance' },
      { 'enable-attempt': (b) => [{ ...b, enabled: true }, '/enabled'], 'extra-field': (b) => [extra(b), '/unexpected_field'] },
    ),
    'stats-link': c(
      'StatsLinkCreate',
      statement,
      { 'missing-statement': (b) => [{ stats_instance_id: b.stats_instance_id, stats_public_jwk: b.stats_public_jwk }, '/statement_sig'], 'extra-field': (b) => [extra(b, 'instance_url', 'https://gauzy.example.com'), '/instance_url'] },
    ),
    identifiers: c(
      'IdentifierHashes',
      { hashes: [{ kind: 'vat', salt_version: 1, hash: hex64('identifier/vat') }] },
      { 'extra-field': (b) => [{ hashes: [{ ...b.hashes[0], value: 'BG123456789' }] }, '/hashes/0/value'] },
    ),
    lookup: c(
      'LookupRequest',
      { salt_version: 1, hashes: [hex64('lookup/1'), hex64('lookup/2')] },
      { 'too-many': () => [{ salt_version: 1, hashes: Array.from({ length: 101 }, (_, i) => hex64(`lookup/many/${i}`)) }, '/hashes'], 'extra-field': (b) => [extra(b), '/unexpected_field'] },
    ),
    'oidc-client': c(
      'OidcClientRequest',
      { redirect_uri: 'https://gauzy.example.com/api/auth/ever/callback', logout_uri: 'https://gauzy.example.com/api/auth/ever/backchannel-logout' },
      { 'extra-field': (b) => [extra(b, 'client_name', 'Acme'), '/client_name'] },
    ),
    mirror: c(
      'MirrorBatch',
      { ops: [{ op: 'upsert', kind: 'app', external_id: 'work-1', external_version: 3, occurred_at: iso(NOW) }] },
      { 'extra-field': (b) => [{ ops: [{ ...b.ops[0], repository_url: 'https://example.com/repo' }] }, '/ops/0/repository_url'] },
    ),
    keys: c('KeyRotate', { public_jwk: { kty: 'OKP', crv: 'Ed25519', x: testKey('connectNext').x } }, { 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    'person-link': c(
      'PersonLinkCreate',
      { product_user_ref: 'user-1', identity_issuer: 'https://auth.ever.co', identity_subject: '275396402232829475', link_method: 'explicit', product_tenant_id: 'tenant-1' },
      { 'null-id': (b) => [{ ...b, product_org_id: null }, '/product_org_id'], 'extra-field': (b) => [extra(b, 'email', 'jane@example.com'), '/email'] },
    ),
    ack: c(
      'AckRequest',
      { job_id: IDS.job, result: 'anonymised', detail: { reason_code: 'identity_unlinked' } },
      { 'bad-result': (b) => [{ ...b, result: 'ignored' }, '/result'], 'extra-field': (b) => [extra(b, 'email', 'jane@example.com'), '/email'] },
    ),
    'identity-resolve': c('IdentityResolveRequest', { issuer: 'https://auth.ever.co', subject: '275396402232829475' }, { 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    'org-profile': c(
      'OrgProfilePush',
      { tenant_link_id: IDS.link, consent_id: IDS.consent, fields: { name: 'Acme', website: 'https://acme.example', country: 'BG' } },
      { 'extra-field': (b) => [{ ...b, fields: { ...b.fields, email: 'jane@example.com' } }, '/fields/email'] },
    ),
    usage: c(
      'UsageReport',
      { items: [{ meter_key: 'employees.reported', quantity: 27, period: '2026-11' }] },
      { 'extra-field': (b) => [{ items: [{ ...b.items[0], employee_names: ['Jane Doe'] }] }, '/items/0/employee_names'] },
    ),
    'usage-readings': c(
      'UsageReadings',
      { readings: [{ unit: 'cpu_hour', quantity: 12, observed_at: iso(NOW) }] },
      { 'extra-field': (b) => [{ readings: [{ ...b.readings[0], hostname: 'node-1' }] }, '/readings/0/hostname'] },
    ),
    'billing-link': c('BillingLinkCreate', { product_tenant_id: 'tenant-1', customer_ref: 'cus_test_0001' }, { 'extra-field': (b) => [extra(b, 'email', 'billing@example.com'), '/email'] }),
    'intent-complete': c(
      'IntentComplete',
      { instance_id: IDS.instance, product_tenant_id: 'tenant-3', product_org_id: 'org-3', product_user_ref: 'user-3', result: 'created' },
      { 'null-id': (b) => [{ ...b, product_org_id: null }, '/product_org_id'], 'extra-field': (b) => [extra(b), '/unexpected_field'] },
    ),
    'install-status': c('InstallStatus', { state: 'installed', external_ref: 'plugin-42' }, { 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    device: c(
      'DeviceRequest',
      { product: 'gauzy', version: '96.2.1', install_source: 'self-hosted', kind: 'self_hosted', public_jwk: jwk },
      { 'extra-field': (b) => [extra(b, 'public_url', 'https://gauzy.example.com'), '/public_url'] },
    ),
    'device-token': c('DeviceTokenRequest', { device_code: b64url(sha256('device-code/1')), client_assertion: assertion }, { 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    webhook: c(
      'WebhookCreate',
      { url: 'https://gauzy.example.com/api/ever-connect/webhooks', event_filter: ['ever.consent.*'] },
      { 'extra-field': (b) => [extra(b), '/unexpected_field'] },
    ),
    'webhook-patch': c('WebhookPatch', { event_filter: ['ever.entitlements.*'] }, { 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    'integration-put.product-ui': c(
      'IntegrationPut',
      { enabled: true, tenant_link_id: IDS.link, consent: { scope_version: 1, dpa_version: '2026-10', accepted: true, screen_version: '1', ui_locale: 'en' } },
      { 'not-accepted': (b) => [{ ...b, consent: { ...b.consent, accepted: false } }, '/consent/accepted'], 'extra-field': (b) => [{ ...b, consent: { ...b.consent, ip_address: '203.0.113.7' } }, '/consent/ip_address'] },
    ),
    'managed-operation-result': c(
      'ManagedOperationResult',
      { status: 'succeeded', artefact_ref: 'bk-20261102-0100', size_bytes: 734003200 },
      { 'file-name': (b) => [extra(b, 'file_name', 'backup-acme.tar.gz'), '/file_name'], 'bad-status': (b) => [{ ...b, status: 'done' }, '/status'] },
    ),
    'public-url': c('pending:instancePutPublicUrl', { base_url: 'https://gauzy.example.com' }, { 'plain-http': () => [{ base_url: 'http://gauzy.example.com' }, '/base_url'], 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    'integration-accept': c('pending:instanceAcceptIntegration', { consent_id: IDS.consent, accepted: true }, { 'extra-field': (b) => [extra(b), '/unexpected_field'] }),
    'provider-grant-status': c(
      'pending:instanceReportProviderGrantStatus',
      { grant_id: ulid('grant/1'), status: 'accepted', product_user_ref: 'user-9' },
      { 'extra-field': (b) => [extra(b, 'email', 'jane@example.com'), '/email'] },
    ),
  };
}

const validateFor = (schema, body) =>
  schema.startsWith('pending:') ? validatePending(schema.slice('pending:'.length), body) : validateComponent(schema, body);

function requests() {
  const files = {};
  const expected = {};
  for (const [name, { schema, body, invalid }] of Object.entries(requestCases())) {
    const v = validateFor(schema, body);
    if (!v.ok) throw new Error(`requests/${name}.json does not validate against ${schema}: ${JSON.stringify(v.errors[0])}`);
    files[`requests/${name}.json`] = json(body);
    expected[`${name}.json`] = { schema, valid: true };
    for (const [suffix, make] of Object.entries(invalid)) {
      const [bad, path] = make(body);
      const r = validateFor(schema, bad);
      if (r.ok) throw new Error(`requests/${name}.invalid-${suffix}.json validates against ${schema}`);
      if (r.errors[0].path !== path) throw new Error(`requests/${name}.invalid-${suffix}.json fails at ${r.errors[0].path}, expected ${path}`);
      files[`requests/${name}.invalid-${suffix}.json`] = json(bad);
      expected[`${name}.invalid-${suffix}.json`] = { schema, valid: false, path };
    }
  }
  files['requests/expected.json'] = json({
    description: 'Each request fixture, the contract schema it is checked against (pending:<operation> for a call pending upstream), the verdict, and for invalid twins the path of the first error.',
    fixtures: expected,
  });
  return files;
}

// ----------------------------------------------------------------------------------------- feed
const SUBJECT_KIND = (type) => {
  const entity = type.split('.')[2];
  return { consent: 'consent', integration: 'integration', entitlement: 'entitlement', usage: 'meter', instance: 'instance', managed_operation: 'managed_operation', membership: 'membership', person: 'person', tenant_link: 'tenant_link' }[entity] ?? entity;
};

function feed(constants) {
  const files = {};
  const expected = {};
  const common = readJson(join(REPO, 'contracts/schemas/events/common.schema.json'));
  const subjectKinds = common.$defs.subject.properties.kind.enum;
  const envelope = (type, data, n = 1) => {
    const kind = subjectKinds.includes(SUBJECT_KIND(type)) ? SUBJECT_KIND(type) : 'instance';
    const event = {
      id: ulid(`event/${type}/${n}`),
      type,
      version: 1,
      occurred_at: iso(NOW),
      subject: { kind, id: ulid(`subject/${type}`) },
      org_id: IDS.org,
      instance_id: IDS.instance,
      actor: { kind: 'system', id: 'platform' },
      data,
    };
    return event;
  };
  const page = (events) => ({ events, last_id: events.at(-1)?.id ?? ulid('event/none'), has_more: false });
  for (const type of constants.feed_event_types) {
    const file = walk(join(REPO, 'contracts/schemas/events')).map((p) => p.split(/[\\/]/).pop()).find((f) => f.startsWith(`${type}.v`));
    const schema = readJson(join(REPO, 'contracts/schemas/events', file));
    const prepared = inlineCommon(schema, common);
    let data = Array.isArray(schema.examples) && schema.examples.length > 0 ? structuredClone(schema.examples[0]) : example(prepared, prepared, type);
    // Ids in examples point at this fixture installation.
    if (data && typeof data === 'object') {
      if ('instance_id' in data) data.instance_id = IDS.instance;
      if ('org_id' in data) data.org_id = IDS.org;
    }
    const v = validateEventData(type, data);
    if (!v.ok) throw new Error(`feed/${type}.json: data does not validate: ${JSON.stringify(v.errors[0])}`);
    const event = envelope(type, data);
    const ve = validateEnvelope(event);
    if (!ve.ok) throw new Error(`feed/${type}.json: envelope does not validate: ${JSON.stringify(ve.errors[0])}`);
    const body = page([event]);
    const vp = validateComponent('FeedResponse', body);
    if (!vp.ok) throw new Error(`feed/${type}.json: page does not validate: ${JSON.stringify(vp.errors[0])}`);
    files[`feed/${type}.json`] = json(body);
    expected[`${type}.json`] = { type, valid: true };
  }
  // Managed operations: one request per kind, each with invalid twins.
  const kinds = {
    update: { target_version: '1.5.0' },
    backup: {},
    restore_check: { artefact_ref: 'bk-20261102-0100' },
    health_report: {},
  };
  const type = 'ever.registry.managed_operation.requested';
  for (const [kind, params] of Object.entries(kinds)) {
    const data = {
      operation_id: ulid(`operation/${kind}`),
      org_id: IDS.org,
      instance_id: IDS.instance,
      kind,
      params,
      not_before: iso(NOW),
      expires_at: iso(NOW + 86400),
    };
    const name = `managed-operation-requested.${kind.replace('_', '-')}`;
    const ok = validateEventData(type, data);
    if (!ok.ok) throw new Error(`feed/${name}.json does not validate: ${JSON.stringify(ok.errors[0])}`);
    files[`feed/${name}.json`] = json(page([envelope(type, data, kind)]));
    expected[`${name}.json`] = { type, valid: true };
    const twins = {
      'unknown-param': [{ ...data, params: { ...params, shell: 'rm -rf /' } }, '/params/shell'],
      'missing-params': [Object.fromEntries(Object.entries(data).filter(([k]) => k !== 'params')), '/params'],
    };
    for (const [suffix, [bad, path]] of Object.entries(twins)) {
      const r = validateEventData(type, bad);
      if (r.ok) throw new Error(`feed/${name}.invalid-${suffix}.json validates`);
      if (r.errors[0].path !== path) throw new Error(`feed/${name}.invalid-${suffix}.json fails at ${r.errors[0].path}, expected ${path}`);
      files[`feed/${name}.invalid-${suffix}.json`] = json(page([envelope(type, bad, `${kind}-${suffix}`)]));
      expected[`${name}.invalid-${suffix}.json`] = { type, valid: false, path: `/events/0/data${path}` };
    }
  }
  files['feed/expected.json'] = json({
    description: 'One FeedResponse page per instance-audience event type and per managed-operation kind. Invalid twins fail the event data schema at the given path (from the page root).',
    fixtures: expected,
  });
  return files;
}

// ----------------------------------------------------------------------------------------- keys
export function manifestKeys(iat = NOW) {
  const nb = iat - 86400;
  return [
    manifestEntry(testKey('assertion'), { notBefore: nb }),
    manifestEntry(testKey('entitlement'), { notBefore: nb }),
    manifestEntry(testKey('entitlementNext'), { notBefore: nb }),
    manifestEntry(testKey('intent'), { notBefore: nb }),
  ];
}

function keys() {
  const files = {};
  const keysArr = manifestKeys();
  const valid = signManifest({ issuer: ISSUER, iat: NOW, keys: keysArr });
  const mismatch = signManifest({ issuer: ISSUER, iat: NOW, keys: keysArr, keysShaOverride: '0'.repeat(64) });
  const unknownRoot = signManifest({ issuer: ISSUER, iat: NOW, keys: keysArr, root: testKey('unknownRoot') });
  for (const [name, body] of Object.entries({ 'manifest.valid': valid, 'manifest.keys-sha256-mismatch': mismatch, 'manifest.unknown-root': unknownRoot })) {
    const v = validateSchema('keyManifest', body);
    if (!v.ok) throw new Error(`keys/${name}.json does not validate: ${JSON.stringify(v.errors[0])}`);
    files[`keys/${name}.json`] = json(body);
  }
  files['keys/expected.json'] = json({
    description: 'Verification outcome of each manifest against the TEST root in roots.json at the context time.',
    fixtures: {
      'manifest.valid.json': { valid: true, trusted_kids: keysArr.map((k) => k.kid) },
      'manifest.keys-sha256-mismatch.json': { valid: false, code: 'keys_mismatch' },
      'manifest.unknown-root.json': { valid: false, code: 'unknown_root' },
    },
  });
  files['keys/roots.json'] = json({ keys: [testRootEntry(ISSUER)] });
  files['keys/context.json'] = json({
    description: 'Inputs a verifier uses with these fixtures: the issuer the manifest names, the time to verify at (seconds), and where the TEST keys come from.',
    issuer: ISSUER,
    now: NOW,
    roots_file: 'keys/roots.json',
    test_keys: 'derived at build time: seed = sha256("ever-connect-sdk/<label>"); no private key file is committed',
  });
  return files;
}

// --------------------------------------------------------------------------------- entitlements
const FEATURES = ['handle', 'discoverability', 'lookup', 'profile.public', 'profile.badges', 'listings', 'marketplace.buy', 'instances.multi', 'ever_id_login', 'app_sync', 'usage_reporting', 'provider_access'];
const LIMITS = ['instances.connected', 'listings.published', 'api.rpm', 'members', 'webhooks.endpoints', 'lookup.hashes_per_day', 'lookup.queries_per_min'];

export function entitlementClaims({ subject, seq = 3, iat = NOW, link = null }) {
  const ever = {
    schema: 'ever.entitlement.v1',
    seq,
    org_id: IDS.org,
    handle: 'acme',
    tenant_id: IDS.tenant,
    instance_id: IDS.instance,
    tier: 'paid',
    plan: { code: 'ever_gauzy_selfhosted_small_business_lifetime', source: 'licence_certificate', ref: 'EVER-GAUZY-SB-1A2B3C4D' },
    products: ['gauzy', 'teams'],
    licence_ids: ['EVER-GAUZY-SB-1A2B3C4D'],
    features: Object.fromEntries(FEATURES.map((f) => [f, ['handle', 'lookup', 'ever_id_login', 'profile.public'].includes(f)])),
    limits: Object.fromEntries(LIMITS.map((l) => [l, l === 'api.rpm' ? 600 : l === 'lookup.hashes_per_day' ? 6000 : l === 'lookup.queries_per_min' ? 60 : 5])),
    meters: { 'instances.connected': { used: 1, period: null }, 'lookup.queries': { used: 12, period: '2026-11' } },
    managed: { updates: false, backups: false, support_level: 'community' },
    grace_s: 2592000,
    refresh_after_s: 21600,
  };
  if (link) {
    ever.tenant_link_id = link;
    ever.tenant = { product: 'gauzy', product_tenant_id: 'tenant-1', product_org_id: 'org-1' };
  }
  return {
    iss: ISSUER,
    aud: 'ever-connect',
    sub: subject,
    jti: ulid(`entitlement/${subject}/${seq}`),
    iat,
    nbf: iat - 60,
    exp: iat + 604800,
    ever,
  };
}

function entitlements() {
  const files = {};
  const expected = {};
  const key = testKey('entitlement');
  const add = (dir, name, jws, claims, exp) => {
    files[`entitlement/${dir}/${name}.jws`] = `${jws}\n`;
    if (claims) files[`entitlement/${dir}/${name}.claims.json`] = json(claims);
    expected[`${dir}/${name}.jws`] = exp;
  };
  const instance = entitlementClaims({ subject: `instance:${IDS.instance}` });
  const link = entitlementClaims({ subject: `link:${IDS.link}`, link: IDS.link });
  for (const [name, claims] of Object.entries({ instance, link })) {
    const v = validateSchema('entitlement', claims);
    if (!v.ok) throw new Error(`entitlement ${name} claims do not validate: ${JSON.stringify(v.errors[0])}`);
    add('valid', name, signEntitlement(claims), claims, { valid: true, kid: key.kid, seq: claims.ever.seq, subject: claims.sub });
  }
  const sign = (claims, header = {}, k = key) => signJws(k.privateKey, { kid: k.kid, typ: ENTITLEMENT_TYP, ...header }, claims);
  const good = sign(instance);
  const [h, p, s] = good.split('.');
  const tamper = (claimsPatch) => `${h}.${b64url(JSON.stringify({ ...instance, ever: { ...instance.ever, ...claimsPatch } }))}.${s}`;
  const invalid = {
    'tampered-kid': [`${b64url(JSON.stringify({ alg: 'EdDSA', kid: testKey('entitlementNext').kid, typ: ENTITLEMENT_TYP }))}.${p}.${s}`, 'bad_signature', 'the header names another trusted entitlement key; the signature was made by the first'],
    'tampered-seq': [tamper({ seq: 99 }), 'bad_signature', 'the payload changed after signing'],
    'wrong-instance': [sign({ ...instance, ever: { ...instance.ever, instance_id: IDS.otherInstance } }), 'instance_mismatch', 'issued for another installation'],
    'wrong-subject': [sign(entitlementClaims({ subject: `link:${IDS.otherLink}`, link: IDS.otherLink })), 'subject_mismatch', 'a link document where the instance document is expected'],
    'wrong-aud': [sign({ ...instance, aud: 'ever-platform' }), 'audience_mismatch', 'the audience is not ever-connect', ['schema_violation']],
    'wrong-issuer': [sign({ ...instance, iss: 'https://api.example.com' }), 'issuer_mismatch', 'issued by another origin'],
    'bad-typ': [sign(instance, { typ: 'JWT' }), 'bad_typ', 'not an entitlement document type'],
    rs256: [`${b64url(JSON.stringify({ alg: 'RS256', kid: key.kid, typ: ENTITLEMENT_TYP }))}.${p}.${b64url(sha256('not-a-signature'))}`, 'bad_alg', 'only EdDSA is accepted'],
    'iat-future': [sign({ ...instance, iat: NOW + 600, nbf: NOW - 60 }), 'iat_in_future', 'issued more than 300 s in the future'],
    'nbf-future': [sign({ ...instance, nbf: NOW + 600 }), 'nbf_in_future', 'not valid before more than 300 s in the future'],
    'unknown-kid': [signJws(testKey('stranger').privateKey, { kid: 'test-entitlement-9', typ: ENTITLEMENT_TYP }, instance), 'unknown_kid', 'a key id the manifest does not list'],
    'wrong-purpose': [sign(instance, { kid: testKey('assertion').kid }, testKey('assertion')), 'unknown_kid', 'signed by a key whose purpose is not entitlement'],
    'flat-shape': [
      sign({ schema: 'ever.entitlement.v1', sub: `instance:${IDS.instance}`, instance_id: IDS.instance, plan: 'self_hosted_paid', features: { discoverable: true }, iat: NOW, exp: NOW + 604800, refresh_after: NOW + 21600 }),
      'schema_violation',
      'the superseded flat claim shape',
    ],
    'stale-seq': [sign({ ...instance, ever: { ...instance.ever, seq: 1 } }), 'entitlement_stale', 'a lower sequence number than the cached document (cached seq 3)'],
  };
  for (const [name, [jws, code, reason, also]] of Object.entries(invalid)) {
    add('invalid', name, jws, null, { valid: false, code, reason, ...(also ? { also_acceptable: also } : {}) });
  }
  files['entitlement/expected.json'] = json({
    description:
      'Verification outcome of each document in the order of the entitlement verification rules (typ, alg, kid in the root-verified manifest with purpose entitlement, signature, schema and claims, instance and subject, iat/nbf, seq), with the inputs of context.json. A verifier that checks the closed schema first may answer a code from also_acceptable.',
    fixtures: expected,
  });
  files['entitlement/context.json'] = json({
    manifest: 'keys/manifest.valid.json',
    roots_file: 'keys/roots.json',
    expected_issuer: ISSUER,
    expected_instance_id: IDS.instance,
    expected_subject: `instance:${IDS.instance}`,
    expected_subject_by_file: { 'valid/link.jws': `link:${IDS.link}` },
    cached: { seq: 3, iat: NOW - 3600 },
    cached_by_file: { 'valid/instance.jws': null, 'valid/link.jws': null },
    now: NOW,
  });
  return files;
}

// -------------------------------------------------------------------------------------- consent
function consentRecords() {
  const files = {};
  const expected = {};
  const base = {
    id: IDS.consent,
    org_id: IDS.org,
    instance_id: IDS.instance,
    tenant_link_id: IDS.link,
    integration_key: 'stats_link',
    scope_version: 1,
    dpa_version: '2026-10',
    terms_version: '2026-10',
    granted_by_person_id: ulid('person/owner'),
    granted_at: iso(NOW),
    consent_source: 'app_ever_co',
    evidence: { ui: 'app.ever.co', screen_version: '1', request_id: 'req-1', ui_locale: 'en' },
    revoked_at: null,
    revoked_by_person_id: null,
    revoke_reason: null,
    revoke_source: null,
    supersedes_id: null,
  };
  const valid = {
    'app-ever-co': base,
    'product-ui': { ...base, id: ulid('consent/product-ui'), integration_key: 'counterparty_lookup', consent_source: 'product_ui', evidence: { ui: 'product:gauzy', screen_version: '1', request_id: 'req-2', ui_locale: 'en' } },
    'cloud-terms': { ...base, id: ulid('consent/cloud-terms'), integration_key: 'usage_reporting', consent_source: 'cloud_terms', granted_by_person_id: null, evidence: { screen_version: '1' } },
    revoked: { ...base, id: ulid('consent/revoked'), revoked_at: iso(NOW + 3600), revoked_by_person_id: ulid('person/owner'), revoke_reason: 'owner', revoke_source: 'platform' },
  };
  const invalid = {
    'product-ui-instance-url': [{ ...valid['product-ui'], integration_key: 'instance_url' }, '/integration_key', 'instance_url is enabled in app.ever.co only'],
    'product-ui-discoverable': [{ ...valid['product-ui'], integration_key: 'counterparty_discoverable' }, '/integration_key', 'counterparty_discoverable is enabled in app.ever.co only'],
    'product-ui-without-evidence': [Object.fromEntries(Object.entries(valid['product-ui']).filter(([k]) => k !== 'evidence')), '/evidence', 'an in-product consent records where it was given'],
    'cloud-terms-with-person': [{ ...valid['cloud-terms'], granted_by_person_id: ulid('person/owner') }, '/granted_by_person_id', 'a consent under the cloud terms has no grantor'],
    'evidence-ip-address': [{ ...base, evidence: { ...base.evidence, ip_address: '203.0.113.7' } }, '/evidence/ip_address', 'evidence never holds an address'],
    'unknown-source': [{ ...base, consent_source: 'email' }, '/consent_source', 'a consent source outside the list'],
  };
  for (const [name, record] of Object.entries(valid)) {
    const v = validateSchema('consent', record);
    if (!v.ok) throw new Error(`consent/valid/${name}.json does not validate: ${JSON.stringify(v.errors[0])}`);
    files[`consent/valid/${name}.json`] = json(record);
    expected[`valid/${name}.json`] = { valid: true };
  }
  for (const [name, [record, path, reason]] of Object.entries(invalid)) {
    const v = validateSchema('consent', record);
    if (v.ok) throw new Error(`consent/invalid/${name}.json validates`);
    if (v.errors[0].path !== path) throw new Error(`consent/invalid/${name}.json fails at ${v.errors[0].path}, expected ${path}`);
    files[`consent/invalid/${name}.json`] = json(record);
    expected[`invalid/${name}.json`] = { valid: false, path, reason };
  }
  files['consent/expected.json'] = json({ description: 'Verdict of each consent record against ever.consent.v1.json; invalid records fail at the given path.', fixtures: expected });
  return files;
}

export const LEGAL = {
  terms_url: 'https://ever.co/legal/terms',
  terms_version: '2026-10',
  dpa_url: 'https://ever.co/legal/dpa',
  dpa_version: '2026-10',
  subprocessors_url: 'https://ever.co/legal/subprocessors',
};

const FREQUENCY = { once: 'once', on_action: 'only when you act', on_change: 'when the value changes', daily: 'once a day', events: 'as events happen' };
const FORM = { clear: 'as is', salted_hash: 'as a salted one-way hash', count: 'as a count', id: 'as an identifier', url: 'as an address' };

function consentScreens(constants, integrations) {
  const files = {};
  for (const key of constants.integration_keys) {
    const d = integrations[key];
    const leaves = d.scope.filter((r) => r.direction === 'to_ever');
    const arrives = d.scope.filter((r) => r.direction === 'from_ever');
    const screen = {
      key,
      scope_version: d.scope_version,
      screen_version: '1',
      blocks: {
        title: `Enable ${d.name} for {organization}`,
        purpose: d.description,
        leaves_installation: leaves.map((r) => ({ field: r.field_path, form: r.form, form_text: FORM[r.form], when: r.frequency, purpose: r.purpose, required: r.required })),
        arrives_at_installation: arrives.map((r) => ({ field: r.field_path, form: r.form, form_text: FORM[r.form], when: r.frequency, purpose: r.purpose })),
        platform_keeps: d.scope.map((r) => ({ field: r.field_path, retention: r.retention })),
        how_often: [...new Set(d.scope.map((r) => FREQUENCY[r.frequency]))],
        where_to_change: 'Integrations & data in this product, or Instances in app.ever.co; turning it off stops the data at once.',
        revoke_effect: d.revoke_effect,
        legal: { ...LEGAL },
        authorisation: 'I am authorised to enable this for {organization}',
      },
      in_product: { allowed: !['counterparty_discoverable', 'instance_url'].includes(key), step_up_max_age_s: constants.step_up_max_age_s },
    };
    files[`consent-screen/${key}.json`] = json(screen);
  }
  return files;
}

// -------------------------------------------------------------------------------------- connect
function connectVectors() {
  const files = {};
  const key = testKey('connect');
  const previous = testKey('connectNext');
  const audience = `${ISSUER}/v1/instances/token`;
  const ctx = {
    instance_id: IDS.instance,
    audience,
    now: NOW,
    current_key: { kty: 'OKP', crv: 'Ed25519', x: key.x, kid: key.kid },
    previous_key: { kty: 'OKP', crv: 'Ed25519', x: previous.x, kid: previous.kid },
    rotated_at: NOW - 3 * 86400,
    seen_jti: ['replayed-jti-0000000000'],
  };
  const vec = (name, assertion, expected, description, context = {}) => {
    files[`connect/vectors/assertion-${name}.json`] = json({ description, context: { ...ctx, ...context }, assertion, expected });
  };
  const ok = { status: 200 };
  const bad = { status: 401, code: 'invalid_client' };
  vec('valid', signClientAssertion({ instanceId: IDS.instance, audience, iat: NOW }), ok, 'a fresh assertion signed with the current key');
  vec('wrong-aud', signClientAssertion({ instanceId: IDS.instance, audience: 'https://api.example.com/v1/instances/token', iat: NOW }), bad, 'the audience is another token endpoint');
  vec('exp-too-far', signClientAssertion({ instanceId: IDS.instance, audience, iat: NOW, ttl: 600 }), bad, 'exp is more than 300 s after iat');
  vec('skew', signClientAssertion({ instanceId: IDS.instance, audience, iat: NOW - 900 }), bad, 'iat is more than 300 s away from the server clock (and already expired)');
  vec('replayed-jti', signClientAssertion({ instanceId: IDS.instance, audience, iat: NOW, jti: 'replayed-jti-0000000000' }), bad, 'a jti the platform has seen before');
  vec('previous-key-inside-overlap', signClientAssertion({ key: previous, instanceId: IDS.instance, audience, iat: NOW }), ok, 'signed with the previous connect key 3 days after rotation (accepted for 7 days)');
  vec('previous-key-outside-overlap', signClientAssertion({ key: previous, instanceId: IDS.instance, audience, iat: NOW }), bad, 'signed with the previous connect key 8 days after rotation', { rotated_at: NOW - 8 * 86400 });
  const [, payload] = signClientAssertion({ instanceId: IDS.instance, audience, iat: NOW }).split('.');
  vec('alg-none', `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${payload}.`, bad, 'an unsigned assertion');
  vec('rs256', `${b64url(JSON.stringify({ alg: 'RS256', kid: key.kid, typ: 'JWT' }))}.${payload}.${b64url(sha256('not-a-signature'))}`, bad, 'another algorithm');
  vec('uuid-iss', signClientAssertion({ instanceId: IDS.statsInstance, audience, iat: NOW }), bad, 'issuer and subject are a UUID (a statistics id), not the installation ULID');
  vec('stranger-key', signClientAssertion({ key: testKey('stranger'), instanceId: IDS.instance, audience, iat: NOW }), bad, 'signed by a key the platform never pinned');
  return files;
}

// ---------------------------------------------------------------------------------------- build
export function buildAll() {
  const constants = readJson(join(REPO, 'contracts/constants.json'));
  const integrations = Object.fromEntries(constants.integration_keys.map((k) => [k, readJson(join(REPO, `contracts/integrations/${k}.json`))]));
  const files = {
    ...requests(),
    ...feed(constants),
    ...keys(),
    ...entitlements(),
    ...consentRecords(),
    ...consentScreens(constants, integrations),
    ...connectVectors(),
    ...Object.fromEntries(Object.entries(statsFixtures()).map(([p, t]) => [`stats/${p}`, t])),
  };
  files['index.json'] = json(fixtureIndex(files));
  return Object.fromEntries(Object.entries(files).map(([p, t]) => [`${FIXTURES}/${p}`, t]));
}

/**
 * The schema-bound JSON fixtures and their verdicts, for the TypeScript/Rust round trip: `kind` is
 * `component` (a schema of the contract), `pending` (a body pending upstream), `schema` (one of
 * the JSON Schemas) or `feed` (a FeedResponse page whose events carry catalog data). `typed`
 * fixtures also deserialize into the generated types and back.
 */
function fixtureIndex(files) {
  const entries = [];
  const read = (p) => JSON.parse(files[p]);
  for (const [name, e] of Object.entries(read('requests/expected.json').fixtures)) {
    const pending = e.schema.startsWith('pending:');
    entries.push({ file: `requests/${name}`, kind: pending ? 'pending' : 'component', schema: pending ? e.schema.slice(8) : e.schema, valid: e.valid, typed: e.valid && !pending });
  }
  for (const [name, e] of Object.entries(read('feed/expected.json').fixtures))
    entries.push({ file: `feed/${name}`, kind: 'feed', schema: e.type, valid: e.valid, typed: e.valid });
  for (const name of ['manifest.valid', 'manifest.keys-sha256-mismatch', 'manifest.unknown-root'])
    entries.push({ file: `keys/${name}.json`, kind: 'schema', schema: 'keyManifest', valid: true, typed: true });
  for (const name of ['instance', 'link']) entries.push({ file: `entitlement/valid/${name}.claims.json`, kind: 'schema', schema: 'entitlement', valid: true, typed: true });
  for (const [name, e] of Object.entries(read('consent/expected.json').fixtures))
    entries.push({ file: `consent/${name}`, kind: 'schema', schema: 'consent', valid: e.valid, typed: e.valid });
  for (const [name, e] of Object.entries(read('stats/expected.json').fixtures)) {
    // Ingest-layer fixtures are schema-valid documents the ingest refuses for other reasons.
    const valid = e.layer === 'ingest' ? true : e.status === 202;
    entries.push({ file: `stats/${name}`, kind: 'schema', schema: 'stats', valid, typed: valid && e.layer !== 'ingest' });
  }
  entries.sort((a, b) => a.file.localeCompare(b.file));
  return {
    description: 'Every schema-bound JSON fixture with the schema it is checked against and its verdict. The TypeScript (ajv) and Rust (jsonschema) round trips must both reach these verdicts.',
    fixtures: entries,
  };
}

function main() {
  const check = process.argv.includes('--check');
  const files = buildAll();
  const managed = ['requests', 'feed', 'keys', 'entitlement', 'consent', 'consent-screen', 'connect', 'stats'];
  const current = {};
  for (const dir of managed)
    for (const p of walk(join(REPO, FIXTURES, dir))) {
      const rel = p.slice(REPO.length + 1).split('\\').join('/');
      current[rel] = readFileSync(p, 'utf8');
    }
  for (const p of Object.keys(files)) if (!(p in current)) current[p] = existsSync(join(REPO, p)) ? readFileSync(join(REPO, p), 'utf8') : undefined;
  const differing = diffOutputs(files, current);
  if (check) {
    if (differing.length > 0) {
      process.stderr.write(`build-signed --check: ${differing.length} fixture(s) differ:\n  ${differing.slice(0, 40).join('\n  ')}\nRun: node tools/fixtures/build-signed.mjs\n`);
      process.exit(1);
    }
    process.stdout.write(`build-signed --check: ok (${Object.keys(files).length} fixtures)\n`);
    return;
  }
  for (const p of differing) {
    if (files[p] === undefined) rmSync(join(REPO, p));
    else writeText(join(REPO, p), files[p]);
  }
  process.stdout.write(`build-signed: ${differing.length} fixture(s) written (${Object.keys(files).length} total)\n`);
}

if (process.argv[1] && process.argv[1].endsWith('build-signed.mjs')) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`build-signed: ${error.message}\n`);
    process.exit(1);
  }
}
