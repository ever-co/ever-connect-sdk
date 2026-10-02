// Every fixture says what it claims: valid fixtures validate, invalid ones fail with their expected
// code and path, signed fixtures verify (or fail) exactly as their expected outcome says.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { REPO, readJson } from '../lib/common.mjs';
import { verifyAssertion } from '../mock-platform/src/assertion.mjs';
import { fromB64url, sha256Hex } from '../mock-platform/src/crypto.mjs';
import { validateComponent, validateEnvelope, validateEventData, validatePending, validateSchema } from '../mock-platform/src/validate.mjs';
import { verifyEntitlement, verifyManifest } from './lib/reference-verify.mjs';

const F = join(REPO, 'contracts/fixtures');
const fixture = (p) => readJson(join(F, p));
const text = (p) => readFileSync(join(F, p), 'utf8');

test('request fixtures: valid bodies validate, every invalid twin fails at its path', () => {
  const { fixtures } = fixture('requests/expected.json');
  assert.ok(Object.keys(fixtures).length >= 60);
  for (const [file, e] of Object.entries(fixtures)) {
    const body = fixture(`requests/${file}`);
    const r = e.schema.startsWith('pending:') ? validatePending(e.schema.slice(8), body) : validateComponent(e.schema, body);
    assert.equal(r.ok, e.valid, `${file} against ${e.schema}`);
    if (!e.valid) assert.equal(r.errors[0].path, e.path, `${file} fails at the wrong path`);
  }
});

test('the redeem fixture and its null-id twin behave as the contract says', () => {
  assert.equal(validateComponent('RedeemRequest', fixture('requests/redeem.json')).ok, true);
  const twin = validateComponent('RedeemRequest', fixture('requests/redeem.invalid-null-id.json'));
  assert.equal(twin.ok, false);
  assert.equal(twin.errors[0].path, '/tenant/product_org_id');
});

test('feed fixtures: one valid page per instance-audience type; managed twins fail at their path', () => {
  const constants = readJson(join(REPO, 'contracts/constants.json'));
  const { fixtures } = fixture('feed/expected.json');
  for (const type of constants.feed_event_types) assert.ok(fixtures[`${type}.json`]?.valid, `no page for ${type}`);
  for (const [file, e] of Object.entries(fixtures)) {
    const page = fixture(`feed/${file}`);
    assert.equal(validateComponent('FeedResponse', page).ok, true, `${file}: page shape`);
    for (const event of page.events) {
      assert.equal(validateEnvelope(event).ok, true, `${file}: envelope`);
      assert.equal(event.type, e.type);
      const r = validateEventData(event.type, event.data);
      assert.equal(r.ok, e.valid, `${file}: data`);
      if (!e.valid) assert.equal(`/events/0/data${r.errors[0].path}`, e.path, `${file} fails at the wrong path`);
    }
  }
});

test('key manifests verify against the TEST root, and the broken ones fail with their code', () => {
  const ctx = fixture('keys/context.json');
  const roots = fixture('keys/roots.json').keys;
  for (const [file, e] of Object.entries(fixture('keys/expected.json').fixtures)) {
    const body = fixture(`keys/${file}`);
    assert.equal(validateSchema('keyManifest', body).ok, true, `${file}: schema`);
    const r = verifyManifest(body, roots, ctx.issuer, ctx.now);
    assert.equal(r.ok, e.valid, file);
    if (!e.valid) assert.equal(r.code, e.code, file);
    else assert.deepEqual(r.keys.map((k) => k.kid), e.trusted_kids);
  }
});

test('entitlement documents: the valid ones verify, every invalid one fails with its expected code', () => {
  const ctx = fixture('entitlement/context.json');
  const keysCtx = fixture('keys/context.json');
  const manifest = verifyManifest(fixture(ctx.manifest), fixture(ctx.roots_file).keys, keysCtx.issuer, keysCtx.now);
  assert.equal(manifest.ok, true);
  const { fixtures } = fixture('entitlement/expected.json');
  assert.ok(Object.keys(fixtures).length >= 16);
  for (const [file, e] of Object.entries(fixtures)) {
    const jws = text(`entitlement/${file}`).trim();
    const subject = ctx.expected_subject_by_file[file] ?? ctx.expected_subject;
    const cached = file in ctx.cached_by_file ? ctx.cached_by_file[file] : ctx.cached;
    const r = verifyEntitlement(jws, { keys: manifest.keys, issuer: ctx.expected_issuer, instanceId: ctx.expected_instance_id, subject, cached, now: ctx.now });
    assert.equal(r.ok, e.valid, `${file}: ${r.code ?? 'ok'}`);
    if (e.valid) {
      assert.equal(r.claims.ever.seq, e.seq);
      assert.deepEqual(r.claims, fixture(`entitlement/${file.replace(/\.jws$/, '.claims.json')}`));
    } else {
      assert.ok([e.code, ...(e.also_acceptable ?? [])].includes(r.code), `${file}: ${r.code}, expected ${e.code}`);
    }
  }
});

test('consent records: valid ones validate, invalid ones fail at their path', () => {
  for (const [file, e] of Object.entries(fixture('consent/expected.json').fixtures)) {
    const r = validateSchema('consent', fixture(`consent/${file}`));
    assert.equal(r.ok, e.valid, file);
    if (!e.valid) assert.equal(r.errors[0].path, e.path, file);
  }
  assert.equal(fixture('consent/valid/product-ui.json').consent_source, 'product_ui');
});

test('consent screens: seven blocks per non-hidden key, in-product consent refused for the two app-only keys', () => {
  const constants = readJson(join(REPO, 'contracts/constants.json'));
  const files = readdirSync(join(F, 'consent-screen')).sort();
  assert.deepEqual(files, constants.integration_keys.map((k) => `${k}.json`).sort());
  for (const key of constants.integration_keys) {
    const screen = fixture(`consent-screen/${key}.json`);
    const def = readJson(join(REPO, 'contracts/integrations', `${key}.json`));
    const b = screen.blocks;
    assert.equal(b.title, `Enable ${def.name} for {organization}`);
    assert.equal(b.purpose, def.description);
    assert.deepEqual(b.leaves_installation.map((r) => r.field), def.scope.filter((r) => r.direction === 'to_ever').map((r) => r.field_path));
    assert.equal(b.platform_keeps.length, def.scope.length);
    assert.ok(b.how_often.length > 0 && b.where_to_change && b.authorisation.includes('{organization}'));
    for (const k of ['terms_url', 'terms_version', 'dpa_url', 'dpa_version', 'subprocessors_url']) assert.ok(b.legal[k], `${key}: legal ${k}`);
    assert.equal(screen.in_product.allowed, !['counterparty_discoverable', 'instance_url'].includes(key));
  }
});

test('client-assertion vectors: the platform rules give each vector its expected answer', () => {
  const dir = join(F, 'connect/vectors');
  const files = readdirSync(dir).sort();
  assert.ok(files.length >= 10);
  for (const file of files) {
    const v = readJson(join(dir, file));
    const c = v.context;
    const r = verifyAssertion(v.assertion, {
      now: c.now,
      audience: c.audience,
      instanceFor: (iss) => (iss === c.instance_id ? { current_key: c.current_key, previous_key: c.previous_key, rotated_at: c.rotated_at } : null),
      seenJti: (jti) => c.seen_jti.includes(jti),
    });
    assert.equal(r.ok ? 200 : 401, v.expected.status, `${file}: ${r.reason ?? 'ok'}`);
  }
});

test('lookup vectors: every published hash recomputes from the test salt', () => {
  const v = fixture('lookup/test-vectors.json');
  assert.equal(v.salt_version, 0);
  const salt = fromB64url(v.salt);
  assert.equal(salt.length, 32);
  assert.equal(salt.toString('hex'), sha256Hex('ever-lookup-test-salt'));
  for (const vec of v.vectors) {
    const hash = sha256Hex(Buffer.concat([salt, Buffer.from(`:${vec.kind}:${vec.normalized}`, 'utf8')]));
    assert.equal(hash, vec.hash, `${vec.kind} ${JSON.stringify(vec.input)}`);
  }
});

test('statistics fixtures: goldens validate, schema-layer invalids fail at their path, ingest-layer ones are planted', () => {
  const { fixtures } = fixture('stats/expected.json');
  assert.equal(Object.keys(fixtures).filter((f) => f.startsWith('valid/')).length, 5);
  assert.equal(Object.keys(fixtures).filter((f) => f.startsWith('invalid/')).length, 12);
  for (const [file, e] of Object.entries(fixtures)) {
    const raw = text(`stats/${file}`);
    if (e.layer === 'ingest') {
      if (file.includes('07-oversize')) assert.ok(Buffer.byteLength(raw) > 16384);
      if (file.includes('11-integral-float')) assert.match(raw, /"invoices": 214\.0,/);
      if (file.includes('12-duplicate-key')) assert.equal(raw.match(/"country":/g).length, 2);
      continue;
    }
    const r = validateSchema('stats', JSON.parse(raw));
    assert.equal(r.ok, e.status === 202, file);
    if (!r.ok) assert.equal(r.errors[0].path, e.path, file);
  }
});
