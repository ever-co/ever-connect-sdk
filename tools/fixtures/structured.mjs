// The structured corpus of the entitlement verifiers: documents and key manifests built on purpose
// (splices, re-signed claims, other keys, header and payload tricks, number and time forms, weak
// keys, rollback, compact-form defects, trust anchoring), each with the context it is verified in.
// The reference verifier gives every case its answer (contracts/fixtures/entitlement/structured.json)
// and the TypeScript and Rust suites must reproduce each one.
import { b64url, signBytes } from '../mock-platform/src/crypto.mjs';
import { ENTITLEMENT_TYP, signManifest, testKey } from '../mock-platform/src/keys.mjs';
import { NOW } from './ids.mjs';

const enc = (x) => (Buffer.isBuffer(x) ? x : Buffer.from(typeof x === 'string' ? x : JSON.stringify(x), 'utf8'));
/** A compact JWS over exact header and payload bytes (text, object or Buffer), signed by `key`. */
const signText = (key, header, payload) => {
  const input = `${b64url(enc(header))}.${b64url(enc(payload))}`;
  return `${input}.${signBytes(key.privateKey, input)}`;
};
const IDENTITY = Buffer.from(`01${'00'.repeat(31)}`, 'hex');
const BASE_POINT = Buffer.from(`58${'66'.repeat(31)}`, 'hex');
/** R = B, s = 1: a signature every message has under the identity-point key. */
const WEAK_SIGNATURE = b64url(Buffer.concat([BASE_POINT, Buffer.from(`01${'00'.repeat(31)}`, 'hex')]));
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

export function structuredCases({ issuer, ids, entitlementClaims, manifestKeys, platformManifests }) {
  const ent1 = testKey('entitlement');
  const ent2 = testKey('entitlementNext');
  const asr = testKey('assertion');
  const intent = testKey('intent');
  const root = testKey('root');
  const atk = testKey('stranger');
  const H = (patch = {}) => ({ alg: 'EdDSA', kid: ent1.kid, typ: ENTITLEMENT_TYP, ...patch });
  const instSub = `instance:${ids.instance}`;
  const linkSub = `link:${ids.link}`;
  const inst = entitlementClaims({ subject: instSub });
  const link = entitlementClaims({ subject: linkSub, link: ids.link });
  const doc = (claims, patch = {}, key = ent1) => signText(key, H(patch), claims);
  const good = doc(inst);
  const [gh, gp, gs] = good.split('.');
  const linkDoc = doc(link);
  const cases = [];
  const add = (group, name, jws, extra = {}) => cases.push({ name: `${group}/${name}`, jws, ...extra });
  const ever = (patch) => ({ ...inst, ever: { ...inst.ever, ...patch } });
  const manifestWith = (keys, o = {}) => signManifest({ issuer: o.issuer ?? issuer, iat: o.iat ?? NOW, keys, root: o.root ?? root });
  const keysWith = (edit) => manifestKeys().map((k) => (k.kid === ent1.kid ? { ...k, ...edit } : k));
  const payloadText = JSON.stringify(inst);

  // ---- baselines
  add('baseline', 'instance', good);
  add('baseline', 'link', linkDoc, { expected_subject: linkSub });
  add('baseline', 're-signed-ent-2', doc(inst, { kid: ent2.kid }, ent2));

  // ---- swaps between valid documents
  add('swap', 'link-payload-instance-signature', `${linkDoc.split('.').slice(0, 2).join('.')}.${gs}`);
  add('swap', 'instance-payload-link-signature', `${gh}.${gp}.${linkDoc.split('.')[2]}`);
  add('swap', 'link-document-as-instance', linkDoc);
  add('swap', 'instance-document-as-link', good, { expected_subject: linkSub });
  add('swap', 'other-instance-resigned', doc(ever({ instance_id: ids.otherInstance })));
  add('swap', 'instance-with-link-members-resigned', doc(ever({ tenant_link_id: ids.link, tenant: link.ever.tenant })));
  const bareLink = { ...link, ever: { ...link.ever } };
  delete bareLink.ever.tenant_link_id;
  delete bareLink.ever.tenant;
  add('swap', 'link-without-link-members-resigned', doc(bareLink), { expected_subject: linkSub });

  // ---- other keys and key ids
  add('keys', 'assertion-key', doc(inst, { kid: asr.kid }, asr));
  add('keys', 'intent-key', doc(inst, { kid: intent.kid }, intent));
  add('keys', 'root-key', doc(inst, { kid: root.kid }, root));
  add('keys', 'ent-2-under-ent-1-kid', doc(inst, {}, ent2));
  add('keys', 'attacker-own-kid', doc(inst, { kid: 'attacker-1' }, atk));
  add('keys', 'attacker-under-ent-1-kid', doc(inst, {}, atk));
  add('keys', 'embedded-jwk', doc(inst, { jwk: { kty: 'OKP', crv: 'Ed25519', x: atk.x } }, atk));
  add('keys', 'jku', doc(inst, { kid: 'attacker-1', jku: 'https://keys.example.com/jwks.json' }, atk));
  add('keys', 'numeric-kid', doc(inst, { kid: 1 }));
  add('keys', 'missing-kid', signText(ent1, { alg: 'EdDSA', typ: ENTITLEMENT_TYP }, inst));
  add('keys', 'escaped-kid', signText(ent1, `{"alg":"EdDSA","kid":"test-entitlement-\\u0031","typ":"${ENTITLEMENT_TYP}"}`, inst));
  add('keys', 'fullwidth-kid', doc(inst, { kid: 'ｔest-entitlement-1' }));
  add('keys', 'nul-kid', doc(inst, { kid: 'test-entitlement-1\u0000' }));
  add('keys', 'ent-2-kid-signed-by-ent-1', doc(inst, { kid: ent2.kid }, ent1));
  add('keys', 'array-kid', doc(inst, { kid: [ent1.kid] }));

  // ---- key windows and duplicate key ids (manifests re-signed by the TEST root)
  add('window', 'previous-past-not-after', good, {
    manifest: manifestWith(keysWith({ state: 'previous', not_after: iso(NOW - 86400) })),
  });
  add('window', 'previous-within-skew', good, {
    manifest: manifestWith(keysWith({ state: 'previous', not_after: iso(NOW - 200) })),
  });
  add('window', 'not-before-future', good, { manifest: manifestWith(keysWith({ not_before: iso(NOW + 3600) })) });
  const ent1Entry = manifestKeys().find((k) => k.kid === ent1.kid);
  const shadow = { ...ent1Entry, x: atk.x };
  add('window', 'duplicate-kid-real-first', good, { manifest: manifestWith([...manifestKeys(), shadow]) });
  add('window', 'duplicate-kid-shadow-first', good, { manifest: manifestWith([shadow, ...manifestKeys()]) });

  // ---- key time formats: anything but a UTC time that exists refuses the manifest
  for (const [name, edit] of [
    ['offset', { not_before: '2026-11-01T12:00:00+02:00' }],
    ['space', { not_before: '2026-11-01 10:00:00Z' }],
    ['leap-second', { not_before: '2026-06-30T23:59:60Z' }],
    ['lower-case-z', { not_before: '2026-11-01T10:00:00z' }],
    ['date-only', { not_before: '2026-11-01' }],
    ['february-31', { not_before: '2026-02-31T00:00:00Z' }],
    ['expanded-year', { not_before: '+02026-11-01T10:00:00Z' }],
    ['garbage-not-after', { state: 'previous', not_after: 'soon' }],
  ])
    add('time', name, good, { manifest: manifestWith(keysWith(edit)) });

  // ---- weak keys
  const weakKey = { ...ent1Entry, kid: 'test-entitlement-9', x: b64url(IDENTITY) };
  const forged = `${b64url(enc(H({ kid: weakKey.kid })))}.${b64url(enc(inst))}.${WEAK_SIGNATURE}`;
  add('weak-key', 'identity-key-in-manifest', forged, { manifest: manifestWith([...manifestKeys(), weakKey]) });
  const weakRootManifest = (() => {
    const keys = manifestKeys();
    const valid = manifestWith(keys);
    const [h, p] = valid.manifest.split('.');
    return { manifest: `${h}.${p}.${WEAK_SIGNATURE}`, keys };
  })();
  add('weak-key', 'identity-root', good, {
    manifest: weakRootManifest,
    roots: [{ kid: root.kid, iss: issuer, kty: 'OKP', crv: 'Ed25519', x: b64url(IDENTITY) }],
  });

  // ---- header tricks (each signed by the entitlement key unless the case is about the key)
  const T = ENTITLEMENT_TYP;
  const K = ent1.kid;
  const hdr = (text) => signText(ent1, text, inst);
  add('header', 'reordered', hdr(`{"typ":"${T}","kid":"${K}","alg":"EdDSA"}`));
  add('header', 'whitespace', hdr(` { "alg" : "EdDSA" , "kid" : "${K}" , "typ" : "${T}" } `));
  add('header', 'duplicate-alg-none-then-eddsa', hdr(`{"alg":"none","alg":"EdDSA","kid":"${K}","typ":"${T}"}`));
  add('header', 'duplicate-alg-eddsa-then-none', hdr(`{"alg":"EdDSA","alg":"none","kid":"${K}","typ":"${T}"}`));
  add('header', 'duplicate-typ', hdr(`{"alg":"EdDSA","kid":"${K}","typ":"JWT","typ":"${T}"}`));
  add('header', 'duplicate-kid', hdr(`{"alg":"EdDSA","kid":"attacker-1","kid":"${K}","typ":"${T}"}`));
  add('header', 'escaped-alg', hdr(`{"alg":"Ed\\u0044SA","kid":"${K}","typ":"${T}"}`));
  add('header', 'alg-ed25519', doc(inst, { alg: 'Ed25519' }));
  add('header', 'alg-upper-case', doc(inst, { alg: 'EDDSA' }));
  add('header', 'alg-none', `${b64url(enc(H({ alg: 'none' })))}.${gp}.`);
  add('header', 'alg-rs256', doc(inst, { alg: 'RS256' }));
  add('header', 'alg-hs256', doc(inst, { alg: 'HS256' }));
  add('header', 'alg-array', doc(inst, { alg: ['EdDSA'] }));
  add('header', 'crit-empty', doc(inst, { crit: [] }));
  add('header', 'b64-false-without-crit', doc(inst, { b64: false }));
  add('header', 'typ-upper-case', doc(inst, { typ: T.toUpperCase() }));
  add('header', 'typ-application-prefix', doc(inst, { typ: `application/${T}` }));
  add('header', 'typ-missing', signText(ent1, { alg: 'EdDSA', kid: K }, inst));
  add('header', 'bom', hdr(`﻿${JSON.stringify(H())}`));
  add('header', 'array', hdr(JSON.stringify([H()])));
  add('header', 'trailing-garbage', hdr(`${JSON.stringify(H())}x`));
  add('header', 'trailing-whitespace', hdr(`${JSON.stringify(H())}  \n`));
  add('header', 'nesting-127', hdr(`{"alg":"EdDSA","kid":"${K}","typ":"${T}","x":${'['.repeat(126)}${']'.repeat(126)}}`));
  add('header', 'nesting-128', hdr(`{"alg":"EdDSA","kid":"${K}","typ":"${T}","x":${'['.repeat(127)}${']'.repeat(127)}}`));
  add('header', 'lone-surrogate-member', hdr(`{"alg":"EdDSA","kid":"${K}","typ":"${T}","x":"\\ud800"}`));
  add('header', 'fraction-member', hdr(`{"alg":"EdDSA","kid":"${K}","typ":"${T}","x":1.0}`));

  // ---- payload tricks
  const pay = (bytes) => signText(ent1, H(), bytes);
  const swap = (from, to) => pay(payloadText.replace(from, to));
  add('payload', 'bom', pay(`﻿${payloadText}`));
  add(
    'payload',
    'raw-invalid-utf8',
    pay(
      Buffer.concat([
        Buffer.from(payloadText.replace('"acme"', '"ac')),
        Buffer.from([0xff]),
        Buffer.from('me"' + payloadText.split('"acme"')[1]),
      ]),
    ),
  );
  add(
    'payload',
    'cesu-surrogate',
    pay(
      Buffer.concat([
        Buffer.from(payloadText.replace('"acme"', '"ac')),
        Buffer.from([0xed, 0xa0, 0x80]),
        Buffer.from('me"' + payloadText.split('"acme"')[1]),
      ]),
    ),
  );
  add('payload', 'duplicate-sub', pay(`{"sub":"${linkSub}",${payloadText.slice(1)}`));
  add('payload', 'duplicate-ever', pay(`{"ever":{"schema":"bogus"},${payloadText.slice(1)}`));
  add('payload', 'duplicate-tier', swap('"tier":"paid"', '"tier":"paid","tier":"bundle"'));
  add('payload', 'duplicate-seq', swap('"seq":3', '"seq":99,"seq":3'));
  add('payload', 'escaped-iss', swap(`"iss":"${issuer}"`, `"iss":"\\u0068${issuer.slice(1)}"`));
  add('payload', 'nul-aud', swap('"aud":"ever-connect"', '"aud":"ever-connect\\u0000"'));
  add('payload', 'array-aud', swap('"aud":"ever-connect"', '"aud":["ever-connect"]'));
  add('payload', 'lone-surrogate-handle', swap('"handle":"acme"', '"handle":"ac\\udc00me"'));
  add('payload', 'fullwidth-handle', swap('"handle":"acme"', '"handle":"ａcme"'));
  add('payload', 'combining-handle', swap('"handle":"acme"', '"handle":"acmé"'));
  add('payload', 'newline-handle', swap('"handle":"acme"', '"handle":"ac\\nme"'));
  add('payload', 'proto-member', pay(`{"__proto__":{},${payloadText.slice(1)}`));
  add('payload', 'ever-null', doc({ ...inst, ever: null }));
  add('payload', 'trailing-whitespace', pay(`${payloadText} \n`));
  add('payload', 'top-level-array', pay(`[${payloadText}]`));
  add('payload', 'extra-ever-member', doc(ever({ extra: true })));
  add('payload', 'issuer-with-path', doc({ ...inst, iss: `${issuer}/` }));
  add('payload', 'subject-trailing-space', doc({ ...inst, sub: `${instSub} ` }));

  // ---- numbers: integers only, without fraction or exponent, within plus or minus 2^53 - 1
  const num = (name, from, to, extra) => add('number', name, swap(from, to), extra);
  const iat = `"iat":${inst.iat}`;
  num('iat-exponent', iat, `"iat":${(inst.iat / 1e9).toString()}e9`);
  num('seq-integral-fraction', '"seq":3', '"seq":3.0');
  num('iat-1e300', iat, '"iat":1e300');
  num('seq-u64-max', '"seq":3', '"seq":18446744073709551615');
  num('seq-i64-max', '"seq":3', '"seq":9223372036854775807');
  num('iat-1e400', iat, '"iat":1e400');
  num('seq-2-53-plus-1', '"seq":3', '"seq":9007199254740993');
  num('seq-1e20', '"seq":3', '"seq":100000000000000000000');
  num('seq-negative', '"seq":3', '"seq":-1');
  num('seq-negative-zero', '"seq":3', '"seq":-0');
  num('seq-fraction', '"seq":3', '"seq":3.5');
  num('seq-leading-zero', '"seq":3', '"seq":03');
  num('seq-plus-sign', '"seq":3', '"seq":+3');
  num('seq-2-53-minus-1', '"seq":3', '"seq":9007199254740991');
  num('iat-string', iat, `"iat":"${inst.iat}"`);
  num('exp-2-53-minus-1', `"exp":${inst.exp}`, '"exp":9007199254740991');
  num('limit-unlimited', '"api.rpm":600', '"api.rpm":-1');
  add('number', 'expired-without-grace', doc({ ...inst, exp: NOW - 1, ever: { ...inst.ever, grace_s: 0 } }));
  // How a number is written matters only for the integer claims a verifier reads (iat, nbf, exp,
  // ever.seq, ever.grace_s); the schema's maximum bounds every integer.
  num('limit-integral-fraction', '"api.rpm":600', '"api.rpm":600.0');
  num('limit-2-53', '"api.rpm":600', '"api.rpm":9007199254740992');
  num('grace-exponent', '"grace_s":2592000', '"grace_s":2.592e6');
  num('nbf-negative-zero', `"nbf":${inst.nbf}`, '"nbf":-0');
  num('exp-integral-fraction', `"exp":${inst.exp}`, `"exp":${inst.exp}.0`);

  // ---- the manifest's expiry: keys of an expired manifest verify no new document
  const manifestExp = NOW + 2592000;
  add('expiry', 'one-second-before-manifest-exp', good, { now: manifestExp - 1 });
  add('expiry', 'at-manifest-exp', good, { now: manifestExp });
  add('expiry', 'past-manifest-exp-unknown-kid', doc(inst, { kid: 'attacker-1' }, atk), { now: manifestExp + 1 });
  add('expiry', 'past-manifest-exp-bad-typ', doc(inst, { typ: 'JWT' }), { now: manifestExp + 1 });

  // ---- the members each kind of subject carries
  const { instance_id: _i, ...orgEver } = inst.ever;
  add('subject', 'org-document', doc({ ...inst, sub: `org:${inst.ever.org_id}`, ever: orgEver }));
  add('subject', 'org-document-with-instance', doc({ ...inst, sub: `org:${inst.ever.org_id}` }));
  add('subject', 'instance-without-instance-id', doc({ ...inst, ever: orgEver }));
  const { tenant: _t, ...linkNoTenant } = link.ever;
  add('subject', 'link-without-tenant', doc({ ...link, ever: linkNoTenant }), { expected_subject: linkSub });
  add('subject', 'link-names-another-link', doc({ ...link, ever: { ...link.ever, tenant_link_id: ids.otherLink } }), {
    expected_subject: linkSub,
  });

  // ---- rollback against the cached document
  add('rollback', 'equal-seq-equal-iat', good, { cached: { seq: 3, iat: inst.iat } });
  add('rollback', 'equal-seq-later-iat', good, { cached: { seq: 3, iat: inst.iat - 1 } });
  add('rollback', 'lower-seq', good, { cached: { seq: 4, iat: 0 } });

  // ---- compact form
  const sBytes = Buffer.from(gs, 'base64url');
  let s = 0n;
  for (let i = 63; i >= 32; i -= 1) s = (s << 8n) | BigInt(sBytes[i]);
  const sPlusL = Buffer.from(sBytes);
  let v = s + L;
  for (let i = 32; i < 64; i += 1) {
    sPlusL[i] = Number(v & 255n);
    v >>= 8n;
  }
  const lastBits = gs.slice(0, -1) + String.fromCharCode(gs.charCodeAt(gs.length - 1) ^ 1);
  add('compact', 'padding', `${gh}=.${gp}.${gs}`);
  const std = (part) => part.replace(/-/g, '+').replace(/_/g, '/');
  const standard = [gh, gp, gs].map(std).join('.');
  if (standard === good) throw new Error('structured: no URL-safe character to swap');
  add('compact', 'standard-alphabet', standard);
  add('compact', 'four-parts', `${good}.${gs}`);
  add('compact', 'empty-signature', `${gh}.${gp}.`);
  add('compact', 'leading-space', ` ${good}`);
  add('compact', 'trailing-newline', `${good}\n`);
  add('compact', 'signature-trailing-bits', `${gh}.${gp}.${lastBits}`);
  add('compact', 'signature-s-plus-l', `${gh}.${gp}.${b64url(sPlusL)}`);

  // ---- trust anchoring: a key set vouches for its own issuer only
  const prod = 'https://api.ever.co';
  const attackerKeys = [...manifestKeys(), { ...ent1Entry, kid: 'attacker-1', x: atk.x }];
  const prodDoc = doc({ ...inst, iss: prod }, { kid: 'attacker-1' }, atk);
  const testRootForProd = manifestWith(attackerKeys, { issuer: prod });
  add('anchor', 'test-root-manifest-for-prod-pinned-roots', prodDoc, {
    manifest: testRootForProd,
    manifest_issuer: prod,
    roots: 'pinned',
    expected_issuer: prod,
  });
  add('anchor', 'test-root-manifest-for-prod-fixture-roots', prodDoc, {
    manifest: testRootForProd,
    manifest_issuer: prod,
    expected_issuer: prod,
  });
  add('anchor', 'fixture-key-set-prod-document', doc({ ...inst, iss: prod }), { expected_issuer: prod });
  add('anchor', 'attacker-key-set-prod-document', prodDoc, { manifest: manifestWith(attackerKeys), expected_issuer: prod });
  for (const m of platformManifests) {
    add('anchor', `${m.name}-key-set-prod-document`, prodDoc, {
      manifest: m.body,
      manifest_issuer: m.issuer,
      manifest_now: m.at,
      now: m.at,
      roots: 'pinned',
      expected_issuer: prod,
    });
    add('anchor', `${m.name}-manifest-for-prod`, prodDoc, {
      manifest: m.body,
      manifest_issuer: prod,
      manifest_now: m.at,
      now: m.at,
      roots: 'pinned',
      expected_issuer: prod,
    });
  }
  return cases;
}

const iso = (seconds) => new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
