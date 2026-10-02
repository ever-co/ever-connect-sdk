// In-memory, deterministic state of the mock platform, with a simulated clock.
import { randomBytes } from 'node:crypto';
import { b64url, sha256 } from './crypto.mjs';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export const DEFAULT_CONFIG = {
  issuer: 'http://mock-platform:8080',
  clock: { start: Date.UTC(2026, 10, 2, 10, 0, 0) / 1000 },
  codes: [
    {
      code: 'EVC-TEST-0000-0001',
      kind: 'connect',
      product: 'gauzy',
      org: { id: '01JMQCK0RG000000000000000A', handle: 'acme' },
      expires_in_s: 900,
      pending_approval: false,
    },
    {
      code: 'EVC-TEST-0000-0003',
      kind: 'connect',
      product: 'gauzy',
      org: { id: '01JMQCK0RG000000000000000A', handle: 'acme' },
      expires_in_s: 86400,
      pending_approval: true,
    },
    {
      code: 'EVC-TEST-0000-0004',
      kind: 'connect',
      product: 'works',
      org: { id: '01JMQCK0RG000000000000000A', handle: 'acme' },
      expires_in_s: 900,
      pending_approval: false,
    },
    {
      code: 'EVL-TEST-0000-0002',
      kind: 'link',
      product: 'gauzy',
      org: { id: '01JMQCK0RG000000000000000B', handle: 'globex' },
      expires_in_s: 900,
    },
  ],
  entitlement: {
    tier: 'paid',
    plan: { code: 'ever_gauzy_selfhosted_small_business_lifetime', source: 'licence_certificate', ref: 'EVER-GAUZY-SB-1A2B3C4D' },
    features: { handle: true, discoverability: true, lookup: true, 'profile.public': true, ever_id_login: true },
    managed: { updates: false, backups: false, support_level: 'community' },
  },
  integrations: { cloud_defaults: false, enabled: [] },
  lookup: {
    salt_versions: [
      { version: 1, salt: b64url(sha256('ever-connect-sdk/mock/lookup-salt/1')), active_from: '2026-11-01T00:00:00Z', retire_after: null },
    ],
    retired_versions: [],
    optins: [{ kind: 'vat', normalized: 'BG123456789', handle: 'acme', features: ['pay', 'invoice_exchange'] }],
    claimed_hashes: [],
  },
  people: [{ issuer: 'https://auth.ever.co', subject: '275396402232829475', person_id: '01JMQCKPERS0N00000000000P1', org_role: 'owner' }],
  limits: {
    wrong_codes_per_hour: 10,
    wrong_attempts_per_code: 5,
    heartbeat_min_interval_s: 60,
    entitlement_reads_per_hour: 6,
    stats_reports_per_day: 24,
    lookup_queries_per_min: 60,
    sso_discover_per_min: 60,
    device_starts_per_hour: 10,
    webhook_endpoints: 5,
  },
  faults: { keys_unavailable: false, webhooks_module_disabled: false, revoke_credential_at_call: null, connect_issuance_off: false },
};

function merge(base, over) {
  if (Array.isArray(base) || Array.isArray(over) || typeof base !== 'object' || base === null) return over === undefined ? base : over;
  const out = { ...base };
  for (const [k, v] of Object.entries(over ?? {})) out[k] = k in base ? merge(base[k], v) : v;
  return out;
}

export function makeConfig(config = {}) {
  return merge(structuredClone(DEFAULT_CONFIG), config);
}

export class MockState {
  constructor(config) {
    this.config = config;
    // clock.real: the clock follows real time from the moment the mock starts (product CI, where
    // products sign with their own clock); otherwise it stands still at clock.start (tests).
    if (config.clock?.real) config.clock.start = Math.floor(Date.now() / 1000);
    this.reset();
  }

  reset() {
    this.offset = 0;
    this.counter = 0;
    this.codes = new Map();
    for (const c of this.config.codes) this.addCode(c);
    this.instances = new Map();
    this.tokens = new Map();
    this.jti = new Map();
    this.wrongCodes = new Map();
    this.devices = new Map();
    this.statsPins = new Map();
    this.statsReports = [];
    this.intents = new Map();
    this.installs = new Map();
    this.grants = new Map();
    this.operations = new Map();
    this.faults = structuredClone(this.config.faults);
    this.keyGeneration = 1;
    this.keysRotatedAt = null;
    this.windows = new Map();
    this.idempotency = new Map();
    this.authCalls = 0;
    this.lastInstanceId = null;
    this.waiters = new Set();
  }

  /** The clock before any offset: real time with clock.real, else clock.start. */
  base() {
    return this.config.clock.real ? Date.now() / 1000 : this.config.clock.start;
  }

  now() {
    return Math.floor(this.base() + this.offset);
  }

  iso(seconds = this.now()) {
    return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  }

  /** A fresh ULID-shaped id: deterministic per run (the counter), never repeated. */
  ulid(prefix = 'X') {
    this.counter += 1;
    const bytes = sha256(`mock/${prefix}/${this.counter}`);
    let out = '01JM';
    for (let i = 0; out.length < 26; i += 1) out += CROCKFORD[bytes[i] % 32];
    return out;
  }

  addCode(c) {
    this.codes.set(c.code.toUpperCase(), {
      ...c,
      code: c.code.toUpperCase(),
      expires_at: this.now() + (c.expires_in_s ?? 900),
      used: false,
      revoked: false,
      wrong_attempts: 0,
    });
  }

  instance(id) {
    return this.instances.get(id ?? this.lastInstanceId) ?? null;
  }

  newToken(instanceId) {
    const token = `evit_${b64url(randomBytes(32))}`;
    this.tokens.set(token, { instance_id: instanceId, expires_at: this.now() + 3600, revoked: false });
    return token;
  }

  revokeTokens(instanceId) {
    for (const t of this.tokens.values()) if (t.instance_id === instanceId) t.revoked = true;
  }

  /** Fixed-window counter: answers the seconds to wait when `limit` is exceeded, else 0. */
  hit(key, limit, windowS) {
    const now = this.now();
    const w = this.windows.get(key);
    if (!w || now >= w.start + windowS) {
      this.windows.set(key, { start: now, count: 1 });
      return 0;
    }
    w.count += 1;
    return w.count > limit ? w.start + windowS - now : 0;
  }

  /** Appends an event to an installation's feed and wakes any long-poll waiting on it. */
  emit(instance, type, data, { subject, actor = { kind: 'system', id: 'platform' } } = {}) {
    const event = {
      id: this.ulid('event'),
      type,
      version: 1,
      occurred_at: this.iso(),
      subject: subject ?? { kind: 'instance', id: instance.id },
      org_id: instance.org.id,
      instance_id: instance.id,
      actor,
      data,
    };
    instance.feed.push(event);
    for (const w of this.waiters) w(instance.id);
    return event;
  }
}
