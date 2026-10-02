// The provisional statistics fixtures: five goldens and twelve invalid reports with their expected
// outcomes, built from the published allow-list rules until the platform publishes its own set
// (then tools/sync-contract.mjs vendors that set byte for byte and this builder retires).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO } from '../lib/common.mjs';
import { uuid } from './ids.mjs';

const schema = () => JSON.parse(readFileSync(join(REPO, 'contracts/schemas/ever.stats.v1.json'), 'utf8'));

/** Every allow-listed key of a product section, each used once, with deterministic values. */
function fill(section, defs, seed) {
  const out = {};
  let n = seed;
  for (const [key, prop] of Object.entries(section.properties ?? {})) {
    n += 1;
    const ref = prop.$ref?.split('/').pop();
    if (prop.type === 'boolean') out[key] = n % 3 !== 0;
    else if (ref === 'count' || prop.type === 'integer') out[key] = (n * 37) % 997;
    else if (ref === 'currency_map') out[key] = { EUR: 1284500 + n, USD: 950000 + n };
    else if (ref === 'currency_map_signed') out[key] = { EUR: 1102000 + n };
    else if (prop.type === 'object' && prop.properties) out[key] = fill(prop, defs, n * 11);
    else throw new Error(`stats golden: no value rule for ${key}`);
  }
  return out;
}

const envelope = (product, extra = {}) => ({
  schema: 'ever.stats.v1',
  report_id: uuid(`stats/${product}/report`),
  instance_id: uuid(`stats/${product}/instance`),
  sent_at: '2026-11-02',
  module_version: '1.0.0',
  product,
  instance_kind: 'backend',
  serves: [product],
  version: '1.4.2',
  channel: 'stable',
  install_source: 'self-hosted',
  country: 'ZZ',
  period: '2026-11',
  final: false,
  ...extra,
});

/** Fixture 01 of the allow-list rule, without the planted field: the Gauzy golden. */
function gauzy() {
  return {
    schema: 'ever.stats.v1',
    report_id: '9f1c1d4a-7b2e-4f0a-9d3c-2a6b1e5f8c01',
    instance_id: '3d2b1a0c-5e4f-4a6b-8c7d-9e0f1a2b3c4d',
    sent_at: '2026-10-03',
    module_version: '1.0.0',
    product: 'gauzy',
    instance_kind: 'backend',
    serves: ['gauzy', 'teams'],
    version: '0.750.1',
    channel: 'stable',
    install_source: 'self-hosted',
    country: 'ZZ',
    period: '2026-09',
    final: true,
    counts: {
      tenants: 3,
      organizations: 4,
      users: 41,
      users_active_30d: 30,
      employees: 27,
      employees_active: 25,
      teams: 6,
      projects: 18,
      tasks: 912,
      contacts: 57,
      integrations_in_use: { github: 1, ever_connect: 0 },
    },
    features: { time_tracking: true, invoice: true, payment: true, open_stats: false },
    aggregates: {
      invoiced_minor: { EUR: 18230055, USD: 950000 },
      invoices: 214,
      payments_minor: { EUR: 17500000 },
      payments: 190,
      hours_tracked_min: 259140,
    },
  };
}

const json = (v) => `${JSON.stringify(v, null, 2)}\n`;

/** {files: {path: text}, expected} for contracts/fixtures/stats/. */
export function statsFixtures() {
  const s = schema();
  const goldens = {
    gauzy: gauzy(),
    teams: envelope('teams', { instance_kind: 'frontend', serves: ['gauzy', 'teams'], counts: {}, features: {}, aggregates: {} }),
  };
  for (const [i, product] of ['works', 'rec', 'traduora'].entries()) {
    const defs = s.$defs[product];
    goldens[product] = envelope(product, {
      counts: fill(defs.counts, s.$defs, 10 * (i + 1)),
      features: fill(defs.features, s.$defs, 20 * (i + 1)),
      aggregates: fill(defs.aggregates, s.$defs, 30 * (i + 1)),
    });
  }
  const files = {};
  const expected = {};
  for (const [product, doc] of Object.entries(goldens)) {
    files[`valid/${product}.json`] = json(doc);
    expected[`valid/${product}.json`] = { status: 202, layer: 'schema', reason: `the ${product} golden: every key is allow-listed` };
  }

  const g = goldens.gauzy;
  const w = goldens.works;
  const invalid = (name, doc, path, reason, { status = 422, code = 'schema_violation', layer = 'schema', text } = {}) => {
    files[`invalid/${name}.json`] = text ?? json(doc);
    expected[`invalid/${name}.json`] = { status, code, path, layer, reason };
  };
  invalid('01-extra-field', { ...g, tenant_name: 'Acme' }, '/tenant_name', 'unknown key; the top-level object is closed');
  invalid('02-string-in-counts', { ...g, counts: { ...g.counts, users: '41' } }, '/counts/users', 'counts are integers');
  invalid(
    '03-per-record-array',
    { ...g, aggregates: { ...g.aggregates, invoiced_minor: { ...g.aggregates.invoiced_minor, EUR: [1200, 3400] } } },
    '/aggregates/invoiced_minor/EUR',
    'amounts are one integer per currency per period',
  );
  invalid('04-email-in-country', { ...g, country: 'jane@example.com' }, '/country', 'country is two letters or ZZ');
  invalid('05-url-in-version', { ...g, version: 'https://acme.example/1.0' }, '/version', 'version is major.minor.patch');
  invalid(
    '06-decimal-amount',
    { ...g, aggregates: { ...g.aggregates, invoiced_minor: { ...g.aggregates.invoiced_minor, EUR: 182300.55 } } },
    '/aggregates/invoiced_minor/EUR',
    'integers only',
  );
  // 17 KiB of allow-listed keys: the golden, indented far enough to pass the body limit.
  const padded = `${JSON.stringify(g, null, 2)
    .split('\n')
    .map((line) => `${' '.repeat(400)}${line}`)
    .join('\n')}\n`;
  if (Buffer.byteLength(padded) <= 17 * 1024) throw new Error('07-oversize is not over 17 KiB');
  invalid('07-oversize', null, '', 'the body is larger than 16 KiB', { status: 413, code: 'validation_failed', layer: 'ingest', text: padded });
  invalid('08-foreign-product-key', { ...g, counts: { ...g.counts, works: 3 } }, '/counts/works', 'a Works key inside a Gauzy report');
  invalid('09-version-suffix', { ...g, version: '1.2.3-acme-corp-prod' }, '/version', 'a build suffix could name a company');
  invalid(
    '10-open-map-key',
    { ...w, aggregates: { ...w.aggregates, deployments_by_provider: { ...w.aggregates.deployments_by_provider, 'acme-internal': 1 } } },
    '/aggregates/deployments_by_provider/acme-internal',
    'nested map keys come from a closed list',
  );
  // JSON Schema treats 214.0 as an integer; the ingest refuses non-integer number syntax itself.
  const integral = json(g).replace('"invoices": 214,', '"invoices": 214.0,');
  if (!integral.includes('214.0')) throw new Error('11-integral-float was not planted');
  invalid('11-integral-float', null, '/aggregates/invoices', 'a number written with a fraction is not an integer on the wire', { layer: 'ingest', text: integral });
  const duplicate = json(g).replace('"country": "ZZ",', '"country": "ZZ",\n  "country": "BG",');
  if (!duplicate.includes('"country": "BG"')) throw new Error('12-duplicate-key was not planted');
  invalid('12-duplicate-key', null, '/country', 'a key may appear once', { layer: 'ingest', text: duplicate });

  files['expected.json'] = json({
    description:
      'Outcome of every statistics fixture at the ingest: status, problem code and errors[0].path. layer "schema" fixtures fail (or pass) JSON Schema validation alone; layer "ingest" fixtures need the ingest checks beyond the schema (body size, number syntax, duplicate keys). Provisional until the platform publishes its fixture set.',
    fixtures: expected,
  });
  return files;
}
