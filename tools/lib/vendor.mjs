// The files this repository vendors from an ever-co/platform checkout, and how each is produced.
// Every vendored file is byte-identical to its source unless `transform` says otherwise; a
// transform exists only for a provisional source (a draft the platform has not published yet) and
// disappears once the platform publishes the file at `upstream`.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { sha256 } from './common.mjs';

/** Static entries; the event schemas are added from the catalog by `vendoredEntries`. */
const STATIC = [
  {
    path: 'contracts/schemas/ever.stats.v1.json',
    source: 'contracts/stats/ever.stats.v1.schema.json',
    upstream: null,
    transform: null,
  },
  {
    path: 'contracts/schemas/ever.entitlement.v1.json',
    source: 'docs/specs/contracts/ever.entitlement.v1.schema.json',
    upstream: 'contracts/entitlements/ever.entitlement.v1.schema.json',
    transform: 'json-public-description',
  },
  {
    path: 'contracts/schemas/ever.usage.v1.json',
    source: 'contracts/usage/ever.usage.v1.schema.json',
    upstream: null,
    transform: null,
  },
  {
    path: 'contracts/integrations/catalog.v1.json',
    source: 'contracts/integrations/catalog.v1.json',
    upstream: null,
    transform: null,
  },
  {
    path: 'contracts/fixtures/lookup/test-vectors.json',
    source: 'docs/specs/contracts/lookup.md',
    upstream: 'contracts/lookup/test-vectors.json',
    transform: 'lookup-vectors',
  },
  {
    path: 'contracts/schemas/ever.consent.v1.json',
    source: 'contracts/consent/ever.consent.v1.schema.json',
    upstream: null,
    transform: null,
  },
  {
    path: 'contracts/schemas/ever.key-manifest.v1.json',
    source: 'contracts/keys/ever-keys.v1.schema.json',
    upstream: null,
    transform: null,
  },
  {
    // Which operations contract v1 serves (pinned) and which it does not serve yet (not_in_v1).
    path: 'contracts/openapi/v1-scope.json',
    source: 'contracts/openapi/v1-scope.json',
    upstream: null,
    transform: null,
  },
];

const TRANSFORMS = {
  // The draft's description cites the platform's own design document by path; the public copy
  // keeps the sentence without the citation.
  'json-public-description': (text) => {
    const doc = JSON.parse(text);
    if (typeof doc.description === 'string') doc.description = doc.description.replace(/\s*\(contracts\/[^()]*\.md[^()]*\)/g, '');
    return `${JSON.stringify(doc, null, 2)}\n`;
  },
  'lookup-vectors': (text) => {
    const salt = /test salt \(base64url\) = ([A-Za-z0-9_-]{43})/.exec(text)?.[1];
    if (!salt) throw new Error('lookup vectors: the test salt line is missing');
    const section = text.split('### 3.1')[1]?.split('\n## ')[0] ?? '';
    const vectors = [];
    for (const line of section.split('\n')) {
      const cells = line
        .split('|')
        .slice(1, -1)
        .map((c) => c.trim());
      if (cells.length !== 5 || !/^(vat|registration|email)$/.test(cells[0])) continue;
      const unquote = (cell) => {
        const m = /^`(.*)`$/.exec(cell);
        return m ? m[1] : cell;
      };
      // Inputs keep their spaces: the raw cell is read between the backticks of the source line.
      const rawInput = /\|\s*(?:vat|registration|email)\s*\|\s*`([^`]*)`/.exec(line)?.[1] ?? unquote(cells[1]);
      const vector = { kind: cells[0], input: rawInput };
      if (cells[2] !== '') vector.country = unquote(cells[2]);
      vector.normalized = unquote(cells[3]);
      vector.salt_version = 0;
      vector.hash = unquote(cells[4]);
      vectors.push(vector);
    }
    if (vectors.length === 0) throw new Error('lookup vectors: no vector rows found');
    return `${JSON.stringify({ salt_version: 0, salt, normalization_version: 1, vectors }, null, 2)}\n`;
  },
};

/** The event schemas of every instance-audience type in the platform catalog. */
export function eventEntries(platform) {
  const catalogPath = join(platform, 'contracts', 'events', 'catalog.json');
  const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
  const types = catalog.events
    .filter((e) => e.audience.includes('instance'))
    .map((e) => e.type)
    .sort();
  const entries = [
    { path: 'contracts/schemas/events/common.schema.json', source: 'contracts/events/schemas/common.schema.json' },
    { path: 'contracts/schemas/events/envelope.schema.json', source: 'contracts/events/schemas/envelope.schema.json' },
  ];
  for (const event of catalog.events.filter((e) => types.includes(e.type)).sort((a, b) => a.type.localeCompare(b.type))) {
    for (const v of event.versions) {
      const file = v.schema_url.split('/').pop();
      entries.push({ path: `contracts/schemas/events/${file}`, source: `contracts/events/schemas/${file}` });
    }
  }
  return {
    entries: entries.map((e) => ({ ...e, transform: null, upstream: null })),
    catalog: {
      source: 'contracts/events/catalog.json',
      version: catalog.version,
      sha256: sha256(readFileSync(catalogPath)),
      instance_types: types,
    },
  };
}

/** Where the platform publishes its client-assertion vectors, and where this repository keeps them. */
export const CONNECT_VECTORS = { source: 'contracts/connect/vectors', path: 'contracts/fixtures/connect/vectors' };

/** The platform's client-assertion vectors, byte-identical, once it publishes them (else none). */
export function connectVectorEntries(platform) {
  const dir = join(platform, CONNECT_VECTORS.source);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ path: `${CONNECT_VECTORS.path}/${f}`, source: `${CONNECT_VECTORS.source}/${f}`, transform: null, upstream: null }));
}

/** Where the platform publishes its statistics fixtures and expected answers, and where this repository keeps them. */
export const STATS_FIXTURES = { source: 'contracts/fixtures/stats', path: 'contracts/fixtures/stats' };

/** The platform's statistics fixtures (every file, subfolders included), byte-identical, once it publishes them (else none). */
export function statsFixtureEntries(platform) {
  const root = join(platform, STATS_FIXTURES.source);
  if (!existsSync(join(root, 'expected.json'))) return [];
  const files = [];
  const visit = (dir, prefix) => {
    for (const name of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (name.isDirectory()) visit(join(dir, name.name), `${prefix}${name.name}/`);
      else if (name.name.endsWith('.json')) files.push(`${prefix}${name.name}`);
    }
  };
  visit(root, '');
  return files.map((f) => ({
    path: `${STATS_FIXTURES.path}/${f}`,
    source: `${STATS_FIXTURES.source}/${f}`,
    transform: null,
    upstream: null,
  }));
}

/**
 * Where the platform publishes its signed entitlement fixtures (documents, the key manifest and
 * roots that vouch for them, the verification context and the expected outcomes), and where this
 * repository keeps them: beside the SDK's own entitlement fixtures, which tools/fixtures/build-signed.mjs
 * writes to contracts/fixtures/entitlement/.
 */
export const ENTITLEMENT_FIXTURES = { source: 'contracts/fixtures/entitlement', path: 'contracts/fixtures/entitlement-platform' };

/** The platform's entitlement fixtures (every file, subfolders included), byte-identical, once it publishes them (else none). */
export function entitlementFixtureEntries(platform) {
  const root = join(platform, ENTITLEMENT_FIXTURES.source);
  if (!existsSync(join(root, 'expected.json'))) return [];
  const files = [];
  const visit = (dir, prefix) => {
    for (const name of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (name.isDirectory()) visit(join(dir, name.name), `${prefix}${name.name}/`);
      else if (name.name.endsWith('.json') || name.name.endsWith('.jws')) files.push(`${prefix}${name.name}`);
    }
  };
  visit(root, '');
  return files.map((f) => ({
    path: `${ENTITLEMENT_FIXTURES.path}/${f}`,
    source: `${ENTITLEMENT_FIXTURES.source}/${f}`,
    transform: null,
    upstream: null,
  }));
}

/**
 * Produces every vendored file from the checkout. Answers {files: {path: text}, entries: [...]}
 * where each entry records its source, transform, provisional flag and hashes.
 */
export function vendor(platform) {
  const events = eventEntries(platform);
  const files = {};
  const entries = [];
  for (const entry of [
    ...STATIC,
    ...events.entries,
    ...connectVectorEntries(platform),
    ...statsFixtureEntries(platform),
    ...entitlementFixtureEntries(platform),
  ]) {
    const upstreamPath = entry.upstream ? join(platform, entry.upstream) : null;
    const fromUpstream = upstreamPath !== null && existsSync(upstreamPath);
    const source = fromUpstream ? entry.upstream : entry.source;
    const raw = readFileSync(join(platform, source));
    const transform = fromUpstream ? null : entry.transform;
    const text = transform ? TRANSFORMS[transform](raw.toString('utf8')) : raw.toString('utf8');
    files[entry.path] = text;
    entries.push({
      path: entry.path,
      source,
      source_sha256: sha256(raw),
      sha256: sha256(text),
      transform,
      provisional: !fromUpstream && entry.upstream !== null,
      upstream: fromUpstream ? null : entry.upstream,
    });
  }
  return { files, entries, events: events.catalog };
}

export function applyTransform(name, text) {
  return name ? TRANSFORMS[name](text) : text;
}
