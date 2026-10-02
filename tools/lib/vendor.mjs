// The files this repository vendors from an ever-co/platform checkout, and how each is produced.
// Every vendored file is byte-identical to its source unless `transform` says otherwise; a
// transform exists only for a provisional source (a draft the platform has not published yet) and
// disappears once the platform publishes the file at `upstream`.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import YAML from 'yaml';
import { sha256 } from './common.mjs';

export const CATALOG_PINS = {
  description:
    'Phase 2 statuses the platform catalog export applies to the seed before publishing it: lookup, discoverability and profile import ship as coming soon.',
  status: {
    counterparty_lookup: 'coming_soon',
    counterparty_discoverable: 'coming_soon',
    profile_import: 'coming_soon',
  },
};

/** Static entries; the event schemas are added from the catalog by `vendoredEntries`. */
const STATIC = [
  {
    path: 'contracts/schemas/ever.stats.v1.json',
    source: 'docs/specs/contracts/stats.v1.schema.json',
    upstream: 'contracts/stats/ever.stats.v1.schema.json',
    transform: 'json-drop-comment',
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
    source: 'docs/specs/seeds/integrations-catalog.yaml',
    upstream: 'contracts/integrations/catalog.v1.json',
    transform: 'catalog-yaml',
  },
  {
    path: 'contracts/fixtures/lookup/test-vectors.json',
    source: 'docs/specs/contracts/lookup.md',
    upstream: 'contracts/lookup/test-vectors.json',
    transform: 'lookup-vectors',
  },
];

const TRANSFORMS = {
  'json-drop-comment': (text) => {
    const doc = JSON.parse(text);
    delete doc.$comment;
    return `${JSON.stringify(doc, null, 2)}\n`;
  },
  // The draft's description cites the platform's own design document by path; the public copy
  // keeps the sentence without the citation.
  'json-public-description': (text) => {
    const doc = JSON.parse(text);
    if (typeof doc.description === 'string') doc.description = doc.description.replace(/\s*\(contracts\/[^()]*\.md[^()]*\)/g, '');
    return `${JSON.stringify(doc, null, 2)}\n`;
  },
  'catalog-yaml': (text) => {
    const doc = YAML.parse(text);
    for (const row of doc.integrations ?? []) {
      const pinned = CATALOG_PINS.status[row.key];
      if (pinned) row.status = pinned;
    }
    // A `hidden` row is a reserved key whose phase has not started. The platform's public catalog
    // view and its export list none, so neither does this copy: no row and none of its scope groups.
    doc.integrations = (doc.integrations ?? []).filter((row) => row.status !== 'hidden');
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
      if (cells[2] !== '') vector.country = cells[2];
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

/**
 * Produces every vendored file from the checkout. Answers {files: {path: text}, entries: [...]}
 * where each entry records its source, transform, provisional flag and hashes.
 */
export function vendor(platform) {
  const events = eventEntries(platform);
  const files = {};
  const entries = [];
  for (const entry of [...STATIC, ...events.entries, ...connectVectorEntries(platform)]) {
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
