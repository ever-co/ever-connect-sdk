// Finds and loads the contract files: from this repository (tools/mock-platform/src -> contracts/)
// or from the packaged copy next to the package (`<package>/contracts`). EVER_MOCK_CONTRACTS_DIR
// overrides both.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

export function contractsDir() {
  const candidates = [
    process.env.EVER_MOCK_CONTRACTS_DIR,
    resolve(here, '..', 'contracts'),
    resolve(here, '..', '..', 'contracts'),
    resolve(here, '..', '..', '..', 'contracts'),
  ].filter(Boolean);
  for (const dir of candidates) if (existsSync(join(dir, 'generated', 'ever-platform.v1.json'))) return dir;
  throw new Error(`contract files not found (looked in ${candidates.join(', ')}); set EVER_MOCK_CONTRACTS_DIR`);
}

let cached = null;

/** Every contract file the mock needs, parsed once. */
export function contract() {
  if (cached) return cached;
  const dir = contractsDir();
  const json = (p) => JSON.parse(readFileSync(join(dir, p), 'utf8'));
  const eventsDir = join(dir, 'schemas', 'events');
  const eventSchemas = {};
  for (const file of readdirSync(eventsDir).sort()) eventSchemas[file] = json(join('schemas', 'events', file));
  const integrations = {};
  const constants = json('constants.json');
  for (const key of constants.integration_keys) integrations[key] = json(join('integrations', `${key}.json`));
  cached = {
    dir,
    spec: json(join('generated', 'ever-platform.v1.json')),
    rows: json(join('generated', 'outbound-calls.json')),
    coverage: json(join('generated', 'row-coverage.json')),
    pending: json(join('openapi', 'pending-upstream.json')),
    constants,
    integrations,
    catalog: json(join('integrations', 'catalog.v1.json')),
    schemas: {
      stats: json(join('schemas', 'ever.stats.v1.json')),
      entitlement: json(join('schemas', 'ever.entitlement.v1.json')),
      consent: json(join('schemas', 'ever.consent.v1.json')),
      keyManifest: json(join('schemas', 'ever.key-manifest.v1.json')),
      usage: json(join('schemas', 'ever.usage.v1.json')),
    },
    eventSchemas,
    lookupVectors: json(join('fixtures', 'lookup', 'test-vectors.json')),
  };
  return cached;
}
