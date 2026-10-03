#!/usr/bin/env node
/**
 * check-schema-drift: every vendored file still equals its source in ever-co/platform.
 *
 *   node tools/check-schema-drift.mjs            committed files match contracts/VENDOR.json; with
 *                                                EVER_PLATFORM_REPO, also the platform checkout
 *   node tools/check-schema-drift.mjs --strict   additionally refuses provisional sources and
 *                                                authored files whose platform version exists
 *   node tools/check-schema-drift.mjs --strict=stats
 *                                                the strict rules for one contract only (see
 *                                                STRICT_SCOPES): the statistics schema, its fixtures
 *                                                and its calls are published, vendored byte for
 *                                                byte, and nothing of them is authored here
 *
 * Without EVER_PLATFORM_REPO the platform comparison is skipped with a warning (a local run
 * without a checkout); CI always sets it. A difference names the file and both sha256 values.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { platformRepo, REPO, readJson, sha256 } from './lib/common.mjs';
import { applyTransform } from './lib/vendor.mjs';

export const AUTHORED_UPSTREAM = {
  'contracts/schemas/ever.consent.v1.json': 'contracts/consent/ever.consent.v1.schema.json',
  'contracts/schemas/ever.key-manifest.v1.json': 'contracts/keys/ever-keys.v1.schema.json',
  'contracts/fixtures/connect/vectors/': 'contracts/connect/vectors',
  'contracts/fixtures/stats/': 'contracts/fixtures/stats',
};

/**
 * The schemas the platform pins for this repository (`contracts/SCHEMAS.sha256`, `sha256  path`
 * lines): each one is vendored byte for byte, at the pinned checksum.
 */
export function checkPins(text, files) {
  const errors = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([0-9a-f]{64}) [ *](\S+)$/);
    if (!m) continue;
    const [, sha, source] = m;
    const entry = files.find((f) => f.source === source);
    if (!entry) errors.push(`${source}: pinned by the platform (contracts/SCHEMAS.sha256) but not vendored: run tools/sync-contract.mjs`);
    else if (entry.transform !== null || entry.sha256 !== sha)
      errors.push(
        `${entry.path}: vendored ${entry.sha256}${entry.transform ? ` (transform ${entry.transform})` : ''}, the platform pins ${source} at ${sha}`,
      );
  }
  return errors;
}

/**
 * The contracts `--strict=<scope>` can hold to the strict rules on their own, while other sources
 * are still provisional: the vendored files of the scope, the folder it vendors whole (no file may
 * be added or left behind), the operations that must come from the pinned API description, and,
 * with a platform checkout, the platform's own pin of the schema (contracts/SCHEMAS.sha256).
 */
export const STRICT_SCOPES = {
  stats: {
    files: (path) => path === 'contracts/schemas/ever.stats.v1.json' || path.startsWith('contracts/fixtures/stats/'),
    folder: 'contracts/fixtures/stats',
    operations: ['ingestStatsReport', 'instanceLinkStats'],
    schema: 'contracts/schemas/ever.stats.v1.json',
  },
};

/** Every file under a folder of this repository, as repository paths. */
function filesUnder(folder) {
  const root = join(REPO, folder);
  if (!existsSync(root)) return [];
  const out = [];
  const visit = (dir, prefix) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) visit(join(dir, e.name), `${prefix}${e.name}/`);
      else out.push(`${prefix}${e.name}`);
    }
  };
  visit(root, `${folder}/`);
  return out.sort();
}

/** The `sha256  path` lines of a pin file, as a map from path to checksum. */
export function pinLines(text) {
  const out = new Map();
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([0-9a-f]{64}) [ *](\S+)$/);
    if (m) out.set(m[2], m[1]);
  }
  return out;
}

/** The strict rules of one scope (STRICT_SCOPES): problems, as messages. */
export function checkScope(name, vendorDoc, { platform = null, present = null } = {}) {
  const scope = STRICT_SCOPES[name];
  if (!scope) return [`--strict=${name}: no such scope (${Object.keys(STRICT_SCOPES).join(', ')})`];
  const errors = [];
  const entries = vendorDoc.files.filter((e) => scope.files(e.path));
  if (!entries.some((e) => e.path === scope.schema)) errors.push(`${scope.schema}: not vendored`);
  for (const e of entries) {
    if (e.provisional) errors.push(`${e.path}: provisional source ${e.source} (the platform has not published ${e.upstream} yet)`);
    if (e.transform !== null) errors.push(`${e.path}: vendored through the transform ${e.transform}, not byte for byte`);
  }
  const listed = new Set(entries.map((e) => e.path));
  const files = present ?? filesUnder(scope.folder);
  if (!files.some((p) => listed.has(p))) errors.push(`${scope.folder}/: not vendored from the platform`);
  else for (const p of files) if (!listed.has(p)) errors.push(`${p}: not in VENDOR.json (a file the platform does not publish)`);
  for (const { path } of vendorDoc.authored ?? [])
    if (scope.files(path) || path === `${scope.folder}/`) errors.push(`${path}: still authored here`);
  for (const id of scope.operations)
    if (vendorDoc.openapi.provisional_operations.includes(id))
      errors.push(`contract: ${id} still comes from the design, not the pinned spec`);
  const schema = entries.find((e) => e.path === scope.schema);
  if (platform && schema) {
    const file = join(platform, 'contracts/SCHEMAS.sha256');
    const pinned = existsSync(file) ? pinLines(readFileSync(file, 'utf8')).get(schema.source) : undefined;
    if (pinned !== schema.sha256)
      errors.push(`${scope.schema}: the platform pins ${schema.source} at ${pinned ?? 'nothing'}, vendored ${schema.sha256}`);
  }
  return errors;
}

export function checkDrift({ platform, strict, scope = null, vendorDoc = readJson(join(REPO, 'contracts/VENDOR.json')) }) {
  const errors = [];
  const warnings = [];
  // A scoped run holds one contract to the strict rules; the rest is checked as without --strict.
  const strictAll = strict && scope === null;
  const inScope = (path) => strictAll || Boolean(scope && STRICT_SCOPES[scope]?.files(path));

  for (const entry of vendorDoc.files) {
    const local = join(REPO, entry.path);
    if (!existsSync(local)) {
      errors.push(`${entry.path}: missing (VENDOR.json lists it)`);
      continue;
    }
    const localSha = sha256(readFileSync(local));
    if (localSha !== entry.sha256) errors.push(`${entry.path}: committed ${localSha} != recorded ${entry.sha256} (edited by hand?)`);
    if (platform) {
      const upstream = entry.upstream ? join(platform, entry.upstream) : null;
      if (upstream && existsSync(upstream)) {
        const upstreamSha = sha256(readFileSync(upstream));
        const msg = `${entry.path}: the platform now publishes ${entry.upstream} (sha256 ${upstreamSha}); vendored ${localSha}: run tools/sync-contract.mjs`;
        if (inScope(entry.path)) errors.push(msg);
        else warnings.push(msg);
      }
      const source = join(platform, entry.source);
      if (!existsSync(source)) {
        errors.push(`${entry.path}: source ${entry.source} is missing in the platform checkout`);
        continue;
      }
      const raw = readFileSync(source);
      const produced = applyTransform(entry.transform, raw.toString('utf8'));
      const producedSha = sha256(produced);
      if (producedSha !== localSha) errors.push(`${entry.path}: platform ${entry.source} gives ${producedSha}, vendored ${localSha}`);
    }
    if (strictAll && entry.provisional)
      errors.push(`${entry.path}: provisional source ${entry.source} (the platform has not published ${entry.upstream} yet)`);
  }

  if (platform) {
    const pinned = join(platform, vendorDoc.openapi.pinned.source);
    const pinnedSha = sha256(readFileSync(pinned));
    if (pinnedSha !== vendorDoc.openapi.pinned.sha256)
      errors.push(
        `${vendorDoc.openapi.pinned.source}: platform ${pinnedSha}, synced ${vendorDoc.openapi.pinned.sha256}: run tools/sync-contract.mjs`,
      );
    const pins = join(platform, 'contracts/SCHEMAS.sha256');
    if (existsSync(pins)) errors.push(...checkPins(readFileSync(pins, 'utf8'), vendorDoc.files));
    const catalog = join(platform, vendorDoc.events.source);
    const catalogSha = sha256(readFileSync(catalog));
    if (catalogSha !== vendorDoc.events.sha256)
      errors.push(`${vendorDoc.events.source}: platform ${catalogSha}, synced ${vendorDoc.events.sha256}: run tools/sync-contract.mjs`);
    // Only what is still authored here (VENDOR.json `authored`) can be overtaken by a publication.
    for (const { path } of vendorDoc.authored ?? []) {
      const upstream = AUTHORED_UPSTREAM[path];
      if (!upstream || !existsSync(join(platform, upstream))) continue;
      const msg = `${path} is authored here but the platform now publishes ${upstream}: vendor it instead`;
      if (inScope(path)) errors.push(msg);
      else warnings.push(msg);
    }
  }
  if (scope) errors.push(...checkScope(scope, vendorDoc, { platform }));
  if (strictAll && vendorDoc.openapi.provisional_operations.length > 0)
    errors.push(
      `contract: ${vendorDoc.openapi.provisional_operations.length} operation(s) still come from the design, not the pinned spec`,
    );
  if (strictAll && (vendorDoc.openapi.security_overrides ?? []).length > 0)
    errors.push(`contract: the security of ${vendorDoc.openapi.security_overrides.join(', ')} is still pending upstream`);
  if (strictAll && vendorDoc.openapi.pending_upstream_rows.length > 0)
    errors.push(`contract: rows ${vendorDoc.openapi.pending_upstream_rows.join(', ')} are still pending upstream`);
  return { errors, warnings };
}

function main() {
  const scoped = process.argv.find((a) => a.startsWith('--strict='));
  const scope = scoped ? scoped.slice('--strict='.length) : null;
  const strict = scope !== null || process.argv.includes('--strict');
  const platform = platformRepo({ required: false });
  if (!platform)
    process.stdout.write('check-schema-drift: warning: EVER_PLATFORM_REPO is unset; comparing committed files with VENDOR.json only\n');
  const { errors, warnings } = checkDrift({ platform, strict, scope });
  for (const w of warnings) process.stdout.write(`check-schema-drift: warning: ${w}\n`);
  if (errors.length > 0) {
    process.stderr.write(`check-schema-drift: ${errors.length} problem(s):\n  ${errors.join('\n  ')}\n`);
    process.exit(1);
  }
  process.stdout.write(
    `check-schema-drift: ok${scope ? ` (strict: ${scope})` : strict ? ' (strict)' : ''}${platform ? '' : ' (local only)'}\n`,
  );
}

if (process.argv[1]?.endsWith('check-schema-drift.mjs')) main();
