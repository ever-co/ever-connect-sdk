#!/usr/bin/env node
/**
 * check-schema-drift: every vendored file still equals its source in ever-co/platform.
 *
 *   node tools/check-schema-drift.mjs            committed files match contracts/VENDOR.json; with
 *                                                EVER_PLATFORM_REPO, also the platform checkout
 *   node tools/check-schema-drift.mjs --strict   additionally refuses provisional sources and
 *                                                authored files whose platform version exists
 *
 * Without EVER_PLATFORM_REPO the platform comparison is skipped with a warning (a local run
 * without a checkout); CI always sets it. A difference names the file and both sha256 values.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, platformRepo, readJson, sha256 } from './lib/common.mjs';
import { applyTransform } from './lib/vendor.mjs';

export const AUTHORED_UPSTREAM = {
  'contracts/schemas/ever.consent.v1.json': 'contracts/consent/ever.consent.v1.schema.json',
  'contracts/schemas/ever.key-manifest.v1.json': 'contracts/keys/ever-keys.v1.schema.json',
  'contracts/fixtures/connect/vectors/': 'contracts/connect/vectors',
  'contracts/fixtures/stats/': 'contracts/fixtures/stats',
};

export function checkDrift({ platform, strict }) {
  const vendorDoc = readJson(join(REPO, 'contracts/VENDOR.json'));
  const errors = [];
  const warnings = [];

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
        if (strict) errors.push(msg);
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
    if (strict && entry.provisional) errors.push(`${entry.path}: provisional source ${entry.source} (the platform has not published ${entry.upstream} yet)`);
  }

  if (platform) {
    const pinned = join(platform, vendorDoc.openapi.pinned.source);
    const pinnedSha = sha256(readFileSync(pinned));
    if (pinnedSha !== vendorDoc.openapi.pinned.sha256)
      errors.push(`${vendorDoc.openapi.pinned.source}: platform ${pinnedSha}, synced ${vendorDoc.openapi.pinned.sha256}: run tools/sync-contract.mjs`);
    const catalog = join(platform, vendorDoc.events.source);
    const catalogSha = sha256(readFileSync(catalog));
    if (catalogSha !== vendorDoc.events.sha256)
      errors.push(`${vendorDoc.events.source}: platform ${catalogSha}, synced ${vendorDoc.events.sha256}: run tools/sync-contract.mjs`);
    for (const [path, upstream] of Object.entries(AUTHORED_UPSTREAM)) {
      if (!existsSync(join(platform, upstream))) continue;
      const msg = `${path} is authored here but the platform now publishes ${upstream}: vendor it instead`;
      if (strict) errors.push(msg);
      else warnings.push(msg);
    }
  }
  if (strict && vendorDoc.openapi.provisional_operations.length > 0)
    errors.push(`contract: ${vendorDoc.openapi.provisional_operations.length} operation(s) still come from the design, not the pinned spec`);
  if (strict && vendorDoc.openapi.pending_upstream_rows.length > 0)
    errors.push(`contract: rows ${vendorDoc.openapi.pending_upstream_rows.join(', ')} are still pending upstream`);
  return { errors, warnings };
}

function main() {
  const strict = process.argv.includes('--strict');
  const platform = platformRepo({ required: false });
  if (!platform) process.stdout.write('check-schema-drift: warning: EVER_PLATFORM_REPO is unset; comparing committed files with VENDOR.json only\n');
  const { errors, warnings } = checkDrift({ platform, strict });
  for (const w of warnings) process.stdout.write(`check-schema-drift: warning: ${w}\n`);
  if (errors.length > 0) {
    process.stderr.write(`check-schema-drift: ${errors.length} problem(s):\n  ${errors.join('\n  ')}\n`);
    process.exit(1);
  }
  process.stdout.write(`check-schema-drift: ok${strict ? ' (strict)' : ''}${platform ? '' : ' (local only)'}\n`);
}

if (process.argv[1] && process.argv[1].endsWith('check-schema-drift.mjs')) main();
