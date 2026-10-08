#!/usr/bin/env node
/**
 * ui-routes: writes or checks a product's ui-routes.json (the routes the browser leg opens) from
 * its router.
 *
 *   ever-egress-audit ui-routes --framework angular|next-app|solidstart --entry <path> --out <ui-routes.json>
 *       [--check] [--root <product root>] [--export <name>] [--tsconfig <file>]
 *
 * --entry: Angular, the file that declares the root Routes (name the array with --export when the
 * file has several); Next.js, the app directory (apps/web/app); SolidStart, src/routes.
 * Without --check the list is written (entries with source manual are kept). With --check nothing
 * is written: a router route missing from the committed list, or a router entry of the list the
 * router no longer has, exits 1 and is named.
 *
 * Exit 0 written or in step, 1 out of step, 2 on a usage error.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { angularRoutes } from './angular.mjs';
import { nextAppRoutes, solidStartRoutes } from './file-routes.mjs';

export const FRAMEWORKS = {
  angular: angularRoutes,
  'next-app': nextAppRoutes,
  solidstart: solidStartRoutes,
};

/** The generated list: the router's routes, then the manual entries of the existing list. */
export function generate({ framework, entry, root = process.cwd(), exportName, tsconfig, existing }) {
  const gen = FRAMEWORKS[framework];
  if (!gen) throw new Error(`unknown framework ${framework} (frameworks: ${Object.keys(FRAMEWORKS).join(', ')})`);
  const { routes, notes } = gen({ entry, root, exportName, tsconfig });
  const router = routes.map((r) => ({ ...r, source: 'router' }));
  const have = new Set(router.map((r) => r.path));
  const manual = (existing?.routes ?? []).filter((r) => r.source === 'manual' && !have.has(r.path));
  return {
    framework,
    entry: relative(resolve(root), resolve(entry)).split(sep).join('/'),
    routes: [...router, ...manual].sort((a, b) => a.path.localeCompare(b.path)),
    notes,
  };
}

/** {missing, stale}: router routes the committed list lacks, and router entries the router no longer has. */
export function compare(generated, committed) {
  const listed = new Set((committed?.routes ?? []).map((r) => r.path));
  const routerNow = new Set(generated.routes.filter((r) => r.source === 'router').map((r) => r.path));
  return {
    missing: [...routerNow].filter((p) => !listed.has(p)).sort(),
    stale: (committed?.routes ?? [])
      .filter((r) => r.source !== 'manual' && !routerNow.has(r.path))
      .map((r) => r.path)
      .sort(),
  };
}

export function main(argv) {
  const arg = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const framework = arg('framework');
  const entry = arg('entry');
  const outFile = arg('out');
  if (!framework || !entry || !outFile) {
    process.stderr.write('ui-routes: --framework, --entry and --out are required (see --help)\n');
    return 2;
  }
  const root = resolve(arg('root') ?? '.');
  const out = resolve(outFile);
  let existing = null;
  if (existsSync(out)) {
    try {
      existing = JSON.parse(readFileSync(out, 'utf8'));
    } catch (error) {
      process.stderr.write(`ui-routes: ${outFile} could not be read: ${error.message}\n`);
      return 2;
    }
  }
  let generated;
  try {
    generated = generate({ framework, entry: resolve(root, entry), root, exportName: arg('export'), tsconfig: arg('tsconfig'), existing });
  } catch (error) {
    process.stderr.write(`ui-routes: ${error.message}\n`);
    return 2;
  }
  for (const n of generated.notes) process.stderr.write(`ui-routes: note: ${n}\n`);
  if (argv.includes('--check')) {
    if (!existing) {
      process.stderr.write(`ui-routes: ${outFile} does not exist; generate it without --check\n`);
      return 1;
    }
    const { missing, stale } = compare(generated, existing);
    for (const p of missing) process.stderr.write(`ui-routes: router route missing from ${outFile}: ${p}\n`);
    for (const p of stale) process.stderr.write(`ui-routes: ${outFile} lists ${p}, which the router no longer has\n`);
    if (missing.length || stale.length) {
      process.stderr.write(`ui-routes: ${outFile} is out of step with the router; regenerate it (without --check) and commit it\n`);
      return 1;
    }
    process.stdout.write(`ui-routes: ${outFile} is in step with the router (${generated.routes.length} routes)\n`);
    return 0;
  }
  writeFileSync(out, `${JSON.stringify({ $schema: existing?.$schema, ...generated }, null, 2)}\n`);
  const routerCount = generated.routes.filter((r) => r.source === 'router').length;
  process.stdout.write(
    `ui-routes: wrote ${outFile} (${routerCount} router routes, ${generated.routes.length - routerCount} manual, ${generated.notes.length} notes)\n`,
  );
  return 0;
}

if (process.argv[1] && process.argv[1].endsWith('cli.mjs')) process.exit(main(process.argv.slice(2)));
