// Bundles the mock platform and the egress audit into dist/ with the layout they expect of each
// other (dist/mock-platform next to dist/egress-audit), so the package runs on its own once
// installed. Tests, recorded samples and node_modules stay out.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const PKG = resolve(here, '..');
const TOOLS = resolve(PKG, '..', '..', '..', 'tools');
const DIST = join(PKG, 'dist');

const PARTS = {
  'mock-platform': ['bin', 'src', 'contracts', 'Dockerfile', '.dockerignore', 'package.json', 'mock.config.example.json'],
  'egress-audit': [
    'run.mjs',
    'scenario.mjs',
    'assert.mjs',
    'assert-call-log.mjs',
    'static-hostnames.mjs',
    'cloud-inference.mjs',
    'browser.mjs',
    'hosts.mjs',
    'check-baseline-shrink.mjs',
    'routes',
    'presets',
    'lib',
    'selftest',
    'modes.json',
    'config.schema.json',
    'adapter.schema.json',
    'ever-hosts.json',
    'hosts.schema.json',
    'optin-hosts.schema.json',
    'ui-routes.schema.json',
    'ui-baseline.schema.json',
    'compose.audit.yml',
    'Corefile',
    'package.json',
    'README.md',
  ],
};
const SKIP = new Set(['node_modules', 'test', '.artifacts']);

export function bundle() {
  rmSync(DIST, { recursive: true, force: true });
  const files = [];
  for (const [tool, entries] of Object.entries(PARTS)) {
    for (const entry of entries) {
      const from = join(TOOLS, tool, entry);
      if (!existsSync(from)) throw new Error(`missing ${relative(TOOLS, from)}`);
      const to = join(DIST, tool, entry);
      mkdirSync(dirname(to), { recursive: true });
      cpSync(from, to, { recursive: true, filter: (src) => !SKIP.has(src.split(sep).pop()) });
    }
  }
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else files.push(relative(DIST, p).split(sep).join('/'));
    }
  };
  walk(DIST);
  return files.sort();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const files = bundle();
  process.stdout.write(`connect-tools: ${files.length} files in dist/\n`);
}
