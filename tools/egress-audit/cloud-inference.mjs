#!/usr/bin/env node
/**
 * cloud-inference: the Ever Platform modules never guess where they run. The install source comes
 * from EVER_INSTALL_SOURCE only; reading a payment secret, a demo flag, a cloud-provider variable,
 * a deployment path, a desktop flag or a host name inside a module fails.
 *
 *   ever-egress-audit cloud-inference --dirs <module dir>,<module dir>
 *
 * Exit 0 when clean, 1 with file:line and the rule.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

export const RULES = [
  { id: 'payment-secret', re: /\bSTRIPE_SECRET_KEY\b/ },
  { id: 'demo-flag', re: /\bprocess\.env(\.|\[['"])DEMO\b|\bNEXT_PUBLIC_DEMO\b/ },
  { id: 'cloud-provider', re: /\bCLOUD_PROVIDER\b/ },
  { id: 'deployment-path', re: /\/srv\/gauzy\b/ },
  { id: 'desktop-flag', re: /\bIS_ELECTRON\b/ },
  { id: 'host-name', re: /\bos\.hostname\s*\(|\bhostname\(\)|\blocation\.hostname\b/ },
];
const SOURCE = /\.(m?[jt]sx?|cjs)$/;
const SKIP = new Set(['node_modules', 'dist', 'build', 'coverage', '.turbo']);

export function scanInference(dirs, root = '.') {
  const findings = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (SKIP.has(name)) continue;
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (SOURCE.test(name) && !/\.(test|spec)\.[cm]?[jt]sx?$/.test(name)) {
        readFileSync(p, 'utf8')
          .split('\n')
          .forEach((line, i) => {
            for (const r of RULES) if (r.re.test(line)) findings.push(`${relative(root, p).split(sep).join('/')}:${i + 1}: ${r.id}`);
          });
      }
    }
  };
  for (const d of dirs) walk(resolve(root, d));
  return findings;
}

export function main(argv) {
  const i = argv.indexOf('--dirs');
  const dirs = (i >= 0 ? argv[i + 1] : '').split(',').filter(Boolean);
  if (dirs.length === 0) {
    process.stderr.write('cloud-inference: --dirs <module dir>[,<module dir>] is required\n');
    return 2;
  }
  const findings = scanInference(dirs);
  if (findings.length > 0) {
    process.stderr.write(`cloud-inference: a module infers where it runs:\n  ${findings.join('\n  ')}\n`);
    return 1;
  }
  process.stdout.write('cloud-inference: ok\n');
  return 0;
}

if (process.argv[1] && process.argv[1].endsWith('cloud-inference.mjs')) process.exit(main(process.argv.slice(2)));
