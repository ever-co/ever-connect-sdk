#!/usr/bin/env node
/**
 * static-hostnames: no Ever host and no Ever Platform base URL appears outside the directories
 * that may name them (the module packages, docs, the audit and tests), so no other code can call
 * Ever Platform behind the modules' back.
 *
 *   ever-egress-audit static-hostnames [--root <dir>] --allow-dirs <dir>,<dir>,**\/*.test.*
 *
 * Exit 0 when clean, 1 with file:line findings.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

export const HOST_PATTERNS = [/\bever\.co\b/, /\bapi\.ever\.co\b/, /\bapp\.ever\.co\b/, /\bEVER_PLATFORM_API_URL\b/];
const TEXT = /\.(m?[jt]sx?|cjs|json|ya?ml|html|vue|svelte|rs|go|py|php|env|example|sample|conf|toml)$|(^|\/)(Dockerfile|\.env[^/]*)$/;
const SKIP = new Set(['node_modules', '.git', 'dist', 'build', 'target', 'coverage', '.next', '.turbo', 'vendor']);

/** A minimal glob: `dir/` or `dir` prefixes, and `**\/*.test.*` style suffix patterns. */
export function allowed(file, patterns) {
  return patterns.some((p) => {
    if (p.includes('*')) {
      const quote = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
      const source = p
        .split('**/')
        .map((part) => part.split('*').map(quote).join('[^/]*'))
        .join('(?:.*/)?');
      return new RegExp(`^${source}$`).test(file);
    }
    const dir = p.replace(/\/$/, '');
    return file === dir || file.startsWith(`${dir}/`);
  });
}

function files(root) {
  try {
    return execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .split('\0')
      .filter(Boolean);
  } catch {
    const out = [];
    const walk = (dir) => {
      for (const name of readdirSync(dir)) {
        if (SKIP.has(name)) continue;
        const p = join(dir, name);
        if (statSync(p).isDirectory()) walk(p);
        else out.push(relative(root, p).split(sep).join('/'));
      }
    };
    walk(root);
    return out;
  }
}

export function scanHostnames(root, allowDirs) {
  const findings = [];
  for (const file of files(root)) {
    if (!TEXT.test(file) || allowed(file, allowDirs)) continue;
    let text;
    try {
      text = readFileSync(join(root, file), 'utf8');
    } catch {
      continue;
    }
    text.split('\n').forEach((line, i) => {
      if (HOST_PATTERNS.some((p) => p.test(line))) findings.push(`${file}:${i + 1}`);
    });
  }
  return findings;
}

export function main(argv) {
  const arg = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const root = resolve(arg('root') ?? '.');
  const allow = (arg('allow-dirs') ?? '').split(',').filter(Boolean);
  const findings = scanHostnames(root, allow);
  if (findings.length > 0) {
    process.stderr.write(
      `static-hostnames: an Ever host or the Ever Platform base URL outside the allowed directories:\n  ${findings.join('\n  ')}\n`,
    );
    return 1;
  }
  process.stdout.write('static-hostnames: ok\n');
  return 0;
}

if (process.argv[1] && process.argv[1].endsWith('static-hostnames.mjs')) process.exit(main(process.argv.slice(2)));
