// ui-routes for file-system routers: the Next.js app router and SolidStart. Each route file becomes
// a route pattern: `(group)` segments are dropped, `[name]` becomes `:name`, `[...name]` `:name+`,
// `[[...name]]` `:name*` and, in SolidStart, `[[name]]` `:name?` and `[...name]` `:name*` (zero or
// more segments there). What a browser cannot open on its own
// (Next parallel `@slot` and intercepting `(.)` routes) is skipped with a note.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

const SKIP_DIRS = new Set(['node_modules', '.next', '.git', 'dist', 'build', '.output', '.vinxi']);

function walk(dir, visit, rel = []) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (!SKIP_DIRS.has(name)) walk(p, visit, [...rel, name]);
    } else visit(rel, name, p);
  }
}

/** One bracketed segment as a pattern segment, or null when it is not dynamic. */
function dynamic(segment, { optional = false, catchAll = '+' } = {}) {
  let m = /^\[\[\.\.\.(\w+)\]\]$/.exec(segment);
  if (m) return `:${m[1]}*`;
  m = /^\[\.\.\.(\w+)\]$/.exec(segment);
  if (m) return `:${m[1]}${catchAll}`;
  if (optional) {
    m = /^\[\[(\w+)\]\]$/.exec(segment);
    if (m) return `:${m[1]}?`;
  }
  m = /^\[(\w+)\]$/.exec(segment);
  return m ? `:${m[1]}` : null;
}

const toPath = (segments) => `/${segments.filter((s) => s !== '').join('/')}`;

/** Next.js app router: every page file under the app directory. {routes: [{path, file}], notes: []}. */
export function nextAppRoutes({ entry, root = process.cwd() } = {}) {
  const appDir = resolve(entry);
  const routes = new Map();
  const notes = new Set();
  const rel = (f) => relative(resolve(root), f).split(sep).join('/');
  walk(appDir, (dirs, name, file) => {
    if (!/^page\.(tsx|ts|jsx|js|mdx)$/.test(name)) return;
    const out = [];
    for (const d of dirs) {
      if (d.startsWith('_')) return; // a private folder: never a route
      if (d.startsWith('@')) {
        notes.add(`${rel(file)}: parallel route slot ${d} is not walked (it renders inside its parent's page)`);
        return;
      }
      if (/^\(\.{1,3}\)/.test(d) || /^\(\.\.\)/.test(d)) {
        notes.add(`${rel(file)}: intercepting route ${d} is not walked (the browser opens the route it intercepts)`);
        return;
      }
      if (/^\(.+\)$/.test(d)) continue; // a route group
      out.push(dynamic(d) ?? d);
    }
    const path = toPath(out);
    if (!routes.has(path)) routes.set(path, { path, file: rel(file) });
  });
  return { routes: [...routes.values()].sort((a, b) => a.path.localeCompare(b.path)), notes: [...notes].sort() };
}

/** SolidStart (file routes under src/routes): files with a default export. {routes: [{path, file}], notes: []}. */
export function solidStartRoutes({ entry, root = process.cwd() } = {}) {
  const routesDir = resolve(entry);
  const routes = new Map();
  const notes = new Set();
  const rel = (f) => relative(resolve(root), f).split(sep).join('/');
  walk(routesDir, (dirs, name, file) => {
    const m = /^(.+)\.(tsx|ts|jsx|js|mdx)$/.exec(name);
    if (!m) return;
    if (!name.endsWith('.mdx')) {
      const text = readFileSync(file, 'utf8');
      if (!/export\s+default\b/.test(text)) {
        if (/export\s+(async\s+)?(function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b/.test(text))
          notes.add(`${rel(file)}: an API route (no default export) is not walked`);
        return;
      }
    }
    const out = [];
    for (const d of dirs) {
      if (/^\(.+\)$/.test(d)) continue;
      out.push(dynamic(d, { optional: true, catchAll: '*' }) ?? d);
    }
    const base = m[1];
    if (base !== 'index' && !/^\(.+\)$/.test(base)) out.push(dynamic(base, { optional: true, catchAll: '*' }) ?? base);
    const path = toPath(out);
    if (!routes.has(path)) routes.set(path, { path, file: rel(file) });
  });
  return { routes: [...routes.values()].sort((a, b) => a.path.localeCompare(b.path)), notes: [...notes].sort() };
}
