// ui-routes for an Angular router: a walk of the TypeScript syntax (no type check, no build) from an
// entry file's Routes array, following children, spreads of route arrays, functions that return
// them, loadChildren (a Routes export, or an NgModule's RouterModule.forChild and ROUTES providers,
// through the modules it imports) and loadComponent, across relative imports and the tsconfig
// `paths` of the product. Guards and redirects are kept as metadata. What only exists at run time
// (a service that adds routes, a matcher function) cannot be followed: it is listed in `notes`, so
// the product adds those routes by hand (source manual).
//
// TypeScript is the product's own (resolved from the entry file), or the harness's.
import { existsSync, readFileSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative, resolve, sep } from 'node:path';

const EXTENSIONS = ['.ts', '.tsx', '.mts', '/index.ts', '/index.tsx'];
const MAX_DEPTH = 60;

export function loadTypeScript(from) {
  for (const base of [from, import.meta.url]) {
    try {
      const require = createRequire(base.startsWith('file:') ? base : resolve(base));
      return require('typescript');
    } catch {
      // try the next place
    }
  }
  throw new Error('the Angular route generator needs the typescript package (install it in the product, or next to the harness)');
}

/** The tsconfig `paths` that apply to a file: the nearest tsconfig with paths, its `extends` chain followed. */
export function tsconfigPaths(ts, startDir, explicit) {
  const read = (file, seen = new Set()) => {
    if (seen.has(file) || !existsSync(file)) return null;
    seen.add(file);
    const { config } = ts.readConfigFile(file, ts.sys.readFile);
    if (!config) return null;
    let inherited = null;
    for (const ext of [config.extends].flat().filter(Boolean)) {
      if (!ext.startsWith('.')) continue;
      const target = resolve(dirname(file), ext.endsWith('.json') ? ext : `${ext}.json`);
      inherited = read(target, seen) ?? inherited;
    }
    const own = config.compilerOptions?.paths;
    if (own) return { paths: own, baseDir: resolve(dirname(file), config.compilerOptions?.baseUrl ?? '.') };
    return inherited;
  };
  if (explicit) return read(resolve(explicit)) ?? { paths: {}, baseDir: dirname(resolve(explicit)) };
  let dir = resolve(startDir);
  for (;;) {
    for (const name of ['tsconfig.json', 'tsconfig.base.json', 'tsconfig.app.json']) {
      const found = read(join(dir, name));
      if (found) return found;
    }
    const up = dirname(dir);
    if (up === dir) return { paths: {}, baseDir: startDir };
    dir = up;
  }
}

function fileFor(base) {
  if (existsSync(base) && statSync(base).isFile()) return base;
  for (const ext of EXTENSIONS) if (existsSync(base + ext) && statSync(base + ext).isFile()) return base + ext;
  return null;
}

/** Resolves a module specifier from a file: relative, or through the tsconfig paths. null for a package. */
export function makeResolver(config) {
  const entries = Object.entries(config.paths ?? {});
  return (specifier, fromFile) => {
    if (specifier.startsWith('.')) return fileFor(resolve(dirname(fromFile), specifier));
    for (const [pattern, targets] of entries) {
      const star = pattern.indexOf('*');
      let rest = null;
      if (star < 0) {
        if (pattern === specifier) rest = '';
      } else if (specifier.startsWith(pattern.slice(0, star)) && specifier.endsWith(pattern.slice(star + 1)))
        rest = specifier.slice(star, specifier.length - (pattern.length - star - 1));
      if (rest === null) continue;
      for (const t of targets) {
        const f = fileFor(resolve(config.baseDir, t.split('*').join(rest)));
        if (f) return f;
      }
    }
    return null;
  };
}

/** Routes of an Angular router: {routes: [{path, file, redirect_to?, guards?}], notes: []}. */
export function angularRoutes({ entry, exportName, root = process.cwd(), tsconfig } = {}) {
  const entryFile = resolve(entry);
  const ts = loadTypeScript(entryFile);
  const resolveModule = makeResolver(tsconfigPaths(ts, dirname(entryFile), tsconfig));
  const sources = new Map();
  const notes = new Set();
  const out = new Map();
  const rel = (f) => relative(resolve(root), f).split(sep).join('/');
  const where = (node) => {
    const sf = node.getSourceFile();
    return `${rel(sf.fileName)}:${sf.getLineAndCharacterOfPosition(node.getStart()).line + 1}`;
  };
  const note = (node, text) => notes.add(`${where(node)}: ${text}`);
  const short = (node) => node.getText().replace(/\s+/g, ' ').slice(0, 100);

  const source = (file) => {
    if (!sources.has(file)) {
      const text = readFileSync(file, 'utf8');
      sources.set(
        file,
        ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS),
      );
    }
    return sources.get(file);
  };
  const unwrap = (e) => {
    while (
      e &&
      (ts.isParenthesizedExpression(e) ||
        ts.isAsExpression(e) ||
        ts.isTypeAssertionExpression?.(e) ||
        ts.isSatisfiesExpression?.(e) ||
        ts.isNonNullExpression(e))
    )
      e = e.expression;
    return e;
  };
  const declName = (d) => (d.name && ts.isIdentifier(d.name) ? d.name.text : null);

  /** A declaration named `name` among statements (variables, functions, classes). */
  function inStatements(statements, name) {
    for (const s of statements) {
      if (ts.isVariableStatement(s)) for (const d of s.declarationList.declarations) if (declName(d) === name) return d;
      if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s)) && s.name?.text === name) return s;
    }
    return null;
  }

  /** The declaration an export name of a file stands for, through re-exports. */
  function findExport(file, name, seen = new Set()) {
    const key = `${file}#${name}`;
    if (seen.has(key)) return null;
    seen.add(key);
    const sf = source(file);
    for (const s of sf.statements) {
      const exported = s.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
      if (name === 'default') {
        if (ts.isExportAssignment(s)) return { node: s.expression, file };
        if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s)) && s.modifiers?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword))
          return { node: s, file };
      }
      if (exported) {
        if (ts.isVariableStatement(s)) for (const d of s.declarationList.declarations) if (declName(d) === name) return { node: d, file };
        if ((ts.isFunctionDeclaration(s) || ts.isClassDeclaration(s)) && s.name?.text === name) return { node: s, file };
      }
      if (ts.isExportDeclaration(s)) {
        const from = s.moduleSpecifier && ts.isStringLiteral(s.moduleSpecifier) ? resolveModule(s.moduleSpecifier.text, file) : null;
        if (!s.exportClause) {
          if (from) {
            const found = findExport(from, name, seen);
            if (found) return found;
          }
        } else if (ts.isNamedExports(s.exportClause)) {
          for (const el of s.exportClause.elements) {
            if (el.name.text !== name) continue;
            const original = el.propertyName?.text ?? el.name.text;
            if (from) return findExport(from, original, seen);
            return resolveName(sf, original, s, seen);
          }
        }
      }
    }
    return null;
  }

  /** What an identifier stands for at a place: an enclosing scope's declaration, a top-level one, or an import. */
  function resolveName(sf, name, at, seen = new Set()) {
    for (let p = at?.parent; p; p = p.parent) {
      if (ts.isBlock(p) || ts.isSourceFile(p) || ts.isModuleBlock(p)) {
        const d = inStatements(p.statements, name);
        if (d) return { node: d, file: sf.fileName };
      }
    }
    for (const s of sf.statements) {
      if (!ts.isImportDeclaration(s) || !s.importClause || !ts.isStringLiteral(s.moduleSpecifier)) continue;
      const from = resolveModule(s.moduleSpecifier.text, sf.fileName);
      const clause = s.importClause;
      if (clause.name?.text === name) return from ? findExport(from, 'default', seen) : { external: s.moduleSpecifier.text };
      const bindings = clause.namedBindings;
      if (bindings && ts.isNamedImports(bindings))
        for (const el of bindings.elements)
          if (el.name.text === name)
            return from ? findExport(from, el.propertyName?.text ?? name, seen) : { external: s.moduleSpecifier.text };
    }
    return null;
  }

  function stringOf(expr, file, depth = 0) {
    const e = unwrap(expr);
    if (!e || depth > MAX_DEPTH) return null;
    if (ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e)) return e.text;
    if (ts.isTemplateExpression(e)) {
      let s = e.head.text;
      for (const span of e.templateSpans) {
        const v = stringOf(span.expression, file, depth + 1);
        if (v === null) return null;
        s += v + span.literal.text;
      }
      return s;
    }
    if (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const a = stringOf(e.left, file, depth + 1);
      const b = stringOf(e.right, file, depth + 1);
      return a === null || b === null ? null : a + b;
    }
    if (ts.isIdentifier(e)) {
      const d = resolveName(e.getSourceFile(), e.text, e);
      if (d?.node && ts.isVariableDeclaration(d.node) && d.node.initializer) return stringOf(d.node.initializer, d.file, depth + 1);
    }
    return null;
  }

  /** The functions' return expressions (an arrow's expression body included). */
  function returns(fn) {
    if (!fn.body) return [];
    if (!ts.isBlock(fn.body)) return [fn.body];
    const found = [];
    const walk = (n) => {
      if (n !== fn.body && (ts.isFunctionLike(n) || ts.isClassLike(n))) return;
      if (ts.isReturnStatement(n) && n.expression) found.push(n.expression);
      ts.forEachChild(n, walk);
    };
    walk(fn.body);
    return found;
  }

  const functionOf = (d) => {
    if (!d?.node) return null;
    if (ts.isFunctionDeclaration(d.node)) return d.node;
    if (ts.isVariableDeclaration(d.node) && d.node.initializer) {
      const init = unwrap(d.node.initializer);
      if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return init;
    }
    return null;
  };

  /** The route objects an expression evaluates to. */
  function routeObjects(expr, depth = 0) {
    const e = unwrap(expr);
    if (!e) return [];
    if (depth > MAX_DEPTH) {
      note(e, 'route list nested too deeply; not followed');
      return [];
    }
    if (ts.isArrayLiteralExpression(e))
      return e.elements.flatMap((el) => routeObjects(ts.isSpreadElement(el) ? el.expression : el, depth + 1));
    if (ts.isObjectLiteralExpression(e)) return [e];
    if (ts.isConditionalExpression(e)) return [...routeObjects(e.whenTrue, depth + 1), ...routeObjects(e.whenFalse, depth + 1)];
    if (ts.isIdentifier(e)) {
      const d = resolveName(e.getSourceFile(), e.text, e);
      if (d?.node && ts.isVariableDeclaration(d.node) && d.node.initializer) return routeObjects(d.node.initializer, depth + 1);
      if (d?.node && ts.isExpression?.(d.node)) return routeObjects(d.node, depth + 1);
      if (!d?.external) note(e, `routes from ${e.text} could not be followed`);
      return [];
    }
    if (ts.isCallExpression(e)) {
      const callee = unwrap(e.expression);
      // [...].concat(...), routes.filter(...): the routes they start from.
      if (ts.isPropertyAccessExpression(callee) && ['concat', 'filter', 'slice'].includes(callee.name.text))
        return [
          ...routeObjects(callee.expression, depth + 1),
          ...(callee.name.text === 'concat' ? e.arguments.flatMap((a) => routeObjects(a, depth + 1)) : []),
        ];
      if (ts.isIdentifier(callee)) {
        const fn = functionOf(resolveName(callee.getSourceFile(), callee.text, callee));
        if (fn) return returns(fn).flatMap((r) => routeObjects(r, depth + 1));
      }
      note(e, `routes built at run time (${short(e)}): add the routes it adds as manual entries`);
      return [];
    }
    note(e, `route list not followed (${short(e)})`);
    return [];
  }

  const prop = (obj, name) =>
    obj.properties.find(
      (p) =>
        (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p) || ts.isMethodDeclaration(p)) &&
        p.name &&
        (p.name.text ?? p.name.getText()) === name,
    );
  const initOf = (p) => (!p ? null : ts.isPropertyAssignment(p) ? p.initializer : ts.isShorthandPropertyAssignment(p) ? p.name : p);

  /** The routes an NgModule declares: RouterModule.forChild/forRoot, ROUTES providers, and its imported modules'. */
  function moduleRoutes(cls, seen, depth) {
    const key = `${cls.getSourceFile().fileName}#${cls.name?.text}`;
    if (seen.has(key) || depth > MAX_DEPTH) return [];
    seen.add(key);
    const decorator = (ts.getDecorators?.(cls) ?? cls.decorators ?? []).find((d) => {
      const c = d.expression;
      return ts.isCallExpression(c) && ts.isIdentifier(c.expression) && c.expression.text === 'NgModule';
    });
    if (!decorator) return null;
    const meta = unwrap(decorator.expression.arguments[0]);
    if (!meta || !ts.isObjectLiteralExpression(meta)) return [];
    const found = [];
    const imports = unwrap(initOf(prop(meta, 'imports')));
    for (const el of imports && ts.isArrayLiteralExpression(imports) ? imports.elements : []) {
      const x = unwrap(el);
      if (
        ts.isCallExpression(x) &&
        ts.isPropertyAccessExpression(x.expression) &&
        ['forChild', 'forRoot'].includes(x.expression.name.text)
      ) {
        if (x.arguments[0]) found.push(...routeObjects(x.arguments[0], depth + 1));
      } else if (ts.isIdentifier(x)) {
        const d = resolveName(x.getSourceFile(), x.text, x);
        if (d?.node && ts.isClassDeclaration(d.node)) found.push(...(moduleRoutes(d.node, seen, depth + 1) ?? []));
      }
    }
    const providers = unwrap(initOf(prop(meta, 'providers')));
    for (const el of providers && ts.isArrayLiteralExpression(providers) ? providers.elements : []) {
      const x = unwrap(el);
      if (ts.isCallExpression(x) && ts.isIdentifier(x.expression) && x.expression.text === 'provideRoutes' && x.arguments[0]) {
        found.push(...routeObjects(x.arguments[0], depth + 1));
        continue;
      }
      if (!ts.isObjectLiteralExpression(x)) continue;
      const provide = unwrap(initOf(prop(x, 'provide')));
      if (!provide || !ts.isIdentifier(provide) || provide.text !== 'ROUTES') continue;
      const useValue = initOf(prop(x, 'useValue'));
      const useFactory = unwrap(initOf(prop(x, 'useFactory')));
      if (useValue) found.push(...routeObjects(useValue, depth + 1));
      else if (useFactory && (ts.isArrowFunction(useFactory) || ts.isFunctionExpression(useFactory)))
        for (const r of returns(useFactory)) found.push(...routeObjects(r, depth + 1));
      else if (useFactory && ts.isIdentifier(useFactory)) {
        const fn = functionOf(resolveName(useFactory.getSourceFile(), useFactory.text, useFactory));
        if (fn) for (const r of returns(fn)) found.push(...routeObjects(r, depth + 1));
        else note(useFactory, `ROUTES factory ${useFactory.text} could not be followed`);
      }
    }
    return found;
  }

  /** The child routes of a loadChildren expression. */
  function lazyChildren(expr, seen, depth) {
    let e = unwrap(expr);
    if (ts.isArrowFunction(e) || ts.isFunctionExpression(e)) {
      const r = returns(e);
      if (r.length !== 1) {
        note(e, 'loadChildren with no single return; not followed');
        return [];
      }
      e = unwrap(r[0]);
    }
    // import('x').then((m) => m.Name) | import('x') | Promise.resolve(routes)
    let spec = null;
    let name = 'default';
    if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression) && e.expression.name.text === 'then') {
      const inner = unwrap(e.expression.expression);
      if (ts.isCallExpression(inner) && inner.expression.kind === ts.SyntaxKind.ImportKeyword) spec = inner.arguments[0];
      const cb = unwrap(e.arguments[0]);
      const body = cb && (ts.isArrowFunction(cb) || ts.isFunctionExpression(cb)) ? unwrap(returns(cb)[0]) : null;
      if (body && ts.isPropertyAccessExpression(body)) name = body.name.text;
      else if (body && ts.isElementAccessExpression(body) && ts.isStringLiteral(body.argumentExpression))
        name = body.argumentExpression.text;
    } else if (ts.isCallExpression(e) && e.expression.kind === ts.SyntaxKind.ImportKeyword) spec = e.arguments[0];
    else if (
      ts.isCallExpression(e) &&
      ts.isPropertyAccessExpression(e.expression) &&
      e.expression.name.text === 'resolve' &&
      e.arguments[0]
    )
      return routeObjects(e.arguments[0], depth + 1);
    else return routeObjects(e, depth + 1);
    if (!spec || !ts.isStringLiteralLike(spec)) {
      note(e, 'loadChildren with a computed module name; not followed');
      return [];
    }
    const file = resolveModule(spec.text, e.getSourceFile().fileName);
    if (!file) {
      note(e, `loadChildren module ${spec.text} could not be resolved (tsconfig paths?)`);
      return [];
    }
    const target = findExport(file, name);
    if (!target) {
      note(e, `${name} is not exported by ${rel(file)}`);
      return [];
    }
    if (ts.isClassDeclaration(target.node)) {
      const r = moduleRoutes(target.node, seen, depth + 1);
      if (r === null) note(e, `${name} in ${rel(file)} is not an NgModule`);
      return r ?? [];
    }
    if (ts.isVariableDeclaration(target.node) && target.node.initializer) return routeObjects(target.node.initializer, depth + 1);
    const fn = functionOf(target);
    if (fn) return returns(fn).flatMap((x) => routeObjects(x, depth + 1));
    return routeObjects(target.node, depth + 1);
  }

  const join2 = (a, b) => `/${[a, b].join('/').split('/').filter(Boolean).join('/')}`;

  function addRoute(path, obj, extra) {
    const p = path === '' ? '/' : path;
    if (out.has(p)) return;
    out.set(p, { path: p, file: where(obj), ...extra });
  }

  function walkRoutes(objects, parent, seen, depth) {
    for (const obj of objects) {
      if (depth > MAX_DEPTH) return;
      const pathProp = prop(obj, 'path');
      const matcher = prop(obj, 'matcher');
      const segment = pathProp ? stringOf(initOf(pathProp), obj.getSourceFile().fileName) : '';
      if (matcher) {
        note(obj, `a route matcher (${short(initOf(matcher))}) under ${parent || '/'}: add its routes as manual entries`);
        continue;
      }
      if (segment === null) {
        note(obj, `a path that is not a constant (${short(initOf(pathProp))}) under ${parent || '/'}; not followed`);
        continue;
      }
      if (segment === '**') {
        note(obj, `the wildcard route under ${parent || '/'} is not walked`);
        continue;
      }
      const full = join2(parent, segment);
      const redirect = prop(obj, 'redirectTo');
      const guards = ['canActivate', 'canMatch', 'canLoad', 'canActivateChild']
        .flatMap((g) => {
          const v = unwrap(initOf(prop(obj, g)));
          return v && ts.isArrayLiteralExpression(v) ? v.elements.map((x) => short(x)) : [];
        })
        .filter(Boolean);
      const meta = guards.length ? { guards } : {};
      if (redirect) {
        const to = stringOf(initOf(redirect), obj.getSourceFile().fileName);
        addRoute(full, obj, { redirect_to: to ?? '(computed)', ...meta });
        continue;
      }
      const children = [];
      const c = prop(obj, 'children');
      if (c) children.push(...routeObjects(initOf(c), depth + 1));
      // The NgModules already loaded on THIS route's chain of parents: a module that loads itself
      // (directly or through others) stops there, while the same module reached through another
      // parent is walked again under that parent (one module, two places in the tree).
      const chain = new Set(seen);
      const lazy = prop(obj, 'loadChildren');
      if (lazy) children.push(...lazyChildren(initOf(lazy), chain, depth + 1));
      // A route with children is reached through them (its own path through a '' child); a route
      // whose children could not be followed is still opened at its own path.
      if (children.length === 0) addRoute(full, obj, meta);
      else walkRoutes(children, full, chain, depth + 1);
    }
  }

  const sf = source(entryFile);
  let roots = [];
  if (exportName) {
    const d = findExport(entryFile, exportName) ?? resolveName(sf, exportName, sf.statements[0]);
    if (!d?.node) throw new Error(`${exportName} is not declared in ${rel(entryFile)}`);
    roots = ts.isClassDeclaration(d.node) ? (moduleRoutes(d.node, new Set(), 0) ?? []) : routeObjects(d.node.initializer ?? d.node);
  } else {
    for (const s of sf.statements)
      if (ts.isVariableStatement(s))
        for (const d of s.declarationList.declarations)
          if (d.type && /\bRoutes\b|\bRoute\s*\[\]/.test(d.type.getText()) && d.initializer) roots.push(...routeObjects(d.initializer));
    if (roots.length === 0) {
      const visit = (n) => {
        if (ts.isCallExpression(n)) {
          const c = n.expression;
          const name = ts.isPropertyAccessExpression(c) ? c.name.text : ts.isIdentifier(c) ? c.text : '';
          if (['forRoot', 'provideRouter'].includes(name) && n.arguments[0]) roots.push(...routeObjects(n.arguments[0]));
        }
        ts.forEachChild(n, visit);
      };
      visit(sf);
    }
    if (roots.length === 0)
      throw new Error(`no Routes array, RouterModule.forRoot or provideRouter in ${rel(entryFile)} (name one with --export)`);
  }
  walkRoutes(roots, '', new Set(), 0);
  return { routes: [...out.values()].sort((a, b) => a.path.localeCompare(b.path)), notes: [...notes].sort() };
}
