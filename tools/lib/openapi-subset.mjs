// Builds the instance-facing subset of the Ever Platform API from the pinned spec (the server's
// truth) and the design contract (for operations the pinned spec does not carry yet).
import { readFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import YAML from 'yaml';
import { sortKeys } from './common.mjs';

export const METHODS = ['get', 'put', 'post', 'delete', 'patch'];

const SCHEMA_MAP_KEYS = ['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas'];
const SCHEMA_ONE_KEYS = [
  'items',
  'additionalProperties',
  'not',
  'propertyNames',
  'contains',
  'if',
  'then',
  'else',
  'unevaluatedProperties',
  'unevaluatedItems',
  'contentSchema',
];
const SCHEMA_LIST_KEYS = ['allOf', 'anyOf', 'oneOf', 'prefixItems'];

const clone = (v) => (v === undefined ? v : JSON.parse(JSON.stringify(v)));
const pascal = (s) => s.replace(/(^|[-_.])([a-z0-9])/g, (_, __, c) => c.toUpperCase());

function pointerGet(doc, pointer) {
  if (!pointer || pointer === '/') return doc;
  return pointer
    .split('/')
    .filter(Boolean)
    .reduce((node, raw) => node?.[raw.replace(/~1/g, '/').replace(/~0/g, '~')], doc);
}

/** Multi-file YAML loader with `$ref` resolution relative to the referring file. */
class DesignFiles {
  constructor() {
    this.cache = new Map();
  }
  load(file) {
    const key = resolve(file);
    if (!this.cache.has(key)) this.cache.set(key, YAML.parse(readFileSync(key, 'utf8')));
    return this.cache.get(key);
  }
  resolve(ref, fromFile) {
    const [filePart, pointer = ''] = ref.split('#');
    const file = filePart ? resolve(dirname(fromFile), filePart) : resolve(fromFile);
    const node = pointerGet(this.load(file), pointer);
    if (node === undefined) throw new Error(`unresolved $ref ${ref} from ${fromFile}`);
    return { node, file, pointer };
  }
  files() {
    return [...this.cache.keys()].sort();
  }
}

/** Every operation of the design contract: {method, path, op, file}. */
function designOperations(files, root) {
  const doc = files.load(root);
  const out = [];
  for (const [path, item0] of Object.entries(doc.paths ?? {})) {
    let item = item0;
    let file = root;
    if (item0?.$ref) ({ node: item, file } = files.resolve(item0.$ref, root));
    for (const method of METHODS) if (item?.[method]) out.push({ method, path, op: item[method], file, item });
  }
  return { doc, operations: out };
}

function pinnedOperations(doc) {
  const out = [];
  for (const [path, item] of Object.entries(doc.paths ?? {}))
    for (const method of METHODS) if (item?.[method]) out.push({ method, path, op: item[method], item });
  return out;
}

const securityNames = (op, doc) => (op.security ?? doc.security ?? []).flatMap((s) => Object.keys(s));

/**
 * Builds the subset. Answers {spec, selected, provisional, collisions, shapeDifferences, designFiles}.
 * `rows` maps operationId -> row number (x-ever-row).
 */
export function buildSubset({ platform, config, rowsByOperation, version, title, description, securityOverrides = {} }) {
  const pinned = JSON.parse(readFileSync(join(platform, config.pinned), 'utf8'));
  const files = new DesignFiles();
  const designRoot = join(platform, config.design);
  const design = designOperations(files, designRoot);
  const aliases = config.design_operation_aliases ?? {};

  const isNever = (path, op, doc) =>
    config.never_path_prefixes.some((p) => path.startsWith(p)) || securityNames(op, doc).some((s) => config.never_security.includes(s));
  const isSelected = (path, op, doc) => {
    if (isNever(path, op, doc)) return false;
    if (config.exclude_operation_ids[op.operationId]) return false;
    const opId = aliases[op.operationId] ?? op.operationId;
    if (config.include_operation_ids.includes(opId)) return true;
    return securityNames(op, doc).some((s) => config.select_security.includes(s));
  };

  // 1. Selection: the pinned spec wins for every (method, path) it defines.
  const selected = new Map(); // `${method} ${path}` -> entry
  for (const entry of pinnedOperations(pinned))
    if (isSelected(entry.path, entry.op, pinned)) selected.set(`${entry.method} ${entry.path}`, { ...entry, source: 'pinned' });
  for (const entry of design.operations) {
    const key = `${entry.method} ${entry.path}`;
    const pinnedHas = Boolean(pinned.paths?.[entry.path]?.[entry.method]);
    if (pinnedHas || !isSelected(entry.path, entry.op, design.doc)) continue;
    selected.set(key, { ...entry, source: 'design' });
  }

  // 2. Component registry. Pinned schema names win; design schemas are added under their own names
  //    (prefixed with their file stem when two design files define different shapes under one name).
  const pinnedSchemas = pinned.components?.schemas ?? {};
  const out = {}; // name -> schema
  const designNames = new Map(); // `${file}#${pointer}` -> name
  const shapeDifferences = new Set();
  const collisions = [];
  const queue = [];

  const addPinned = (name) => {
    if (out[name] !== undefined) return;
    const schema = pinnedSchemas[name];
    if (schema === undefined) throw new Error(`pinned schema ${name} is missing`);
    out[name] = null; // reserve before walking (cycles)
    out[name] = convertPinnedSchema(clone(schema));
  };
  const convertPinnedSchema = (node) => {
    if (Array.isArray(node)) return node.map(convertPinnedSchema);
    if (!node || typeof node !== 'object') return node;
    if (typeof node.$ref === 'string') {
      const m = /^#\/components\/schemas\/(.+)$/.exec(node.$ref);
      if (!m) throw new Error(`unsupported pinned $ref ${node.$ref}`);
      addPinned(m[1]);
    }
    const copy = {};
    for (const [k, v] of Object.entries(node)) copy[k] = typeof v === 'object' ? convertPinnedSchema(v) : v;
    return copy;
  };

  const designSchemaRef = (ref, fromFile) => {
    const { node, file, pointer } = files.resolve(ref, fromFile);
    const segments = pointer.split('/').filter(Boolean);
    if (segments.length !== 1) return { inline: convertDesignSchema(clone(node), file) };
    const name0 = segments[0];
    const key = `${file}#${pointer}`;
    if (designNames.has(key)) return { name: designNames.get(key) };
    // A design schema whose name the pinned contract now uses for another concept keeps its own
    // shape under the name sync.config.json gives it (design_renames), for the design operations.
    const renamed = config.design_renames?.[name0]?.to;
    if (renamed) {
      designNames.set(key, renamed);
      if (!collisions.some((c) => c.name === name0 && c.renamed === renamed))
        collisions.push({ name: name0, renamed, file: basename(file) });
      out[renamed] = null;
      out[renamed] = convertDesignSchema(clone(node), file);
      return { name: renamed };
    }
    if (pinnedSchemas[name0] !== undefined) {
      designNames.set(key, name0);
      addPinned(name0);
      queue.push({ compareWith: name0, node, file });
      return { name: name0 };
    }
    let name = name0;
    const taken = [...designNames.entries()].find(([k, v]) => v === name && k !== key);
    if (taken) {
      name = `${pascal(basename(file, '.yaml'))}${name0}`;
      collisions.push({ name: name0, renamed: name, file: basename(file) });
    }
    designNames.set(key, name);
    out[name] = null;
    out[name] = convertDesignSchema(clone(node), file);
    return { name };
  };

  function convertDesignSchema(node, file) {
    if (Array.isArray(node)) return node.map((n) => convertDesignSchema(n, file));
    if (!node || typeof node !== 'object') return node;
    const copy = {};
    for (const [k, v] of Object.entries(node)) {
      if (k === '$ref') continue;
      if (SCHEMA_MAP_KEYS.includes(k) && v && typeof v === 'object' && !Array.isArray(v)) {
        copy[k] = Object.fromEntries(Object.entries(v).map(([pk, pv]) => [pk, convertDesignSchema(pv, file)]));
      } else if (SCHEMA_ONE_KEYS.includes(k) && v && typeof v === 'object') {
        copy[k] = convertDesignSchema(v, file);
      } else if (SCHEMA_LIST_KEYS.includes(k) && Array.isArray(v)) {
        copy[k] = v.map((s) => convertDesignSchema(s, file));
      } else {
        copy[k] = clone(v);
      }
    }
    if (typeof node.$ref === 'string') {
      const target = designSchemaRef(node.$ref, file);
      if (target.inline) return { ...target.inline, ...copy };
      return { $ref: `#/components/schemas/${target.name}`, ...copy };
    }
    return copy;
  }

  // Parameters, request bodies, responses and headers are inlined into each operation.
  const inlineDesign = (node, file, kind) => {
    let current = node;
    let at = file;
    while (current?.$ref) {
      const r = files.resolve(current.$ref, at);
      current = r.node;
      at = r.file;
    }
    current = clone(current);
    if (kind === 'parameter' || kind === 'header') {
      if (current.schema) current.schema = convertDesignSchema(current.schema, at);
    }
    if (kind === 'requestBody' || kind === 'response') {
      for (const media of Object.values(current.content ?? {})) if (media.schema) media.schema = convertDesignSchema(media.schema, at);
    }
    if (kind === 'response' && current.headers) {
      current.headers = Object.fromEntries(Object.entries(current.headers).map(([h, v]) => [h, inlineDesign(v, at, 'header')]));
    }
    return current;
  };

  const inlinePinned = (node, kind) => {
    let current = node;
    while (current?.$ref) {
      const m = /^#\/components\/(parameters|requestBodies|responses|headers)\/(.+)$/.exec(current.$ref);
      if (!m) throw new Error(`unsupported pinned $ref ${current.$ref}`);
      current = pinned.components[m[1]][m[2]];
    }
    current = clone(current);
    if ((kind === 'parameter' || kind === 'header') && current.schema) current.schema = convertPinnedSchema(current.schema);
    if (kind === 'requestBody' || kind === 'response')
      for (const media of Object.values(current.content ?? {})) if (media.schema) media.schema = convertPinnedSchema(media.schema);
    if (kind === 'response' && current.headers)
      current.headers = Object.fromEntries(Object.entries(current.headers).map(([h, v]) => [h, inlinePinned(v, 'header')]));
    return current;
  };

  // 3. Operations.
  const paths = {};
  const provisional = [];
  const selectedList = [];
  const keep = new Set(config.keep_security);
  for (const key of [...selected.keys()].sort()) {
    const entry = selected.get(key);
    const { method, path, source } = entry;
    const src = entry.op;
    const operationId = aliases[src.operationId] ?? src.operationId;
    const op = {};
    for (const [k, v] of Object.entries(src)) {
      if (['parameters', 'requestBody', 'responses', 'security', 'operationId'].includes(k)) continue;
      if (config.drop_extensions.includes(k)) continue;
      op[k] = clone(v);
    }
    op.operationId = operationId;
    const docForSecurity = source === 'pinned' ? pinned : design.doc;
    const declared = src.security ?? docForSecurity.security ?? [];
    const security = declared.filter((req) => Object.keys(req).length === 0 || Object.keys(req).every((name) => keep.has(name)));
    const override = securityOverrides[operationId];
    if (override) {
      // A credential a product uses that the platform does not accept on this operation yet.
      const wanted = override.security.flatMap((req) => Object.keys(req));
      if (wanted.every((name) => declared.some((req) => name in req)))
        throw new Error(`security override ${operationId}: the contract accepts ${wanted.join(', ')} now; drop the override`);
      op.security = clone(override.security);
    } else if (declared.length > 0 && security.length === 0) {
      // Every scheme dropped would turn a protected operation into a public one.
      throw new Error(
        `operation ${operationId}: none of its security schemes (${declared.flatMap((r) => Object.keys(r)).join(', ')}) is one a product uses; record a security override in pending-upstream.json`,
      );
    } else op.security = security;
    const itemParams = entry.item?.parameters ?? [];
    const params = [...itemParams, ...(src.parameters ?? [])].map((p) =>
      source === 'pinned' ? inlinePinned(p, 'parameter') : inlineDesign(p, entry.file, 'parameter'),
    );
    if (params.length > 0) op.parameters = params;
    if (src.requestBody)
      op.requestBody =
        source === 'pinned' ? inlinePinned(src.requestBody, 'requestBody') : inlineDesign(src.requestBody, entry.file, 'requestBody');
    op.responses = Object.fromEntries(
      Object.entries(src.responses ?? {}).map(([code, r]) => [
        code,
        source === 'pinned' ? inlinePinned(r, 'response') : inlineDesign(r, entry.file, 'response'),
      ]),
    );
    const row = rowsByOperation.get(operationId);
    if (row !== undefined) op['x-ever-row'] = row;
    paths[path] ??= {};
    paths[path][method] = op;
    selectedList.push({ method: method.toUpperCase(), path, operationId, source, security: op.security.flatMap((s) => Object.keys(s)) });
    if (source === 'design') provisional.push(operationId);
  }

  // 4. Shape differences between a design schema and the pinned schema of the same name.
  for (const { compareWith, node, file } of queue) {
    const designShape = JSON.stringify(sortKeys(stripDocs(convertDesignSchemaDetached(node, file))));
    const pinnedShape = JSON.stringify(sortKeys(stripDocs(pinnedSchemas[compareWith])));
    if (designShape !== pinnedShape) shapeDifferences.add(compareWith);
  }
  function convertDesignSchemaDetached(node, file) {
    // Compare names only: replace refs by their component names without registering anything.
    if (Array.isArray(node)) return node.map((n) => convertDesignSchemaDetached(n, file));
    if (!node || typeof node !== 'object') return node;
    if (typeof node.$ref === 'string') {
      const [, pointer = ''] = node.$ref.split('#');
      return { $ref: `#/components/schemas/${pointer.split('/').filter(Boolean).pop()}` };
    }
    return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, convertDesignSchemaDetached(v, file)]));
  }

  // 5. Security schemes actually used.
  const usedSchemes = new Set(selectedList.flatMap((o) => o.security));
  const securitySchemes = {};
  for (const name of [...usedSchemes].sort()) {
    const scheme = pinned.components?.securitySchemes?.[name] ?? design.doc.components?.securitySchemes?.[name];
    if (!scheme) throw new Error(`security scheme ${name} not found`);
    const copy = clone(scheme);
    for (const k of Object.keys(copy)) if (k.startsWith('x-')) delete copy[k];
    securitySchemes[name] = copy;
  }

  const schemas = Object.fromEntries(
    Object.keys(out)
      .sort()
      .map((n) => [n, out[n]]),
  );
  const spec = {
    openapi: '3.1.0',
    info: { title, version, description, contact: clone(pinned.info?.contact ?? { name: 'Ever Co.' }) },
    servers: [{ url: 'https://api.ever.co' }],
    paths: Object.fromEntries(
      Object.keys(paths)
        .sort()
        .map((p) => [p, Object.fromEntries(METHODS.filter((m) => paths[p][m]).map((m) => [m, paths[p][m]]))]),
    ),
    components: { securitySchemes, schemas },
  };
  return {
    spec,
    selected: selectedList,
    provisional: provisional.sort(),
    collisions,
    shapeDifferences: [...shapeDifferences].sort(),
    designFiles: files.files(),
  };
}

function stripDocs(node) {
  if (Array.isArray(node)) return node.map(stripDocs);
  if (!node || typeof node !== 'object') return node;
  const out = {};
  for (const [k, v] of Object.entries(node)) {
    if (['description', 'example', 'examples', 'title', '$comment'].includes(k)) continue;
    out[k] = stripDocs(v);
  }
  return out;
}

/** Deterministic YAML text of the subset. */
export function subsetYaml(spec, header) {
  const body = YAML.stringify(spec, { lineWidth: 0, minContentWidth: 0, aliasDuplicateObjects: false });
  return `${header}${body}`;
}
