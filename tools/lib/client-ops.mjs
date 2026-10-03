// The client's operation table, generated from contracts/openapi/ever-platform.v1.yaml for both
// languages: packages/ts/connect-sdk/src/generated/operations.ts and
// crates/ever-connect-sdk/src/client/generated.rs (+ request-schemas.json). The clients make no
// request outside this table: every method is one line over an entry, and the transport builds
// the URL from `baseUrl` + the entry's path.

const METHODS = ['get', 'put', 'post', 'delete', 'patch'];
const REF = '#/components/schemas/';

function authOf(op) {
  const schemes = (op.security ?? []).flatMap((s) => Object.keys(s));
  if (schemes.includes('instanceToken')) return 'instance';
  if (schemes.some((s) => s.startsWith('everId'))) return 'person';
  return 'none';
}

function headerRule(params, name) {
  const p = params.find((x) => x.in === 'header' && x.name.toLowerCase() === name.toLowerCase());
  if (!p) return 'none';
  return p.required ? 'required' : 'optional';
}

function refsOf(node, out) {
  if (Array.isArray(node)) node.forEach((n) => refsOf(n, out));
  else if (node && typeof node === 'object')
    for (const [k, v] of Object.entries(node)) {
      if (k === '$ref' && typeof v === 'string' && v.startsWith(REF)) out.add(v.slice(REF.length));
      else refsOf(v, out);
    }
  return out;
}

/** The operation entries, in path order. */
export function clientOperations(spec, calls) {
  const statusById = {};
  for (const row of calls.rows) for (const e of row.endpoints) statusById[e.operation_id] = e.status;
  const ops = [];
  for (const [path, item] of Object.entries(spec.paths))
    for (const method of METHODS) {
      const op = item[method];
      if (!op) continue;
      const params = [...(item.parameters ?? []), ...(op.parameters ?? [])];
      const json = op.requestBody?.content?.['application/json'];
      const success = Object.keys(op.responses ?? {})
        .filter((s) => /^(2[0-9]{2}|304)$/.test(s))
        .map(Number);
      ops.push({
        id: op.operationId,
        method: method.toUpperCase(),
        path,
        pathParams: params.filter((p) => p.in === 'path').map((p) => p.name),
        query: params.filter((p) => p.in === 'query').map((p) => p.name),
        auth: authOf(op),
        idempotencyKey: headerRule(params, 'Idempotency-Key'),
        linkHeader: headerRule(params, 'Ever-Link-Id'),
        conditional: headerRule(params, 'If-None-Match') !== 'none',
        body: json ? { schema: json.schema, required: op.requestBody.required === true } : null,
        success,
        row: op['x-ever-row'],
        integration: op['x-ever-integration'] ?? null,
        status: statusById[op.operationId] ?? 'pending_upstream',
      });
    }
  return ops;
}

/** The component schemas the request bodies reach, as one document `{components: {schemas}}`. */
export function requestSchemas(spec, ops) {
  const names = new Set();
  const queue = [
    ...refsOf(
      ops.map((o) => o.body?.schema ?? null),
      new Set(),
    ),
  ];
  while (queue.length > 0) {
    const name = queue.shift();
    if (names.has(name)) continue;
    names.add(name);
    const schema = spec.components.schemas[name];
    if (!schema) throw new Error(`request schema ${name} is not a component`);
    for (const r of refsOf(schema, new Set())) if (!names.has(r)) queue.push(r);
  }
  const schemas = {};
  for (const name of [...names].sort()) schemas[name] = spec.components.schemas[name];
  return { components: { schemas } };
}

const tsLiteral = (v) => JSON.stringify(v, null, 2);

export function operationsTs(ops, schemas, sdkVersion, header) {
  const entries = ops.map((o) => `  ${JSON.stringify(o.id)}: ${tsLiteral(o).replace(/\n/g, '\n  ')},`).join('\n');
  return `${header}// The client's operation table: one entry per operation of contracts/openapi/ever-platform.v1.yaml.

/** The SDK version: the \`User-Agent\` names it (\`ever-connect-sdk/<version> (<product>/<version>)\`). */
export const SDK_VERSION = ${JSON.stringify(sdkVersion)};

/** How an operation authenticates: none, the instance token, or the person's Ever ID token. */
export type OperationAuth = 'none' | 'instance' | 'person';
export type HeaderRule = 'required' | 'optional' | 'none';

export interface OperationSpec {
  readonly id: string;
  readonly method: 'GET' | 'PUT' | 'POST' | 'DELETE' | 'PATCH';
  readonly path: string;
  readonly pathParams: readonly string[];
  readonly query: readonly string[];
  readonly auth: OperationAuth;
  readonly idempotencyKey: HeaderRule;
  readonly linkHeader: HeaderRule;
  readonly conditional: boolean;
  readonly body: { readonly schema: unknown; readonly required: boolean } | null;
  readonly success: readonly number[];
  readonly row: number;
  readonly integration: string | null;
  readonly status: 'pinned' | 'provisional' | 'pending_upstream';
}

export const OPERATIONS = {
${entries}
} as const satisfies { readonly [id: string]: OperationSpec };

export type OperationId = keyof typeof OPERATIONS;

/** The component schemas request bodies are checked against before sending. */
export const REQUEST_SCHEMAS: { readonly [key: string]: unknown } = ${tsLiteral(schemas)};
`;
}

const rsStr = (s) => JSON.stringify(s);
const rsList = (xs) => `&[${xs.map(rsStr).join(', ')}]`;
const rsRule = (r) => ({ required: 'HeaderRule::Required', optional: 'HeaderRule::Optional', none: 'HeaderRule::None' })[r];
const rsAuth = (a) => ({ none: 'OperationAuth::None', instance: 'OperationAuth::Instance', person: 'OperationAuth::Person' })[a];

export function operationsRs(ops, header) {
  const entries = ops
    .map(
      (o) => `    Operation {
        id: ${rsStr(o.id)},
        method: ${rsStr(o.method)},
        path: ${rsStr(o.path)},
        path_params: ${rsList(o.pathParams)},
        query: ${rsList(o.query)},
        auth: ${rsAuth(o.auth)},
        idempotency_key: ${rsRule(o.idempotencyKey)},
        link_header: ${rsRule(o.linkHeader)},
        conditional: ${o.conditional},
        body_schema: ${o.body ? `Some(${rsStr(JSON.stringify(o.body.schema))})` : 'None'},
        body_required: ${o.body ? o.body.required : false},
        success: &[${o.success.join(', ')}],
        row: ${o.row},
        integration: ${o.integration ? `Some(${rsStr(o.integration)})` : 'None'},
        status: ${rsStr(o.status)},
    },`,
    )
    .join('\n');
  return `${header}//! The client's operation table: one entry per operation of
//! \`contracts/openapi/ever-platform.v1.yaml\`.

/// How an operation authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationAuth {
    /// No credential (the key manifest, the legal texts, the redeem, the token itself, statistics).
    None,
    /// The instance token.
    Instance,
    /// The person's Ever ID token, passed by the caller.
    Person,
}

/// Whether a header is required, optional or not part of the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderRule {
    /// The client refuses the call without it.
    Required,
    /// Sent when given.
    Optional,
    /// Never sent.
    None,
}

/// One operation.
#[derive(Debug, Clone, Copy)]
pub struct Operation {
    /// The \`operationId\`.
    pub id: &'static str,
    /// The HTTP method.
    pub method: &'static str,
    /// The path template (\`{name}\` placeholders).
    pub path: &'static str,
    /// The path parameters, in order.
    pub path_params: &'static [&'static str],
    /// The query parameters it accepts.
    pub query: &'static [&'static str],
    /// How it authenticates.
    pub auth: OperationAuth,
    /// The \`Idempotency-Key\` rule.
    pub idempotency_key: HeaderRule,
    /// The \`Ever-Link-Id\` rule.
    pub link_header: HeaderRule,
    /// Whether it takes \`If-None-Match\`.
    pub conditional: bool,
    /// The JSON Schema of the body (against [\`REQUEST_SCHEMAS\`]), when it takes one.
    pub body_schema: Option<&'static str>,
    /// Whether the body is required.
    pub body_required: bool,
    /// The statuses that are an answer, not a problem.
    pub success: &'static [u16],
    /// The outbound-call row.
    pub row: u16,
    /// The integration that gates it.
    pub integration: Option<&'static str>,
    /// \`pinned\`, \`provisional\` or \`pending_upstream\`.
    pub status: &'static str,
}

/// Every operation.
pub const OPERATIONS: &[Operation] = &[
${entries}
];

/// The component schemas request bodies are checked against before sending.
pub const REQUEST_SCHEMAS: &str = include_str!("request-schemas.json");
`;
}
