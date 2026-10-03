// The mock platform: an HTTP server (node:http, no framework) that answers every call of the
// instance-facing contract with the platform's statuses and problem codes, from in-memory state.
// Routes come from the contract itself (contracts/generated/ever-platform.v1.json plus the calls
// pending upstream); bodies are validated against the closed contract schemas before a handler
// runs; every product call is recorded without its body.
import { createServer } from 'node:http';
import { adminRoutes } from './admin.mjs';
import { contract } from './contract.mjs';
import { sha256Hex } from './crypto.mjs';
import { isInstanceWide, stateLabel } from './model.mjs';
import { fail, HttpProblem, problemBody } from './problem.mjs';
import { Recorder } from './record.mjs';
import { connectHandlers, keyAccepted } from './routes/connect.mjs';
import { consentHandlers } from './routes/consent.mjs';
import { instanceHandlers } from './routes/instance.mjs';
import { integrationsHandlers } from './routes/integrations.mjs';
import { linkHandlers } from './routes/links.mjs';
import { lookupHandlers } from './routes/lookup.mjs';
import { managedHandlers } from './routes/managed.mjs';
import { mirrorHandlers } from './routes/mirror.mjs';
import { miscHandlers } from './routes/misc.mjs';
import { oidcHandlers } from './routes/oidc.mjs';
import { personHandlers } from './routes/person.mjs';
import { statsHandlers } from './routes/stats.mjs';
import { statsLinkHandlers } from './routes/stats-link.mjs';
import { MockState, makeConfig } from './state.mjs';
import { requestSchemaName, validateComponent, validatePending } from './validate.mjs';

const HANDLERS = {
  ...connectHandlers,
  ...instanceHandlers,
  ...integrationsHandlers,
  ...linkHandlers,
  ...statsHandlers,
  ...statsLinkHandlers,
  ...lookupHandlers,
  ...oidcHandlers,
  ...mirrorHandlers,
  ...personHandlers,
  ...miscHandlers,
  ...consentHandlers,
  ...managedHandlers,
};

const MAX_BODY = { ingestStatsReport: 16 * 1024, instanceMirrorApps: 4 * 1024 * 1024 };
const DEFAULT_MAX_BODY = 1024 * 1024;

function compile(template) {
  const names = [];
  const source = template
    .replace(/[.*+?^${}()|[\]\\]/g, (c) => (c === '{' || c === '}' ? c : `\\${c}`))
    .replace(/\{([^}]+)\}/g, (_, n) => {
      names.push(n);
      return '([^/]+)';
    });
  return { regex: new RegExp(`^${source}$`), names };
}

function routesFromContract() {
  const c = contract();
  const routes = [];
  for (const [template, item] of Object.entries(c.spec.paths)) {
    for (const [method, op] of Object.entries(item)) {
      const security = (op.security ?? []).flatMap((s) => Object.keys(s));
      routes.push({
        method: method.toUpperCase(),
        template,
        ...compile(template),
        operationId: op.operationId,
        row: op['x-ever-row'],
        security,
        integration: op['x-ever-integration'] ?? null,
        idempotent: (op.parameters ?? []).some((p) => p.in === 'header' && p.name === 'Idempotency-Key' && p.required),
        schema: requestSchemaName(op),
        hasBody: Boolean(op.requestBody),
        pending: false,
      });
    }
  }
  for (const p of c.pending.operations) {
    routes.push({
      method: p.method,
      template: p.path,
      ...compile(p.path),
      operationId: p.operation_id,
      row: p.row,
      security: ['instanceToken'],
      integration: p.integration,
      idempotent: false,
      schema: null,
      hasBody: p.request !== null,
      pending: true,
    });
  }
  // Static paths before templated ones, so `/v1/instances/me` never matches `/v1/instances/{x}`.
  routes.sort((a, b) => a.names.length - b.names.length);
  for (const r of routes) if (!HANDLERS[r.operationId]) throw new Error(`no mock handler for ${r.operationId}`);
  return routes;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) tooLarge = true;
      else chunks.push(chunk);
    });
    req.on('end', () => resolve({ raw: Buffer.concat(chunks), tooLarge, size }));
    req.on('error', reject);
  });
}

function bearer(req) {
  const h = req.headers.authorization;
  if (typeof h !== 'string') return null;
  const m = /^Bearer\s+(\S+)$/i.exec(h);
  return m ? m[1] : null;
}

/** Integration state lookup: the link named by the call, else the instance (instance-wide keys). */
export function integrationState(instance, key, linkId) {
  if (isInstanceWide(key)) return instance.integrations[key];
  if (linkId) return instance.integrations[`${key}@${linkId}`];
  const any = Object.entries(instance.integrations).filter(([k]) => k.startsWith(`${key}@`));
  return any.find(([, v]) => v.state === 'enabled')?.[1] ?? any[0]?.[1];
}

const TENANT_LINK_ID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const linkProblem = (code, message) => fail(422, 'validation_failed', message, { errors: [{ path: '#Ever-Link-Id', code, message }] });

/**
 * The integration gate, as the platform's: the tenant link comes from `Ever-Link-Id` (a value that
 * is not a tenant link id is refused for every key), a per-link key needs it, and the key must be
 * enabled for that link (an installation-wide key: for the installation).
 */
function gate(ctx) {
  const key = ctx.route.integration;
  if (!key) return;
  const raw = ctx.headers['ever-link-id'];
  const named = raw === undefined ? null : String(raw).trim();
  if (named !== null && !TENANT_LINK_ID.test(named)) linkProblem('invalid', 'Ever-Link-Id is not a tenant link id');
  let s;
  if (isInstanceWide(key)) s = ctx.instance.integrations[key];
  else {
    if (named === null) linkProblem('required', 'this integration acts for one tenant link: name it in Ever-Link-Id');
    const link = ctx.instance.links[named];
    s = link && link.state === 'active' ? ctx.instance.integrations[`${key}@${named}`] : undefined;
  }
  const label = s ? stateLabel(ctx.instance, key, s) : 'disabled';
  if (label === 'enabled' && s.enabled !== false) return;
  if (label === 'revoked') fail(403, 'integration_revoked');
  if (label === 'denied_by_policy') fail(403, 'denied_by_policy', "the installation's operator denies this integration");
  fail(403, 'integration_disabled', `the ${key} integration is not enabled`);
}

function authInstance(ctx) {
  const token = bearer(ctx.req);
  const t = token ? ctx.state.tokens.get(token) : null;
  if (!t || t.expires_at <= ctx.state.now()) fail(401, 'unauthorized', 'no valid instance token');
  const instance = ctx.state.instances.get(t.instance_id);
  if (t.revoked || !instance || instance.status === 'revoked') fail(401, 'credential_revoked');
  // A token minted with a key the installation no longer accepts (a second rotation dropped it, or
  // its overlap ended) stops while the installation stays connected: mint a new one.
  if (t.kid !== null && !keyAccepted(instance, t.kid, ctx.state.now()))
    fail(401, 'unauthorized', 'the key that minted this token is no longer accepted: mint a new token');
  const limit = ctx.state.faults.revoke_credential_at_call;
  ctx.state.authCalls += 1;
  if (limit !== null && ctx.state.authCalls > limit) {
    instance.status = 'revoked';
    ctx.state.revokeTokens(instance.id);
    fail(401, 'credential_revoked');
  }
  if (instance.status === 'disconnected') fail(403, 'instance_disconnected');
  if (instance.status === 'pending_approval' && ctx.route.operationId !== 'getInstanceSelf') fail(403, 'instance_pending_approval');
  ctx.instance = instance;
  ctx.token = token;
}

export function createMockPlatform(options = {}) {
  const config = makeConfig(options.config ?? {});
  const state = new MockState(config);
  const recorder = new Recorder(options.record ?? null);
  const routes = routesFromContract();
  const admin = adminRoutes;
  const log = options.log ?? (() => {});

  async function handle(req, res) {
    const url = new URL(req.url, 'http://mock');
    const requestId = typeof req.headers['x-request-id'] === 'string' ? req.headers['x-request-id'] : null;
    const send = (status, body, headers = {}) => {
      const h = { 'cache-control': 'private, no-store', ...headers };
      if (body === undefined || status === 204 || status === 304) {
        res.writeHead(status, h);
        res.end();
        return '';
      }
      const isProblem = body && typeof body === 'object' && 'code' in body && 'type' in body && status >= 400;
      const text = JSON.stringify(body);
      res.writeHead(status, { 'content-type': isProblem ? 'application/problem+json' : 'application/json', ...h });
      res.end(text);
      return text;
    };

    // Controls of the mock itself: never recorded as product calls.
    if (url.pathname.startsWith('/__mock/')) {
      const { raw } = await readBody(req, 8 * 1024 * 1024);
      let body = null;
      if (raw.length > 0) {
        try {
          body = JSON.parse(raw.toString('utf8'));
        } catch {
          send(400, problemBody(new HttpProblem(400, 'validation_failed', 'the body is not JSON'), requestId));
          return;
        }
      }
      const handler = admin[`${req.method} ${url.pathname}`];
      if (!handler) {
        send(404, problemBody(new HttpProblem(404, 'not_found'), requestId));
        return;
      }
      try {
        const out = await handler({ state, config, recorder, body, query: url.searchParams, issuer: config.issuer });
        send(out?.status ?? 200, out?.body ?? { ok: true });
      } catch (error) {
        if (error instanceof HttpProblem) send(error.status, problemBody(error, requestId));
        else send(500, { error: String(error.message) });
      }
      return;
    }

    const route = routes.find((r) => r.method === req.method && r.regex.test(url.pathname));
    const pathRoute = route ?? routes.find((r) => r.regex.test(url.pathname));
    const { raw, tooLarge } = await readBody(req, route ? (MAX_BODY[route.operationId] ?? DEFAULT_MAX_BODY) : DEFAULT_MAX_BODY);
    let status = 500;
    let headersOut = {};
    try {
      if (!route) {
        if (pathRoute) fail(405, 'method_not_allowed');
        fail(404, 'not_found');
      }
      const m = route.regex.exec(url.pathname);
      const params = Object.fromEntries(route.names.map((n, i) => [n, decodeURIComponent(m[i + 1])]));
      const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v[0] : v]));
      const ctx = {
        req,
        res,
        state,
        config,
        route,
        params,
        headers,
        query: url.searchParams,
        raw,
        tooLarge,
        requestId,
        issuer: config.issuer,
        body: null,
        instance: null,
      };
      // The statistics handler answers its own size limit, after the media type (the platform's order).
      if (tooLarge && route.operationId !== 'ingestStatsReport') fail(413, 'payload_too_large');
      if (route.security.includes('instanceToken')) authInstance(ctx);
      if (route.hasBody && route.operationId !== 'ingestStatsReport') {
        const type = String(headers['content-type'] ?? '');
        const form = route.operationId === 'instanceToken' && type.startsWith('application/x-www-form-urlencoded');
        if (raw.length === 0 && route.operationId === 'testWebhook') ctx.body = null;
        else if (form) ctx.body = Object.fromEntries(new URLSearchParams(raw.toString('utf8')));
        else {
          try {
            ctx.body = JSON.parse(raw.toString('utf8'));
          } catch {
            fail(422, 'validation_failed', 'the body is not JSON', { errors: [{ path: '', code: 'invalid_shape', message: 'not JSON' }] });
          }
        }
        const v = route.pending
          ? validatePending(route.operationId, ctx.body)
          : route.schema && ctx.body !== null
            ? validateComponent(route.schema, ctx.body)
            : { ok: true };
        ctx.validation = v;
        if (!v.ok && !HANDLERS[route.operationId].ownValidation) fail(422, 'validation_failed', undefined, { errors: v.errors });
      }
      if (route.idempotent) {
        const key = headers['idempotency-key'];
        if (!key)
          fail(422, 'validation_failed', 'the Idempotency-Key header is required', {
            errors: [{ path: '#Idempotency-Key', code: 'required', message: 'required' }],
          });
        const principal = ctx.instance?.id ?? 'public';
        const slot = `${principal}|${route.operationId}|${key}`;
        const seen = state.idempotency.get(slot);
        const bodySha = sha256Hex(raw);
        if (seen) {
          if (seen.bodySha !== bodySha) fail(422, 'idempotency_mismatch');
          status = seen.status;
          headersOut = { ...seen.headers, 'idempotency-replayed': 'true' };
          send(status, seen.body, headersOut);
          return finish(route, status, headers, raw);
        }
        ctx.idempotencySlot = { slot, bodySha };
      }
      if (ctx.instance) gate(ctx);
      const out = (await HANDLERS[route.operationId](ctx)) ?? { status: 204 };
      status = out.status ?? 200;
      headersOut = out.headers ?? {};
      if (ctx.idempotencySlot && status < 500)
        state.idempotency.set(ctx.idempotencySlot.slot, {
          bodySha: ctx.idempotencySlot.bodySha,
          status,
          body: out.body,
          headers: headersOut,
        });
      send(status, out.body, headersOut);
      return finish(route, status, headers, raw);
    } catch (error) {
      if (!(error instanceof HttpProblem)) {
        log(`mock error: ${error.stack ?? error}`);
        error = new HttpProblem(500, 'internal_error', 'the mock failed');
      }
      status = error.status;
      const extraHeaders = error.extra?.retry_after_s !== undefined ? { 'retry-after': String(error.extra.retry_after_s) } : {};
      send(status, problemBody(error, requestId), extraHeaders);
      return finish(route, status, Object.fromEntries(Object.entries(req.headers)), raw);
    }
  }

  function finish(route, status, headers, raw) {
    recorder.add({
      ts: state.iso(),
      method: route?.method ?? 'UNKNOWN',
      pathTemplate: route?.template ?? 'unknown',
      row: route?.row ?? null,
      status,
      userAgent: headers['user-agent'] ?? null,
      idempotencyKey: headers['idempotency-key'] ?? null,
      body: raw,
    });
  }

  const server = createServer((req, res) => {
    handle(req, res).catch((error) => {
      log(`mock failure: ${error.stack ?? error}`);
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });

  return {
    server,
    state,
    config,
    recorder,
    routes,
    listen(port = 0, host = '127.0.0.1') {
      return new Promise((resolve) => {
        server.listen(port, host, () => {
          const address = server.address();
          resolve({ port: address.port, url: `http://${host}:${address.port}` });
        });
      });
    },
    close() {
      return new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      });
    },
  };
}
