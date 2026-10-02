#!/usr/bin/env node
// The audit driver. run.mjs builds it into a small image together with the product adapter and runs
// it on the sealed audit network, so it reaches the product and the mock platform by service name
// while its own traffic stays outside every sniffed namespace. One step per container run:
//
//   scenario   wait for the product's health URL, then run the adapter hooks: login,
//              createFixtures, openSettings, and the mode's prepare and trigger hooks
//   managed    once the product reads its feed, request a managed operation on the mock and wait
//              for its result; answers the mark (the call-log length at the request)
//   wait       watch for wait_s seconds; in a mock mode keep watching (up to required_timeout_s)
//              until the required rows were called
//   probe      request every module route and answer the statuses
//   record     answer the mock platform's call record
//
// The plan comes from EVER_AUDIT_PLAN (JSON); the result is one line `EVER_AUDIT_RESULT <json>`.
const plan = JSON.parse(process.env.EVER_AUDIT_PLAN ?? '{}');
const step = process.argv[2] ?? 'scenario';
const MOCK = 'http://mock-platform:8080';
const log = (...a) => process.stderr.write(`${a.join(' ')}\n`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const result = (value) => process.stdout.write(`EVER_AUDIT_RESULT ${JSON.stringify(value)}\n`);

async function waitHealthy(url, seconds) {
  const until = Date.now() + seconds * 1000;
  let last = 'no answer';
  while (Date.now() < until) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (r.status < 500) return { ok: true, status: r.status };
      last = `status ${r.status}`;
    } catch (error) {
      last = error.cause?.code ?? error.message;
    }
    await sleep(1000);
  }
  return { ok: false, reason: last };
}

async function requests() {
  const r = await fetch(`${MOCK}/__mock/requests`, { signal: AbortSignal.timeout(5000) });
  if (r.status !== 200) throw new Error(`the mock platform answered ${r.status} for its record`);
  return r.json();
}

async function scenario() {
  const health = await waitHealthy(plan.health_url, plan.health_timeout_s ?? 120);
  if (!health.ok) return result({ ok: false, fault: `the product never answered ${plan.health_url}: ${health.reason}` });
  let adapter = {};
  try {
    adapter = (await import('./adapter.mjs')).default ?? {};
  } catch (error) {
    if (error.code !== 'ERR_MODULE_NOT_FOUND') return result({ ok: false, fault: `the adapter did not load: ${error.message}` });
  }
  const ctx = { baseUrl: new URL(plan.health_url).origin, mode: plan.mode, env: plan.env ?? {}, fetch, log, headers: {} };
  const steps = [];
  const hooks = ['login', 'createFixtures', 'openSettings'];
  if (plan.prepare) hooks.push(plan.prepare);
  if (plan.trigger && plan.trigger !== 'managed_request') hooks.push(plan.trigger);
  for (const hook of hooks) {
    if (typeof adapter[hook] !== 'function') {
      steps.push({ hook, skipped: true });
      continue;
    }
    try {
      const out = await adapter[hook](ctx);
      if (hook === 'login' && out && typeof out === 'object') ctx.headers = out;
      steps.push({ hook, ok: true });
    } catch (error) {
      return result({ ok: false, fault: `adapter ${hook} failed: ${error.message}`, steps });
    }
  }
  return result({ ok: true, steps });
}

async function managed() {
  const timeoutS = plan.trigger_timeout_s ?? 120;
  const until = Date.now() + timeoutS * 1000;
  let entries = [];
  while (Date.now() < until) {
    entries = await requests();
    if (entries.some((e) => e.row === 7)) break;
    await sleep(1000);
  }
  if (!entries.some((e) => e.row === 7))
    return result({ ok: false, fault: `the product did not read its feed within ${timeoutS} s; no operation was requested` });
  const mark = entries.length;
  const body = plan.managed_request ?? { kind: 'backup', params: {} };
  const r = await fetch(`${MOCK}/__mock/managed/request`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const answer = await r.json().catch(() => null);
  if (r.status !== 201)
    return result({ ok: false, fault: `the mock platform refused the managed request: ${r.status} ${JSON.stringify(answer)}` });
  let state = 'requested';
  while (Date.now() < until) {
    const ops = await (await fetch(`${MOCK}/__mock/managed/operations`)).json();
    state = ops.find((o) => o.operation_id === answer.operation_id)?.state ?? state;
    if (['succeeded', 'failed', 'expired', 'cancelled'].includes(state)) break;
    await sleep(1000);
  }
  return result({ ok: true, mark, operation: { id: answer.operation_id, kind: body.kind, state } });
}

async function wait() {
  await sleep((plan.wait_s ?? 20) * 1000);
  if (!plan.mock) return result({ ok: true });
  const required = plan.required_rows ?? [];
  const afterRequired = plan.after_required_rows ?? [];
  const until = Date.now() + (plan.required_timeout_s ?? 60) * 1000;
  for (;;) {
    const entries = await requests();
    const rows = new Set(entries.map((e) => e.row));
    const after = new Set(entries.slice(plan.mark ?? 0).map((e) => e.row));
    if (required.every((r) => rows.has(r)) && afterRequired.every((r) => after.has(r))) break;
    if (Date.now() >= until) break;
    await sleep(1000);
  }
  await sleep((plan.settle_s ?? 3) * 1000);
  return result({ ok: true });
}

async function probe() {
  const baseUrl = new URL(plan.health_url).origin;
  const routes = [];
  for (const path of plan.module_routes ?? []) {
    try {
      const r = await fetch(`${baseUrl}${path}`, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
      routes.push({ path, status: r.status });
    } catch (error) {
      routes.push({ path, status: 0, error: error.cause?.code ?? error.message });
    }
  }
  return result({ ok: true, routes });
}

async function record() {
  try {
    return result({ ok: true, entries: await requests() });
  } catch (error) {
    return result({ ok: false, fault: `the mock platform record could not be read: ${error.cause?.code ?? error.message}` });
  }
}

const steps = { scenario, managed, wait, probe, record };
if (!steps[step]) {
  result({ ok: false, fault: `unknown driver step ${step}` });
  process.exit(2);
}
try {
  await steps[step]();
} catch (error) {
  result({ ok: false, fault: `driver step ${step} failed: ${error.cause?.code ?? error.message}` });
}
