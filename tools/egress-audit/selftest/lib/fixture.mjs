// Shared parts of the self-test's fixture products: a health endpoint that answers 404 for every
// other route (so module routes are off), a logger and the client calls of the Ever Platform API.
import { createServer } from 'node:http';

export const USER_AGENT = 'ever-connect-sdk/0.0.0-selftest (gauzy/1.0.0)';
export const log = (...parts) => process.stdout.write(`${new Date().toISOString()} ${parts.join(' ')}\n`);
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function serve(port = Number(process.env.PORT ?? 8080)) {
  const server = createServer((req, res) => {
    const path = new URL(req.url, 'http://fixture').pathname;
    res.writeHead(path === '/healthz' ? 200 : 404, { 'content-type': 'application/json' });
    res.end(path === '/healthz' ? '{"ok":true}' : '{"error":"not_found"}');
  });
  server.listen(port, '0.0.0.0', () => log(`fixture listening on ${port}`));
  return server;
}

/** A JSON call to the platform API: {status, body}. Network errors throw with their code. */
export async function call(base, method, path, { body, token, headers = {} } = {}) {
  const h = { 'user-agent': USER_AGENT, ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  if (body !== undefined) h['content-type'] = 'application/json';
  const res = await fetch(`${base}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  return { status: res.status, body: parsed };
}
