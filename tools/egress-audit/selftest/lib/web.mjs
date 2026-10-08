// The self-test's toy web app for the browser leg: a sign-in page, a few signed-in pages that all
// render the fixture's index.html, and the statistics status route of a product with statistics on.
//
//   GET  /healthz                 200
//   GET  /sign-in                 the sign-in form (email + password)
//   POST /sign-in                 the fixture's account: a session cookie, then the home page
//   GET  /, /about, /settings,
//        /items/<id>              the fixture page (signed in), else back to /sign-in
//   GET  /api/ever-stats/status   200 when EVER_STATS_ENABLED=true (a module route: 404 when off)
//   anything else                 404
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { log } from './fixture.mjs';

/** The fixture account (not a secret: the self-test checks that no artefact holds the password). */
export const ACCOUNT = { email: 'admin@example.test', password: 'selftest-password-0e6a' };

const SIGN_IN = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head>
<body><form method="post" action="/sign-in">
<label>Email <input name="email" type="email"></label>
<label>Password <input name="password" type="password"></label>
<button type="submit">Sign in</button>
</form></body></html>
`;

const PAGES = /^\/(about|settings|items\/[A-Za-z0-9-]+)?$/;

export function serveWeb(pageFile, port = Number(process.env.PORT ?? 8080)) {
  const page = readFileSync(pageFile, 'utf8');
  const sessions = new Set();
  const signedIn = (req) =>
    (req.headers.cookie ?? '')
      .split(';')
      .map((c) => c.trim().split('='))
      .some(([k, v]) => k === 'session' && sessions.has(v));
  const send = (res, status, type, body, headers = {}) => {
    res.writeHead(status, { 'content-type': type, ...headers });
    res.end(body);
  };
  const server = createServer((req, res) => {
    const path = new URL(req.url, 'http://fixture').pathname;
    if (path === '/healthz') return send(res, 200, 'application/json', '{"ok":true}');
    if (path === '/sign-in' && req.method === 'GET') return send(res, 200, 'text/html; charset=utf-8', SIGN_IN);
    if (path === '/sign-in' && req.method === 'POST') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const form = new URLSearchParams(body);
        if (form.get('email') !== ACCOUNT.email || form.get('password') !== ACCOUNT.password)
          return send(res, 401, 'text/html; charset=utf-8', SIGN_IN);
        const id = randomBytes(16).toString('hex');
        sessions.add(id);
        send(res, 303, 'text/plain', '', { location: '/', 'set-cookie': `session=${id}; HttpOnly; Path=/; SameSite=Lax` });
      });
      return;
    }
    if (path === '/api/ever-stats/status' && process.env.EVER_STATS_ENABLED === 'true')
      return send(res, 200, 'application/json', '{"enabled":true,"last_report":null}');
    if (PAGES.test(path)) {
      if (!signedIn(req)) return send(res, 303, 'text/plain', '', { location: '/sign-in' });
      return send(res, 200, 'text/html; charset=utf-8', page.replace('__ROUTE__', path));
    }
    return send(res, 404, 'application/json', '{"error":"not_found"}');
  });
  server.listen(port, '0.0.0.0', () => log(`web fixture listening on ${port}`));
  return server;
}
