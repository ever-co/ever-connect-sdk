// Row 14: the one Ever ID sign-in client of an installation: requested once (202), then read
// until ready; the secret is answered on the first ready read only.
import { randomBytes } from 'node:crypto';
import { b64url } from '../crypto.mjs';
import { fail } from '../problem.mjs';

/** An exact `https` URI with a host and no credentials, query or fragment: its origin. */
function exactOrigin(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || !u.hostname || u.username || u.password) return null;
  if (raw.includes('?') || raw.includes('#') || u.hostname.includes('*')) return null;
  return u.origin;
}

export const oidcHandlers = {
  instanceRequestOidcClient({ state, instance, body }) {
    const redirect = exactOrigin(body.redirect_uri);
    const logout = exactOrigin(body.logout_uri);
    if (!redirect || !logout || redirect !== logout)
      fail(422, 'redirect_uri_invalid', 'exact https URIs with a host, both on one origin, no query, fragment or credentials');
    if (instance.oidc && ['pending', 'ready'].includes(instance.oidc.status))
      fail(409, 'oidc_client_exists', 'this installation already has its sign-in client (pending or ready)');
    instance.oidc = {
      status: 'pending',
      job_id: state.ulid('job'),
      secret: `ics_${b64url(randomBytes(24))}`,
      secret_shown: false,
      created_at: state.now(),
    };
    return { status: 202, body: { status: 'pending', job_id: instance.oidc.job_id } };
  },

  instanceGetOidcClient({ state, instance, issuer }) {
    const c = instance.oidc;
    if (!c) fail(404, 'not_found', 'no sign-in client was requested');
    if (c.status === 'pending') c.status = 'ready';
    const body = { status: c.status, job_id: c.job_id, created_at: state.iso(c.created_at) };
    if (c.status === 'ready') {
      body.issuer = `${issuer}/idp`;
      body.client_id = `inst-${instance.id}`;
      if (!c.secret_shown) {
        body.client_secret = c.secret;
        c.secret_shown = true;
      }
    }
    return { status: 200, body };
  },
};
