// Row 14: the one Ever ID sign-in client of an installation: requested once (202), then read
// until ready; the secret is answered on the first ready read only.
import { randomBytes } from 'node:crypto';
import { b64url } from '../crypto.mjs';
import { fail } from '../problem.mjs';

export const oidcHandlers = {
  instanceRequestOidcClient({ state, instance }) {
    if (instance.oidc && instance.oidc.status !== 'revoked')
      fail(409, 'already_exists', 'this installation already has its sign-in client');
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
