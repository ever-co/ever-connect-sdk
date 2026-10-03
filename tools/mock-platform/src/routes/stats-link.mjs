// Row 11: the two-key statistics link. The statement is signed with the statistics key and sent
// under the connect-key token; it must be signed by the key pinned for the statistics id.
import { verifyJws } from '../crypto.mjs';
import { STATS_LINK_TYP } from '../keys.mjs';
import { fail } from '../problem.mjs';

export const statsLinkHandlers = {
  instanceLinkStats({ state, instance, body }) {
    const invalid = (message) =>
      fail(422, 'validation_failed', message, { errors: [{ path: '/statement_sig', code: 'invalid', message }] });
    const decoded = verifyJws(body.statement_sig, body.stats_public_jwk.x, { typ: STATS_LINK_TYP });
    if (!decoded) invalid('the statement does not verify with stats_public_jwk');
    const p = decoded.payload;
    if (p.stats_instance_id !== body.stats_instance_id || p.stats_public_jwk?.x !== body.stats_public_jwk.x)
      invalid('the statement does not match the body');
    // The statement names the installation that sends it: one another installation obtained links nothing.
    if (p.sub !== instance.id) invalid("the statement's sub is not this instance's id");
    if (!Number.isInteger(p.iat) || Math.abs(state.now() - p.iat) > 600) invalid('the statement is older than 10 minutes');
    const pin = state.statsPins.get(body.stats_instance_id);
    if (!pin || pin.x !== body.stats_public_jwk.x)
      fail(409, 'key_mismatch', 'the statement is not signed by the statistics key pinned for this id');
    // One live installation holds a statistics id; a disconnected or revoked holder lets it go.
    for (const other of state.instances.values())
      if (other !== instance && other.stats_instance_id === body.stats_instance_id) {
        if (other.status === 'active' || other.status === 'pending_approval')
          fail(409, 'already_linked', 'another connected installation holds this statistics id');
        other.stats_linked = false;
        other.stats_instance_id = null;
      }
    instance.stats_linked = true;
    instance.stats_instance_id = body.stats_instance_id;
    return { status: 200, body: {} };
  },
};
