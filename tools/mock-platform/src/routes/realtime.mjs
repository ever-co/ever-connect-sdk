// Row 35: the live event stream (Server-Sent Events, GET /rt/sse). The mock's stream is finite: it
// answers sys.hello, the events of the installation's own instance topic after Last-Event-ID (the
// event feed's ids are the cursors), and sys.closed {reauthenticate}, so a product's reconnect path
// runs on every read. Public topics are accepted with or without a credential (any credential
// reaches them) and carry no events here. The faults realtime_disabled, realtime_busy and
// too_many_streams answer the platform's 503 and 429.
import { fail } from '../problem.mjs';

const MAX_TOPICS = 20;
const MAX_ANONYMOUS_TOPICS = 4;
const MAX_TOPICS_LENGTH = 1024;
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const SLUG = /^[A-Za-z0-9._-]{1,64}$/;

const invalid = (code, message) => fail(422, 'topic_invalid', message, { errors: [{ path: '?topics', code, message }] });

/** One topic of the grammar: {kind, id}, or null. `tenant/<id>` and `internal` parse but are never served. */
function parseTopic(raw) {
  if (raw === 'system') return { kind: 'system', id: null };
  if (raw === 'internal') return { kind: 'internal', id: null };
  const slash = raw.indexOf('/');
  if (slash < 0) return null;
  const kind = raw.slice(0, slash);
  const id = raw.slice(slash + 1);
  if ((kind === 'profile' || kind === 'listing') && SLUG.test(id)) return { kind, id };
  if (['org', 'person', 'instance', 'tenant'].includes(kind) && ULID.test(id)) return { kind, id };
  return null;
}

/** The requested topics, trimmed and de-duplicated in the caller's order, as the platform reads them. */
function topics(raw, max) {
  if (raw.length > MAX_TOPICS_LENGTH) invalid('too_long', `the topic list is longer than ${MAX_TOPICS_LENGTH} characters`);
  const out = [];
  for (const t of raw.split(',').map((s) => s.trim())) {
    if (t === '' || out.some((o) => o.name === t)) continue;
    const parsed = parseTopic(t);
    if (!parsed) invalid('invalid', 'a topic is not system, org/<id>, person/<id>, instance/<id>, profile/<handle> or listing/<id>');
    out.push({ name: t, ...parsed });
  }
  if (out.length === 0) invalid('required', 'name at least one topic');
  if (out.length > max) invalid('out_of_range', `at most ${max} topics`);
  return out;
}

// No id line without a cursor: an empty `id:` would reset the client's last event id.
const frame = (event, id, data) => `${id === null || id === '' ? '' : `id: ${id}\n`}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;

export const realtimeHandlers = {
  realtimeStream({ state, instance, otherCredential, query, headers }) {
    if (state.faults.realtime_disabled) fail(503, 'realtime_disabled', 'the stream is off on this deployment');
    const credential = Boolean(instance) || otherCredential;
    const requested = topics(query.get('topics') ?? '', credential ? MAX_TOPICS : MAX_ANONYMOUS_TOPICS);
    const isPublic = (t) => t.kind === 'system' || t.kind === 'profile' || t.kind === 'listing';
    if (!credential && requested.some((t) => !isPublic(t))) fail(401, 'unauthorized', 'a private topic needs a credential');
    // The whole request is refused when one topic is out of the credential's reach (never a partial grant).
    if (requested.some((t) => !isPublic(t) && !(t.kind === 'instance' && t.id === instance?.id)))
      fail(403, 'topic_forbidden', 'a topic is out of reach of this credential');
    if (state.faults.too_many_streams)
      fail(429, 'too_many_streams', 'this caller holds as many open streams as it may', { retry_after_s: 30 });
    if (state.faults.realtime_busy) fail(503, 'realtime_busy', 'this replica holds as many streams as it may', { retry_after_s: 5 });

    const own = instance ? requested.find((t) => t.kind === 'instance') : undefined;
    const feed = own ? instance.feed : [];
    const resumeFrom = headers['last-event-id'] ?? null;
    let start = feed.length;
    let resync = null;
    if (resumeFrom !== null) {
      const i = feed.findIndex((e) => e.id === resumeFrom);
      if (i >= 0) start = i + 1;
      else resync = { reason: 'unknown_cursor', since: null };
    }
    const replay = feed.slice(start);
    const head = start > 0 ? feed[start - 1].id : '';
    let text = frame('sys.hello', head, {
      server_time: state.iso(),
      topics: requested.map((t) => t.name),
      start: head,
      replayed: replay.length,
    });
    if (resync) text += frame('sys.resync', null, resync);
    for (const e of replay)
      text += frame(e.type, e.id, {
        id: e.id,
        topic: own.name,
        seq: feed.indexOf(e) + 1,
        type: e.type,
        ts: e.occurred_at,
        data: e.data,
      });
    text += frame('sys.closed', null, { reason: 'reauthenticate' });
    return {
      status: 200,
      body: text,
      headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-store, no-transform', 'x-accel-buffering': 'no' },
    };
  },
};
