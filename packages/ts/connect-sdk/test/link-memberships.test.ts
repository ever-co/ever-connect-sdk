// A tenant link's members (row 38): one page, every page (bounded, stopped on a repeated cursor or
// an answer that is not a page), and the operation as products registered it before the SDK
// shipped it.
import { describe, expect, it } from 'vitest';
import {
  createEverPlatformClient,
  type LinkMembership,
  makeNodeSigner,
  OPERATIONS,
  PagingError,
  ProblemError,
  readAllPages,
  readPages,
} from '../src/index';

const INSTANCE = '01JNE7V9J03J6XQ2WN8H0Z88R5';
const LINK = '01JHGF4PAY0P5JJ7J2A56VSRZM';
const SIGNER = makeNodeSigner(new Uint8Array(32).fill(11));
const TOKEN = 'evit_secret-token-value-0004';
const BASE = 'https://api.ever.test';
const PATH = `/v1/instances/me/tenant-links/${LINK}/memberships`;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': status >= 400 ? 'application/problem+json' : 'application/json' },
  });

const member = (subject: string, role: LinkMembership['role'] = 'member'): LinkMembership => ({
  identity_issuer: 'https://auth.ever.test',
  identity_subject: subject,
  role,
});

/** A platform that issues tokens and answers the member list from `pages`, by cursor (`''` for the first page). */
function platform(pages: Record<string, () => Response>) {
  const urls: string[] = [];
  const authorizations: string[] = [];
  const fetch = (async (url: string, init: RequestInit) => {
    if (url.endsWith('/v1/instances/token')) return json(200, { access_token: TOKEN, token_type: 'Bearer', expires_in: 3600 });
    urls.push(url.slice(BASE.length));
    authorizations.push((init.headers as Record<string, string>).authorization ?? '');
    const cursor = new URL(url).searchParams.get('cursor') ?? '';
    const answer = pages[cursor];
    return answer ? answer() : json(500, { type: 'https://api.ever.co/problems/internal_error', code: 'internal_error' });
  }) as unknown as typeof globalThis.fetch;
  const client = createEverPlatformClient({
    baseUrl: BASE,
    userAgentProduct: { product: 'works', version: '1.2.3' },
    signer: SIGNER,
    registryInstanceId: () => INSTANCE,
    fetch,
    now: () => 1793613600,
  });
  return { client, urls, authorizations };
}

const page = (items: LinkMembership[], next: string | null) => () => json(200, { tenant_link_id: LINK, items, next_cursor: next });

describe('instances.tenantLinks.memberships', () => {
  it('reads one page with the instance token, the cursor and the limit', async () => {
    const p = platform({ c1: page([member('s-2')], null) });
    const answer = await p.client.instances.tenantLinks.memberships(LINK, { cursor: 'c1', limit: 50 });
    expect(answer).toEqual({ tenant_link_id: LINK, items: [member('s-2')], next_cursor: null });
    expect(p.urls).toEqual([`${PATH}?cursor=c1&limit=50`]);
    expect(p.authorizations).toEqual([`Bearer ${TOKEN}`]);
  });

  it('sends neither cursor nor limit when none is given', async () => {
    const p = platform({ '': page([], null) });
    await p.client.instances.tenantLinks.memberships(LINK);
    expect(p.urls).toEqual([PATH]);
  });

  it('answers 404 module_disabled as a ProblemError', async () => {
    const p = platform({
      '': () => json(404, { type: 'https://api.ever.co/problems/module_disabled', code: 'module_disabled', status: 404 }),
    });
    const error = await p.client.instances.tenantLinks.memberships(LINK).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ProblemError);
    expect(error).toMatchObject({ status: 404, code: 'module_disabled' });
  });
});

describe('instances.tenantLinks.allMemberships', () => {
  it('reads every page in order, 100 a page, until next_cursor is null', async () => {
    const p = platform({
      '': page([member('s-1', 'owner'), member('s-2')], 'c1'),
      c1: page([member('s-3')], 'c2'),
      c2: page([], null),
    });
    const all = await p.client.instances.tenantLinks.allMemberships(LINK);
    expect(all.map((m) => m.identity_subject)).toEqual(['s-1', 's-2', 's-3']);
    expect(p.urls).toEqual([`${PATH}?limit=100`, `${PATH}?cursor=c1&limit=100`, `${PATH}?cursor=c2&limit=100`]);
  });

  it('stops on a cursor it was handed before (cursor_repeated)', async () => {
    const p = platform({ '': page([member('s-1')], 'c1'), c1: page([member('s-2')], 'c1') });
    const error = await p.client.instances.tenantLinks.allMemberships(LINK).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(PagingError);
    expect(error).toMatchObject({ code: 'cursor_repeated', pages: 2 });
    expect(p.urls).toHaveLength(2);
  });

  it('stops after maxPages pages (too_many_pages), never answering part of the list', async () => {
    // A list that never ends: every page names a new cursor.
    let n = 0;
    const endless = new Proxy({} as Record<string, () => Response>, {
      get: () => () => {
        n += 1;
        return json(200, { tenant_link_id: LINK, items: [member(`s-${n}`)], next_cursor: `c${n}` });
      },
    });
    const p = platform(endless);
    const error = await p.client.instances.tenantLinks.allMemberships(LINK, { maxPages: 3, limit: 1 }).catch((e: unknown) => e);
    expect(error).toMatchObject({ name: 'PagingError', code: 'too_many_pages', pages: 3 });
    expect(p.urls).toEqual([`${PATH}?limit=1`, `${PATH}?cursor=c1&limit=1`, `${PATH}?cursor=c2&limit=1`]);
  });

  it('stops on an answer that is not a page (malformed_page)', async () => {
    for (const body of [{ next_cursor: null }, { items: [], next_cursor: 7 }, [], null]) {
      const p = platform({ '': () => json(200, body) });
      await expect(p.client.instances.tenantLinks.allMemberships(LINK)).rejects.toMatchObject({ code: 'malformed_page', pages: 1 });
    }
  });

  it('ends the read with the problem of any page', async () => {
    const p = platform({
      '': page([member('s-1')], 'c1'),
      c1: () => json(422, { type: 'https://api.ever.co/problems/validation_failed', code: 'validation_failed', status: 422 }),
    });
    await expect(p.client.instances.tenantLinks.allMemberships(LINK)).rejects.toMatchObject({ status: 422, code: 'validation_failed' });
  });
});

describe('readPages and readAllPages', () => {
  it('take an empty next_cursor as the end, and refuse a page bound below 1', async () => {
    const cursors: (string | null)[] = [];
    const items = await readAllPages<number>(async (cursor) => {
      cursors.push(cursor);
      return cursor === null ? { items: [1, 2], next_cursor: 'a' } : { items: [3], next_cursor: '' };
    });
    expect(items).toEqual([1, 2, 3]);
    expect(cursors).toEqual([null, 'a']);
    await expect(readAllPages(async () => ({ items: [] }), 0)).rejects.toBeInstanceOf(RangeError);
  });

  it('yield page by page, so a caller can stop early', async () => {
    let reads = 0;
    for await (const p of readPages<number>(async () => {
      reads += 1;
      return { items: [reads], next_cursor: `c${reads}` };
    })) {
      expect(p.items).toEqual([1]);
      break;
    }
    expect(reads).toBe(1);
  });
});

describe('the operation in the table', () => {
  it('is the one products registered while the SDK had none (their guard keeps the SDK entry)', () => {
    expect(OPERATIONS.instanceListLinkMemberships).toMatchObject({
      id: 'instanceListLinkMemberships',
      method: 'GET',
      path: '/v1/instances/me/tenant-links/{link}/memberships',
      pathParams: ['link'],
      query: ['cursor', 'limit'],
      auth: 'instance',
      idempotencyKey: 'none',
      linkHeader: 'none',
      body: null,
      success: [200],
      row: 38,
    });
  });
});
