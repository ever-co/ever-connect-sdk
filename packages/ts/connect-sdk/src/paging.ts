/**
 * Cursor-paged reads: every page of a list, in order, from the first page (no cursor) to the one
 * whose `next_cursor` is `null`. The read is bounded: it stops with a {@link PagingError} on a
 * cursor the platform handed out before (`cursor_repeated`), after `maxPages` pages
 * (`too_many_pages`), and on an answer that is not a page (`malformed_page`), so a caller that
 * acts on what a whole list leaves out (a membership resync removing people) never acts on part
 * of one.
 */
import { PagingError } from './errors';

/** One page of a cursor-paged list: its items and the cursor of the next page (`null` on the last). */
export interface CursorPage<T> {
  readonly items: readonly T[];
  readonly next_cursor?: string | null;
}

/** The most pages a paged read takes unless told otherwise (100,000 items at 100 a page). */
export const DEFAULT_MAX_PAGES = 1000;

/** The largest page the platform's cursor-paged lists answer. */
export const MAX_PAGE_SIZE = 100;

/** Reads one page: `cursor` is `null` for the first page, else the previous page's `next_cursor`. */
export type PageReader = (cursor: string | null) => Promise<unknown>;

function isPage(page: unknown): page is CursorPage<unknown> {
  if (typeof page !== 'object' || page === null || Array.isArray(page)) return false;
  const { items, next_cursor: next } = page as { items?: unknown; next_cursor?: unknown };
  return Array.isArray(items) && (next === undefined || next === null || typeof next === 'string');
}

/**
 * Every page, in order. An empty `next_cursor` ends the list like `null`. Stops with a
 * {@link PagingError}; any error of `read` (a `ProblemError`, a timeout) ends the read as it is.
 */
export async function* readPages<T>(
  read: PageReader,
  maxPages: number = DEFAULT_MAX_PAGES,
): AsyncGenerator<CursorPage<T>, void, undefined> {
  if (!Number.isSafeInteger(maxPages) || maxPages < 1) throw new RangeError('maxPages is a positive integer');
  const seen = new Set<string>();
  let cursor: string | null = null;
  for (let pages = 0; ; ) {
    if (pages >= maxPages) throw new PagingError('too_many_pages', pages);
    const page = await read(cursor);
    pages += 1;
    if (!isPage(page)) throw new PagingError('malformed_page', pages);
    yield page as CursorPage<T>;
    const next = page.next_cursor ?? null;
    if (next === null || next === '') return;
    if (seen.has(next)) throw new PagingError('cursor_repeated', pages);
    seen.add(next);
    cursor = next;
  }
}

/** Every item of every page, in order (see {@link readPages}). */
export async function readAllPages<T>(read: PageReader, maxPages: number = DEFAULT_MAX_PAGES): Promise<T[]> {
  const items: T[] = [];
  for await (const page of readPages<T>(read, maxPages)) items.push(...page.items);
  return items;
}
