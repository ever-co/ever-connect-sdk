/**
 * Counterparty lookup: identifier normalisation (version 1) and the salted hash an installation
 * sends instead of the identifier. An identifier that cannot be normalised is never hashed or sent
 * ({@link LookupInputError}, "cannot be checked").
 *
 *   vat           trim, upper-case, drop spaces, dots, hyphens and slashes; a leading two-letter
 *                 prefix is the country, otherwise the caller's country is prepended
 *   registration  `<CC>:<number>`: the caller's country, then the number trimmed, upper-cased,
 *                 without spaces, dots and hyphens
 *   email         trim, Unicode NFC, lower-case, the part after the last `@` IDNA-encoded; no
 *                 plus-tag or dot is removed
 *
 *   hash = hex(sha256(salt bytes ‖ ":" ‖ kind ‖ ":" ‖ utf8(normalized)))
 */
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { fromB64url } from './encoding';
import { LookupInputError, LookupVectorError } from './errors';

/** The identifier kinds of normalisation version 1. */
export type LookupKind = 'vat' | 'registration' | 'email';
export const LOOKUP_KINDS: readonly LookupKind[] = ['vat', 'registration', 'email'];
export const NORMALIZATION_VERSION = 1;

/** One published salt (`GET /v1/lookup/salt` lists the active ones; version 0 is the test salt). */
export interface LookupSalt {
  readonly version: number;
  /** base64url of 32 bytes. */
  readonly salt: string;
}

/** One hashed identifier, as `POST /v1/lookup` and the identifier upload take it. */
export interface LookupHash {
  readonly kind: LookupKind;
  readonly salt_version: number;
  readonly hash: string;
}

/** The published test vectors (`GET /v1/lookup/test-vectors`). */
export interface LookupTestVectors {
  readonly salt_version: number;
  readonly salt: string;
  readonly normalization_version: number;
  readonly vectors: readonly {
    readonly kind: string;
    readonly input: string;
    readonly country?: string;
    readonly normalized: string;
    readonly salt_version?: number;
    readonly hash: string;
  }[];
}

function country(ctx: { country?: string } | undefined): string {
  const cc = (ctx?.country ?? '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) throw new LookupInputError('no_country');
  return cc;
}

/** Normalises an identifier (version 1); throws {@link LookupInputError} when it cannot be checked. */
export function normalizeIdentifier(kind: LookupKind, value: string, ctx?: { country?: string }): string {
  if (typeof value !== 'string') throw new LookupInputError('empty');
  switch (kind) {
    case 'vat': {
      const v = value
        .trim()
        .toUpperCase()
        .replace(/[ ./-]/g, '');
      if (v === '') throw new LookupInputError('empty');
      return /^[A-Z]{2}/.test(v) ? v : `${country(ctx)}${v}`;
    }
    case 'registration': {
      const n = value.trim().toUpperCase().replace(/[ .-]/g, '');
      if (n === '') throw new LookupInputError('empty');
      return `${country(ctx)}:${n}`;
    }
    case 'email': {
      const v = value.trim().normalize('NFC').toLowerCase();
      if (v === '') throw new LookupInputError('empty');
      const at = v.lastIndexOf('@');
      if (at < 0) throw new LookupInputError('no_at_sign');
      const domain = domainToASCII(v.slice(at + 1));
      if (domain === '') throw new LookupInputError('bad_domain');
      return `${v.slice(0, at)}@${domain}`;
    }
    default:
      throw new LookupInputError('unknown_kind');
  }
}

/** The salted hash of a normalised identifier. */
export function lookupHash(kind: LookupKind, normalized: string, salt: LookupSalt): LookupHash {
  if (!LOOKUP_KINDS.includes(kind)) throw new LookupInputError('unknown_kind');
  if (normalized === '') throw new LookupInputError('empty');
  const saltBytes = fromB64url(salt.salt);
  if (saltBytes?.length !== 32) throw new TypeError('a lookup salt is 32 bytes, base64url');
  const hash = createHash('sha256').update(saltBytes).update(`:${kind}:`).update(normalized, 'utf8').digest('hex');
  return { kind, salt_version: salt.version, hash };
}

/** Normalises and hashes in one step. */
export const hashIdentifier = (kind: LookupKind, value: string, salt: LookupSalt, ctx?: { country?: string }): LookupHash =>
  lookupHash(kind, normalizeIdentifier(kind, value, ctx), salt);

/** Reproduces every published vector; throws {@link LookupVectorError} at the first one that differs. */
export function checkTestVectors(vectors: LookupTestVectors): void {
  vectors.vectors.forEach((v, index) => {
    const kind = v.kind as LookupKind;
    let normalized: string;
    try {
      normalized = normalizeIdentifier(kind, v.input, v.country === undefined ? undefined : { country: v.country });
    } catch {
      throw new LookupVectorError(index, 'normalized');
    }
    if (normalized !== v.normalized) throw new LookupVectorError(index, 'normalized');
    const { hash } = lookupHash(kind, normalized, { version: vectors.salt_version, salt: vectors.salt });
    if (hash !== v.hash) throw new LookupVectorError(index, 'hash');
  });
}
