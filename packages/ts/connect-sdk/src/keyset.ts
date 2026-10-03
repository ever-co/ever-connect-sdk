/**
 * The key set: the keys of the last verified manifest, held in memory. Storage stays in the
 * product (persist `toJSON()` and rebuild with `KeySet.restore`, which verifies again).
 *
 * - `find(kid, purpose)` answers only an `active` or `previous` key of that purpose inside its
 *   validity window, so an assertion or intent key never verifies an entitlement document.
 * - `needsRefresh(now)` is true 24 h after the last fetch, and when the manifest has expired.
 * - `unknownKidRefreshAllowed(now)` answers true at most once per 10 minutes.
 * - A manifest that fails verification, or that is older than the current one, never replaces it.
 */
import { CONSTANTS } from '@ever-co/connect-contracts';
import { KeyManifestError } from './errors';
import {
  CLOCK_SKEW_S,
  type KeyManifestDocument,
  type ManifestKey,
  type VerifiedKeyManifest,
  type VerifyKeyManifestOptions,
  verifyKeyManifest,
} from './manifest';

/** What a product persists between restarts. */
export interface StoredKeySet {
  readonly document: KeyManifestDocument;
  /** Unix seconds of the fetch. */
  readonly fetchedAt: number;
}

/** The outcome of {@link KeySet.update}. */
export interface KeySetUpdate {
  /** The key set to use from now on (the previous one when the manifest was refused). */
  readonly keySet: KeySet;
  readonly replaced: boolean;
  /** Why the manifest was refused; null when it replaced the set or was older than the current one. */
  readonly error: KeyManifestError | null;
}

const seconds = (iso: string | null | undefined): number | null => {
  if (iso === null || iso === undefined) return null;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
};

export class KeySet {
  private lastUnknownKidRefresh: number | null = null;

  private constructor(
    /** The verified manifest. */
    readonly manifest: VerifiedKeyManifest,
    /** Unix seconds of the fetch. */
    readonly fetchedAt: number,
  ) {}

  /** A key set over a manifest that {@link verifyKeyManifest} answered. */
  static fromManifest(manifest: VerifiedKeyManifest, fetchedAt: number = Math.floor(Date.now() / 1000)): KeySet {
    return new KeySet(manifest, fetchedAt);
  }

  /** Verifies a served body and builds a key set; throws {@link KeyManifestError}. */
  static verify(body: unknown, options: VerifyKeyManifestOptions = {}): KeySet {
    const now = Math.floor(options.now ?? Date.now() / 1000);
    return new KeySet(verifyKeyManifest(body, { ...options, now }), now);
  }

  /** Rebuilds a stored key set, verifying the stored manifest again (offline: only the pinned root is needed). */
  static restore(stored: StoredKeySet, options: VerifyKeyManifestOptions = {}): KeySet {
    return new KeySet(verifyKeyManifest(stored.document, options), stored.fetchedAt);
  }

  /** The key `kid` for `purpose` at `now`, or null: unknown, another purpose, retired or outside its window. */
  find(kid: string, purpose: ManifestKey['ever_purpose'], now: number = Math.floor(Date.now() / 1000)): ManifestKey | null {
    const key = this.manifest.keys.find((k) => k.kid === kid);
    if (!key || key.ever_purpose !== purpose || (key.state !== 'active' && key.state !== 'previous')) return null;
    const notBefore = seconds(key.not_before);
    const notAfter = seconds(key.not_after);
    if (notBefore === null || now + CLOCK_SKEW_S < notBefore) return null;
    if (notAfter !== null && now > notAfter + CLOCK_SKEW_S) return null;
    return key;
  }

  /** Whether the manifest lists `kid` at all (an unknown `kid` suggests one refresh). */
  has(kid: string): boolean {
    return this.manifest.keys.some((k) => k.kid === kid);
  }

  /** True 24 h after the fetch, and once the manifest has expired. */
  needsRefresh(now: number = Math.floor(Date.now() / 1000)): boolean {
    return now - this.fetchedAt >= CONSTANTS.key_manifest.refresh_s || now >= this.manifest.expiresAt;
  }

  /**
   * Whether an unknown `kid` may trigger a refresh now (at most once per 10 minutes); answering
   * true records the refresh.
   */
  unknownKidRefreshAllowed(now: number = Math.floor(Date.now() / 1000)): boolean {
    // A fetch is a refresh too: a set fetched less than 10 minutes ago is not fetched again.
    const last = Math.max(this.fetchedAt, this.lastUnknownKidRefresh ?? Number.NEGATIVE_INFINITY);
    if (now - last < CONSTANTS.key_manifest.unknown_kid_refresh_min_s) return false;
    this.lastUnknownKidRefresh = now;
    return true;
  }

  /**
   * Verifies a newly fetched manifest body. It replaces this set only when it verifies and is not
   * older than the current manifest; otherwise this set stays in use.
   */
  update(body: unknown, options: VerifyKeyManifestOptions = {}): KeySetUpdate {
    const now = Math.floor(options.now ?? Date.now() / 1000);
    let next: VerifiedKeyManifest;
    try {
      next = verifyKeyManifest(body, { ...options, now });
    } catch (error) {
      if (error instanceof KeyManifestError) return { keySet: this, replaced: false, error };
      throw error;
    }
    if (next.issuedAt < this.manifest.issuedAt) return { keySet: this, replaced: false, error: null };
    const keySet = new KeySet(next, now);
    keySet.lastUnknownKidRefresh = this.lastUnknownKidRefresh;
    return { keySet, replaced: true, error: null };
  }

  /** What to persist: the served body and the fetch time (no secret is in it). */
  toJSON(): StoredKeySet {
    return { document: this.manifest.document, fetchedAt: this.fetchedAt };
  }
}
