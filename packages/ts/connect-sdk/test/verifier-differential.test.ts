// The seeded mutation corpus (tools/fixtures/mutations.mjs): every case flips one bit of a valid
// document. None may verify, and the answer of each case must equal the committed one, which the
// Rust verifier reproduces too (crates/ever-connect-sdk/tests/verifier_differential.rs).
import { describe, expect, it } from 'vitest';
// @ts-expect-error: a plain ES module of the repository tools (no type declarations).
import { CODE_LETTERS, corpusSha256, mutationCorpus } from '../../../../tools/fixtures/mutations.mjs';
import { EntitlementError, KeySet, type RootKey, verifyEntitlement } from '../src/index';
import { fixture, fixtureText } from './helpers';

const ctx = fixture('entitlement/context.json');
const keysCtx = fixture('keys/context.json');
const roots = fixture<{ keys: RootKey[] }>('keys/roots.json').keys;
const keySet = KeySet.verify(fixture('keys/manifest.valid.json'), { unsafeRootKeys: roots, issuer: keysCtx.issuer, now: keysCtx.now });
const committed = fixture<{
  seed: number;
  count: number;
  bases: string[];
  corpus_sha256: string;
  letters: Record<string, string>;
  answers: string;
}>('entitlement/mutations.json');

describe('verifier differential: the seeded mutation corpus', () => {
  const bases = committed.bases.map((b) => fixtureText(`entitlement/${b}`).trim());
  const corpus: { base: number; jws: string }[] = mutationCorpus(bases, committed.count, committed.seed);

  it('is the committed corpus', () => {
    expect(corpus.length).toBe(10000);
    expect(corpusSha256(corpus)).toBe(committed.corpus_sha256);
    expect(committed.letters).toEqual(CODE_LETTERS);
  });

  it('no mutated document verifies, and every answer equals the committed one', { timeout: 120_000 }, () => {
    const subjects = [ctx.expected_subject, ctx.expected_subject_by_file['valid/link.jws']];
    let answers = '';
    for (const { base, jws } of corpus) {
      try {
        verifyEntitlement(jws, {
          keySet,
          expectedIssuer: ctx.expected_issuer,
          expectedInstanceId: ctx.expected_instance_id,
          expectedSubject: subjects[base],
          cached: null,
          now: ctx.now,
        });
        answers += '!';
      } catch (error) {
        if (!(error instanceof EntitlementError)) throw error;
        answers += committed.letters[error.code] ?? '?';
      }
    }
    expect(answers.includes('!')).toBe(false);
    const first = [...answers].findIndex((a, i) => a !== committed.answers[i]);
    expect(first, `case ${first}`).toBe(-1);
  });
});

// The structured corpus (tools/fixtures/structured.mjs): documents and manifests built on purpose,
// each verified in its own context; every answer must equal the reference verifier's, which the
// Rust verifier reproduces too.
interface StructuredCase {
  name: string;
  jws: string;
  expect: string;
  manifest?: unknown;
  manifest_issuer?: string;
  manifest_now?: number;
  roots?: 'fixture' | 'pinned' | RootKey[];
  expected_issuer?: string;
  expected_instance_id?: string;
  expected_subject?: string;
  cached?: { seq: number; iat: number } | null;
  now?: number;
}
const structured = fixture<{
  defaults: Required<Omit<StructuredCase, 'name' | 'jws' | 'expect' | 'manifest'>> & { manifest: string };
  cases: StructuredCase[];
}>('entitlement/structured.json');

/** The answer of the SDK for one structured case, in the corpus's notation. */
export function structuredAnswer(c: StructuredCase): string {
  const o = { ...structured.defaults, ...c };
  const body = c.manifest ?? fixture(structured.defaults.manifest);
  const unsafeRootKeys = Array.isArray(o.roots) ? o.roots : o.roots === 'fixture' ? roots : undefined;
  let set: KeySet;
  try {
    set = KeySet.verify(body, { issuer: o.manifest_issuer, now: o.manifest_now, ...(unsafeRootKeys ? { unsafeRootKeys } : {}) });
  } catch (error) {
    return `manifest:${(error as { code: string }).code}`;
  }
  try {
    const r = verifyEntitlement(c.jws, {
      keySet: set,
      expectedIssuer: o.expected_issuer,
      expectedInstanceId: o.expected_instance_id,
      expectedSubject: o.expected_subject,
      cached: o.cached,
      now: o.now,
    });
    return `ok:${r.status}`;
  } catch (error) {
    if (!(error instanceof EntitlementError)) throw error;
    return `${error.code}${error.refreshSuggested ? '+refresh' : ''}`;
  }
}

describe('verifier differential: the structured corpus', () => {
  it('has every group of the review and more than 118 cases', () => {
    expect(structured.cases.length).toBeGreaterThanOrEqual(118);
    const groups = new Set(structured.cases.map((c) => c.name.split('/')[0]));
    for (const g of [
      'baseline',
      'swap',
      'keys',
      'window',
      'time',
      'weak-key',
      'header',
      'payload',
      'number',
      'rollback',
      'compact',
      'anchor',
    ])
      expect(groups.has(g as string), g).toBe(true);
  });
  for (const c of structured.cases)
    it(`${c.name}: ${c.expect}`, () => {
      expect(structuredAnswer(c)).toBe(c.expect);
    });
});
