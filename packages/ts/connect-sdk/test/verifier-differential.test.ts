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
const keySet = KeySet.verify(fixture('keys/manifest.valid.json'), { rootKeys: roots, issuer: keysCtx.issuer, now: keysCtx.now });
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
