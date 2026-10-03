import { describe, expect, it } from 'vitest';
import {
  checkTestVectors,
  hashIdentifier,
  LookupInputError,
  type LookupTestVectors,
  LookupVectorError,
  lookupHash,
  normalizeIdentifier,
  UsageValidationError,
  usageReadingErrors,
  validateUsageReading,
} from '../src/index';
import { fixture } from './helpers';

const vectors = fixture<LookupTestVectors>('lookup/test-vectors.json');

describe('lookup: normalisation v1 and the hash, against the published vectors', () => {
  it('reproduces all six vectors', () => {
    expect(vectors.vectors.length).toBe(6);
    expect(() => checkTestVectors(vectors)).not.toThrow();
    const first = vectors.vectors[0]!;
    expect(first.input).toBe(' bg 123 456 789 ');
    expect(lookupHash('vat', normalizeIdentifier('vat', first.input), { version: 0, salt: vectors.salt }).hash).toBe(
      '12c9b8f891583acaea6dc0f86233ea527c32c31e0bd818c329a7105d3beaf366',
    );
  });
  it('one changed vector fails at its index', () => {
    const broken = { ...vectors, vectors: vectors.vectors.map((v, i) => (i === 4 ? { ...v, hash: '0'.repeat(64) } : v)) };
    expect(() => checkTestVectors(broken)).toThrow(LookupVectorError);
    try {
      checkTestVectors(broken);
    } catch (error) {
      expect((error as LookupVectorError).index).toBe(4);
      expect((error as LookupVectorError).field).toBe('hash');
    }
  });
  it('the rules: no plus-tag or dot stripping, the domain IDNA-encoded after the last @', () => {
    expect(normalizeIdentifier('email', 'a.b+c@Bücher.example')).toBe('a.b+c@xn--bcher-kva.example');
    expect(normalizeIdentifier('email', '"x@y"@Example.COM')).toBe('"x@y"@example.com');
    expect(normalizeIdentifier('vat', 'de 12.345.678/9', { country: 'BG' })).toBe('DE123456789');
    expect(normalizeIdentifier('registration', ' hrb-12.345 ', { country: 'de' })).toBe('DE:HRB12345');
  });
  it('what cannot be checked is never hashed', () => {
    const reason = (fn: () => unknown) => {
      try {
        fn();
      } catch (error) {
        expect(error).toBeInstanceOf(LookupInputError);
        expect((error as LookupInputError).code).toBe('cannot_be_checked');
        return (error as LookupInputError).reason;
      }
      return 'ok';
    };
    expect(reason(() => normalizeIdentifier('vat', ' .-/ '))).toBe('empty');
    expect(reason(() => normalizeIdentifier('vat', '123456789'))).toBe('no_country');
    expect(reason(() => normalizeIdentifier('vat', '123456789', { country: 'Bulgaria' }))).toBe('no_country');
    expect(reason(() => normalizeIdentifier('registration', '123'))).toBe('no_country');
    expect(reason(() => normalizeIdentifier('email', 'jane.example.com'))).toBe('no_at_sign');
    expect(reason(() => normalizeIdentifier('email', 'jane@'))).toBe('bad_domain');
    expect(reason(() => normalizeIdentifier('email', '   '))).toBe('empty');
    expect(reason(() => hashIdentifier('vat', '', { version: 1, salt: vectors.salt }))).toBe('empty');
  });
  it('the hash names its kind and salt version', () => {
    expect(hashIdentifier('vat', 'BG123456789', { version: 7, salt: vectors.salt })).toEqual({
      kind: 'vat',
      salt_version: 7,
      hash: '12c9b8f891583acaea6dc0f86233ea527c32c31e0bd818c329a7105d3beaf366',
    });
    expect(() => lookupHash('vat', 'BG1', { version: 1, salt: 'short' })).toThrow(TypeError);
  });
});

describe('usage: ever.usage.v1 readings carry counts only', () => {
  const expected = fixture<{ fixtures: Record<string, { valid: boolean; path?: string }> }>('usage/expected.json').fixtures;
  for (const [file, e] of Object.entries(expected)) {
    it(`${file}: ${e.valid ? 'valid' : `fails at ${e.path}`}`, () => {
      const body = fixture(`usage/${file}`);
      const errors = usageReadingErrors(body);
      if (e.valid) {
        expect(errors).toEqual([]);
        expect(() => validateUsageReading(body)).not.toThrow();
      } else {
        expect(errors.map((x) => x.path)).toContain(e.path);
        expect(() => validateUsageReading(body)).toThrow(UsageValidationError);
      }
    });
  }
  it('an error names paths and codes, never a value', () => {
    const body = { ...fixture('usage/valid/employees.json'), contact: 'Jane Doe <jane@example.com>' };
    try {
      validateUsageReading(body);
    } catch (error) {
      expect(String((error as Error).message)).not.toContain('Jane');
      expect((error as UsageValidationError).errors).toEqual([{ path: '/contact', code: 'unknown_field' }]);
    }
  });
});
