/**
 * Connect and link codes (`EVC-XXXX-XXXX-XXXX`, `EVL-XXXX-XXXX-XXXX`): what an operator pastes into
 * the product. `normalize` accepts the code with any case, spaces or missing dashes and answers the
 * canonical spelling Ever Platform expects, or null when it is not a code.
 */
import { CONSTANTS, INTEGRATIONS, type IntegrationKey } from '@ever-co/connect-contracts';

const CONNECT = new RegExp(CONSTANTS.connect_code_pattern);
const LINK = new RegExp(CONSTANTS.link_code_pattern);
const SYMBOLS = /^(EVC|EVL)([0-9A-HJKMNP-TV-Z]{12})$/;

/** The canonical spelling of a connect or link code, or null. */
function normalize(input: string): string | null {
  if (typeof input !== 'string') return null;
  const compact = input.toUpperCase().replace(/[\s-]/g, '');
  const m = SYMBOLS.exec(compact);
  if (!m) return null;
  const s = m[2] as string;
  return `${m[1]}-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
}

export const codes = {
  normalize,
  /** Whether the input is a connect code (after normalisation). */
  isConnectCode: (input: string): boolean => {
    const c = normalize(input);
    return c !== null && CONNECT.test(c);
  },
  /** Whether the input is a link code (after normalisation). */
  isLinkCode: (input: string): boolean => {
    const c = normalize(input);
    return c !== null && LINK.test(c);
  },
} as const;

/** The scope table of an integration, for a read-only "Show scope" view. */
export const scopeTable = (key: IntegrationKey) => INTEGRATIONS[key].scope;
