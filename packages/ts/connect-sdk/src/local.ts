/**
 * Local hosts: the only places where plain `http://`, extra root keys and another issuer are
 * accepted (CI positive controls, the mock platform, a development build). The list comes from
 * `CONSTANTS.root_keys_file_hosts`.
 */
import { CONSTANTS } from '@ever-co/connect-contracts';

function ipv4(host: string): number | null {
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

function inCidr(address: number, cidr: string): boolean {
  const [base, bits] = cidr.split('/') as [string, string];
  const start = ipv4(base);
  if (start === null) return false;
  const size = 2 ** (32 - Number(bits));
  return address >= start && address < start + size;
}

/** Whether `hostname` (as `URL.hostname` gives it) is a local host. */
export function isLocalHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[(.*)\]$/, '$1');
  const address = ipv4(host);
  for (const entry of CONSTANTS.root_keys_file_hosts) {
    if (entry.startsWith('*.')) {
      if (host.endsWith(entry.slice(1)) && host.length > entry.length - 1) return true;
    } else if (entry.includes('/')) {
      if (address !== null && inCidr(address, entry)) return true;
    } else if (host === entry) return true;
  }
  return false;
}

/** Whether a URL points at a local host. */
export function isLocalUrl(url: string): boolean {
  try {
    return isLocalHost(new URL(url).hostname);
  } catch {
    return false;
  }
}

/** The origin of a URL (`https://api.ever.co`), or null when it is not an http(s) URL. */
export function originOf(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null;
  } catch {
    return null;
  }
}

let warned = false;
/** Writes one warning per process (the override rules say "ignored with one warning"). */
export function warnOnce(message: string, sink: (message: string) => void = (m) => console.warn(m)): void {
  if (warned) return;
  warned = true;
  sink(message);
}
