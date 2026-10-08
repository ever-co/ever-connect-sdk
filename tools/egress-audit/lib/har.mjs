// The browser leg's HAR: what browser.mjs keeps of Playwright's recording, and what assert.mjs reads.
// No body, cookie, header value (a short list of harmless ones excepted), form value, query value
// or fragment is kept: an artefact holds only which request went where and how it ended.

/** Header names whose values say nothing about a person or a session. */
const SAFE_HEADERS = new Set([
  'accept',
  'accept-encoding',
  'accept-language',
  'access-control-allow-origin',
  'cache-control',
  'content-encoding',
  'content-length',
  'content-type',
  'host',
  'origin',
  'pragma',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'server',
  'upgrade',
  'user-agent',
  'vary',
]);
/** Header names whose values are URLs: kept, redacted. */
const URL_HEADERS = new Set(['location', 'referer']);
export const REDACTED = '[redacted]';

/**
 * A URL without its secrets: query values, the fragment and any user info are dropped (query names
 * stay); a mailto: address keeps only its domain. A value that is not a URL is answered as is when
 * it has no query, else cut at the `?`.
 */
export function redactUrl(value) {
  const text = String(value ?? '');
  const mail = /^mailto:([^?]*)/i.exec(text);
  if (mail) {
    const first = mail[1].split(',')[0];
    const at = first.lastIndexOf('@');
    return at >= 0 ? `mailto:${REDACTED}@${first.slice(at + 1)}` : 'mailto:';
  }
  let u;
  try {
    u = new URL(text);
  } catch {
    return text.split(/[?#]/)[0];
  }
  if (!/^(https?|wss?|ftp):$/.test(u.protocol)) return `${u.protocol}${u.protocol === 'data:' ? REDACTED : u.pathname.split(/[?#]/)[0]}`;
  const keys = [...new Set([...u.searchParams.keys()])];
  return `${u.protocol}//${u.host}${u.pathname}${keys.length ? `?${keys.map((k) => `${encodeURIComponent(k)}=`).join('&')}` : ''}`;
}

const headers = (list) =>
  (list ?? []).map(({ name, value }) => {
    const n = String(name).toLowerCase();
    if (SAFE_HEADERS.has(n) || n.startsWith('sec-ch-ua')) return { name, value };
    if (URL_HEADERS.has(n)) return { name, value: redactUrl(value) };
    return { name, value: REDACTED };
  });

/** A Playwright HAR (log) with every body, cookie, header value, query value and form value removed. */
export function sanitizeHar(har) {
  const log = har?.log ?? {};
  return {
    log: {
      version: log.version ?? '1.2',
      creator: log.creator ?? { name: 'ever-egress-audit', version: '1' },
      browser: log.browser,
      pages: (log.pages ?? []).map((p) => ({ startedDateTime: p.startedDateTime, id: p.id, title: '', pageTimings: p.pageTimings ?? {} })),
      entries: (log.entries ?? []).map((e) => {
        const req = e.request ?? {};
        const res = e.response ?? {};
        return {
          pageref: e.pageref,
          startedDateTime: e.startedDateTime,
          time: e.time,
          request: {
            method: req.method,
            url: redactUrl(req.url),
            httpVersion: req.httpVersion,
            cookies: [],
            headers: headers(req.headers),
            queryString: (req.queryString ?? []).map((q) => ({ name: q.name, value: REDACTED })),
            ...(req.postData ? { postData: { mimeType: req.postData.mimeType ?? '', text: '' } } : {}),
            headersSize: req.headersSize ?? -1,
            bodySize: req.bodySize ?? -1,
          },
          response: {
            status: res.status,
            statusText: res.statusText ?? '',
            httpVersion: res.httpVersion ?? '',
            cookies: [],
            headers: headers(res.headers),
            content: { size: res.content?.size ?? -1, mimeType: res.content?.mimeType ?? '' },
            redirectURL: res.redirectURL ? redactUrl(res.redirectURL) : '',
            headersSize: res.headersSize ?? -1,
            bodySize: res.bodySize ?? -1,
            ...(res._failureText ? { _failureText: String(res._failureText).slice(0, 200) } : {}),
          },
          cache: {},
          timings: e.timings ?? { send: -1, wait: -1, receive: -1 },
          ...(e.serverIPAddress ? { serverIPAddress: e.serverIPAddress } : {}),
          ...(e._resourceType ? { _resourceType: e._resourceType } : {}),
        };
      }),
    },
  };
}

/**
 * What a HAR artefact holds that it must not: a cookie, set-cookie or authorization value, a
 * request body, a cookie list, or any of the given secrets anywhere in its text.
 */
export function harLeaks(text, secrets = []) {
  const problems = [];
  for (const s of secrets) if (s && text.includes(s)) problems.push('the HAR holds a secret it was given');
  const har = JSON.parse(text);
  for (const e of har.log?.entries ?? []) {
    for (const h of [...(e.request?.headers ?? []), ...(e.response?.headers ?? [])])
      if (/^(cookie|set-cookie|authorization)$/i.test(h.name) && h.value !== REDACTED) problems.push(`the HAR holds a ${h.name} value`);
    if (e.request?.postData?.text) problems.push('the HAR holds a request body');
    if ((e.request?.cookies ?? []).length || (e.response?.cookies ?? []).length) problems.push('the HAR holds cookies');
    if (e.response?.content?.text !== undefined) problems.push('the HAR holds a response body');
  }
  return [...new Set(problems)];
}

/** The host of a URL, lower case, or '' (data:, blob:, about: ...). */
export function urlHost(value) {
  try {
    return new URL(value).hostname.toLowerCase().replace(/^\[|\]$/g, '');
  } catch {
    return '';
  }
}

/** One row per HAR entry: {method, url, host, path, status, failure}. */
export function harEntries(har) {
  return (har?.log?.entries ?? []).map((e) => {
    const url = e.request?.url ?? '';
    let path = '';
    try {
      path = new URL(url).pathname;
    } catch {
      // not a URL with a path
    }
    return {
      method: e.request?.method ?? '',
      url,
      host: urlHost(url),
      path,
      status: e.response?.status ?? 0,
      ...(e.response?._failureText ? { failure: e.response._failureText } : {}),
    };
  });
}
