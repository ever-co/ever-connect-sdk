// The browser leg's DOM dump: every URL the rendered page points at, from the attributes a browser
// follows or loads (href, src, srcset, action, formaction, poster, ping, data, xlink:href,
// imagesrcset, a meta refresh and url() in a style attribute), in the document and in every open
// shadow root. browser.mjs runs collectRefs in every frame of a page.

/**
 * Runs in the page (it is serialised by Playwright, so it uses nothing from this module): answers
 * [{tag, attribute, url}] with each URL resolved against the document's base URL.
 */
export function collectRefs() {
  const single = ['href', 'src', 'action', 'formaction', 'poster', 'data', 'xlink:href'];
  const sets = ['srcset', 'imagesrcset'];
  const out = [];
  const seen = new Set();
  const add = (el, attribute, raw) => {
    const value = String(raw ?? '').trim();
    if (!value || value.startsWith('#') || /^(javascript|data|blob|about):/i.test(value)) return;
    let url = value;
    if (!/^mailto:/i.test(value)) {
      try {
        url = new URL(value, document.baseURI).href;
      } catch {
        return;
      }
    }
    const key = `${el.tagName}|${attribute}|${url}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ tag: el.tagName.toLowerCase(), attribute, url });
  };
  const visit = (root) => {
    for (const el of root.querySelectorAll('*')) {
      for (const name of single) if (el.hasAttribute(name)) add(el, name, el.getAttribute(name));
      for (const name of sets)
        if (el.hasAttribute(name))
          for (const candidate of el.getAttribute(name).split(',')) add(el, name, candidate.trim().split(/\s+/)[0]);
      if (el.hasAttribute('ping')) for (const p of el.getAttribute('ping').split(/\s+/)) add(el, 'ping', p);
      if (el.tagName === 'META' && /refresh/i.test(el.getAttribute('http-equiv') ?? '')) {
        const m = /url\s*=\s*['"]?([^'";]+)/i.exec(el.getAttribute('content') ?? '');
        if (m) add(el, 'content', m[1]);
      }
      const style = el.getAttribute('style');
      if (style && /url\(/i.test(style)) for (const m of style.matchAll(/url\(\s*['"]?([^'")]+)/gi)) add(el, 'style', m[1]);
      if (el.shadowRoot) visit(el.shadowRoot);
    }
  };
  visit(document);
  return out;
}

/**
 * Every frame's references, each with the route it was found on: [{route, frame, tag, attribute, url}].
 * redact(url) keeps a URL without its secrets (lib/har.mjs redactUrl).
 */
export async function pageRefs(page, route, redact) {
  const refs = [];
  for (const frame of page.frames()) {
    let found = [];
    try {
      found = await frame.evaluate(collectRefs);
    } catch {
      continue; // a frame that went away while it was read
    }
    const where = frame === page.mainFrame() ? 'main' : redact(frame.url());
    for (const r of found) refs.push({ route, frame: where, tag: r.tag, attribute: r.attribute, url: redact(r.url) });
  }
  return refs;
}
