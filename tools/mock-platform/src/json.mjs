// Checks on the raw JSON text that JSON.parse cannot make: a key repeated in one object, and a
// number written with a fraction or an exponent (JSON Schema treats 214.0 as an integer, the
// statistics ingest does not). Answers the JSON pointer of the first offence, or null.
export function rawJsonOffence(text) {
  let i = 0;
  const ws = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i])) i += 1;
  };
  const escapePointer = (s) => s.replace(/~/g, '~0').replace(/\//g, '~1');
  const string = () => {
    const start = i;
    i += 1;
    while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    i += 1;
    return JSON.parse(text.slice(start, i));
  };
  let offence = null;
  const value = (path) => {
    ws();
    const c = text[i];
    if (c === '{') {
      i += 1;
      const seen = new Set();
      ws();
      if (text[i] === '}') {
        i += 1;
        return;
      }
      for (;;) {
        ws();
        const key = string();
        const at = `${path}/${escapePointer(key)}`;
        if (seen.has(key) && offence === null) offence = { path: at, reason: 'duplicate_key' };
        seen.add(key);
        ws();
        i += 1; // ':'
        value(at);
        ws();
        if (text[i] === ',') {
          i += 1;
          continue;
        }
        i += 1; // '}'
        return;
      }
    }
    if (c === '[') {
      i += 1;
      ws();
      if (text[i] === ']') {
        i += 1;
        return;
      }
      for (let n = 0; ; n += 1) {
        value(`${path}/${n}`);
        ws();
        if (text[i] === ',') {
          i += 1;
          continue;
        }
        i += 1; // ']'
        return;
      }
    }
    if (c === '"') {
      string();
      return;
    }
    const m = /^-?\d+(\.\d+)?([eE][+-]?\d+)?|^true|^false|^null/.exec(text.slice(i));
    if (!m) throw new SyntaxError('malformed JSON');
    if ((m[1] || m[2]) && offence === null) offence = { path, reason: 'non_integral_number' };
    i += m[0].length;
  };
  value('');
  return offence;
}
