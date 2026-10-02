#!/usr/bin/env node
/**
 * assert-call-log: the calls the mock platform recorded during a run equal what the mode allows.
 *
 *   positive_connect   exactly rows 1, 3, 4, 6, 7, 8 and 9
 *   positive_stats     row 17 (at least one accepted report), nothing else
 *   every_trigger      exactly the generated outbound-call list of the product
 *   positive_managed   after the operation was requested: the feed read (row 7) and the result
 *                      call (row 34) only
 *
 *   ever-egress-audit assert-call-log --mode <mode> --log <requests.jsonl|requests.json>
 *                     [--calls outbound-calls.json --product <p> --phase <n>] [--mark <n>]
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

export function loadModes(extra = {}) {
  const base = JSON.parse(readFileSync(join(here, 'modes.json'), 'utf8')).modes;
  return { ...base, ...extra };
}

/** The rows of the outbound-call table that apply to a product up to a phase. */
export function generatedRows(outboundCalls, product, { phase = 2, exclude = [] } = {}) {
  return outboundCalls.rows
    .filter((r) => r.products.includes(product) && r.phase <= phase && !exclude.includes(r.row))
    .map((r) => r.row)
    .sort((a, b) => a - b);
}

const resolveRows = (rows, generated) => (rows === 'generated' ? generated : rows);
const uniq = (rows) => [...new Set(rows)].sort((a, b) => a - b);

/**
 * Checks recorded entries ({row, status, ...}) against a mode. Answers {ok, problems, rows}.
 * `mark` is the index of the first entry after the mode's trigger (positive_managed).
 */
export function checkCallLog(entries, mode, { generated = [], mark = null } = {}) {
  const problems = [];
  const rows = entries.map((e) => e.row);
  const unknown = entries.filter((e) => e.row === null || e.row === undefined);
  for (const e of unknown) problems.push(`a call outside the outbound-call table: ${e.method} ${e.path_template}`);
  const allowed = resolveRows(mode.allowed_rows ?? [], generated);
  const required = resolveRows(mode.required_rows ?? [], generated);
  const seen = uniq(rows.filter((r) => r !== null && r !== undefined));
  for (const r of seen) if (!allowed.includes(r)) problems.push(`row ${r} is not allowed in this mode`);
  for (const r of required) if (!seen.includes(r)) problems.push(`row ${r} was required but never called`);
  if (mode.exact && JSON.stringify(seen) !== JSON.stringify(uniq(required)))
    problems.push(`the rows called (${seen.join(', ') || 'none'}) are not exactly ${uniq(required).join(', ')}`);
  if (required.includes(17) && !entries.some((e) => e.row === 17 && e.status === 202))
    problems.push('no statistics report was accepted (202)');
  if (mode.after_mark) {
    if (mark === null) problems.push('the mode trigger never ran (no mark in the call log)');
    else {
      const after = uniq(entries.slice(mark).map((e) => e.row));
      for (const r of after)
        if (!mode.after_mark.allowed_rows.includes(r))
          problems.push(`row ${r} was called after the trigger; only ${mode.after_mark.allowed_rows.join(', ')} may be`);
      for (const r of mode.after_mark.required_rows) if (!after.includes(r)) problems.push(`row ${r} was not called after the trigger`);
    }
  }
  return { ok: problems.length === 0, problems, rows: seen };
}

export function parseJsonl(text) {
  return text
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l));
}

export function main(argv) {
  const arg = (name) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const modes = loadModes();
  const mode = modes[arg('mode')];
  if (!mode || !arg('log')) {
    process.stderr.write(
      `assert-call-log: --mode <${Object.keys(modes).join('|')}> and --log <requests.jsonl|requests.json> are required\n`,
    );
    return 2;
  }
  const text = readFileSync(arg('log'), 'utf8');
  const entries = text.trimStart().startsWith('[') ? JSON.parse(text) : parseJsonl(text);
  let generated = [];
  if (arg('calls'))
    generated = generatedRows(JSON.parse(readFileSync(arg('calls'), 'utf8')), arg('product') ?? 'gauzy', {
      phase: Number(arg('phase') ?? 2),
    });
  const markAt = arg('mark') === undefined ? null : Number(arg('mark'));
  const r = checkCallLog(entries, mode, { generated, mark: markAt });
  if (!r.ok) {
    process.stderr.write(`assert-call-log: ${arg('mode')} failed:\n  ${r.problems.join('\n  ')}\n`);
    return 1;
  }
  process.stdout.write(`assert-call-log: ${arg('mode')} ok (rows ${r.rows.join(', ') || 'none'})\n`);
  return 0;
}

if (process.argv[1] && process.argv[1].endsWith('assert-call-log.mjs')) process.exit(main(process.argv.slice(2)));
