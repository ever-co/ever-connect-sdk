// The request record: one line per call a product made, never a body, a code, an assertion, a
// token or a secret. `--record <file>` appends JSON lines; GET /__mock/requests answers the list.
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { sha256Hex } from './crypto.mjs';

export class Recorder {
  constructor(file = null) {
    this.file = file;
    this.entries = [];
    if (file) {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, '');
    }
  }

  add({ ts, method, pathTemplate, row, status, userAgent, idempotencyKey, body }) {
    const entry = {
      ts,
      method,
      path_template: pathTemplate,
      row: row ?? null,
      status,
      user_agent: userAgent ?? null,
      idempotency_key: idempotencyKey ?? null,
      body_sha256: body && body.length > 0 ? sha256Hex(body) : null,
    };
    this.entries.push(entry);
    if (this.file) appendFileSync(this.file, `${JSON.stringify(entry)}\n`);
    return entry;
  }

  clear() {
    this.entries = [];
    if (this.file) writeFileSync(this.file, '');
  }
}
