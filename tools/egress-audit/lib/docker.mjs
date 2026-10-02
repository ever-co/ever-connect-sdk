// Thin wrappers around the docker CLI. Every call is synchronous and logged; a failing call throws a
// DockerError with the command and the last lines of its output (never the environment).
import { spawnSync } from 'node:child_process';

export class DockerError extends Error {
  constructor(args, r) {
    const tail = `${r.stderr ?? ''}${r.stdout ?? ''}`.trim().split('\n').slice(-12).join('\n');
    super(`docker ${args.slice(0, 6).join(' ')}${args.length > 6 ? ' ...' : ''} failed (exit ${r.status}):\n${tail}`);
    this.status = r.status;
    this.stderr = r.stderr;
  }
}

export function docker(args, { env, input, allowFail = false, timeoutS = 900, log } = {}) {
  log?.(`$ docker ${args.join(' ')}`);
  const r = spawnSync('docker', args, {
    env: env ?? process.env,
    input,
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
    timeout: timeoutS * 1000,
    windowsHide: true,
  });
  if (r.error) {
    if (r.error.code === 'ENOENT') throw new Error('the docker CLI is not installed or not on PATH');
    throw r.error;
  }
  if (r.status !== 0 && !allowFail) throw new DockerError(args, r);
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** A compose runner bound to a project and its files. */
export function composeRunner({ project, files, projectDirectory, env, log }) {
  const base = ['compose', '-p', project, '--project-directory', projectDirectory, ...files.flatMap((f) => ['-f', f])];
  return (args, opts = {}) => docker([...base, ...args], { env, log, ...opts });
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Polls `check` every `everyMs` until it answers a truthy value or `timeoutS` passes. */
export async function poll(check, { timeoutS, everyMs = 1000 }) {
  const until = Date.now() + timeoutS * 1000;
  for (;;) {
    const v = await check();
    if (v) return v;
    if (Date.now() >= until) return null;
    await sleep(everyMs);
  }
}
