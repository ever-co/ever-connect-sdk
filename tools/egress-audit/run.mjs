#!/usr/bin/env node
// ever-egress-audit: proves that an Ever Platform module host makes no outbound call it should not.
// See README.md. Exit codes: 0 pass, 1 a violation, 2 a harness fault or a usage error.
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const modes = JSON.parse(readFileSync(join(here, 'modes.json'), 'utf8')).modes;

const HELP = `ever-egress-audit - the egress audit of a product that hosts the Ever Platform modules

Usage:
  ever-egress-audit --config <egress-audit.config.json> --mode <mode> [--legs api,browser] [--artifacts <dir>] [--no-mock] [--keep] [--verbose]
  ever-egress-audit --selftest [--legs api,browser] [--artifacts <dir>] [--only <run>[,<run>]] [--verbose]
  ever-egress-audit assert --evidence <evidence.json> [--out <report.json>]
  ever-egress-audit assert-call-log --mode <mode> --log <requests.json> [--calls <outbound-calls.json> --product <p>] [--mark <n>]
  ever-egress-audit static-hostnames [--root <dir>] --allow-dirs <dir>[,<dir>] [--optin-hosts <file> | --config <file>] [--baseline <file>] [--all-files]
  ever-egress-audit cloud-inference --dirs <module dir>[,<module dir>]
  ever-egress-audit ui-routes --framework angular|next-app|solidstart --entry <path> --out <ui-routes.json> [--check]
  ever-egress-audit check-baseline-shrink --base <git ref> --config <egress-audit.config.json> [--first-version] (or --file <ui-baseline.json>)

Modes:
${Object.entries(modes)
  .map(([name, m]) => `  ${name.padEnd(17)} ${m.description}`)
  .join('\n')}
  (a product config may add its own modes)

Legs (--legs, default api,browser when the config names a web_service, else api):
  api              the product processes, each in its own sniffed namespace, the module routes and
                   the mock platform's call record
  browser          a Playwright browser in its own sniffed namespace signs in through the product UI,
                   walks every route of ui-routes.json, idles on the settings pages and records a HAR
                   and the DOM references (modes off, loaded_off, positive_stats); a run that leaves it
                   out of a config with a web_service faults (exit 2), so it never passes

The run seals every compose network of the product's compose files (internal, no route out), makes CoreDNS
the only resolver, captures every connection attempt and DNS query of each product process from
before it starts, drives the product from inside the sealed network and writes report.json with
the pcaps, the DNS log and the mock platform's call record.

No name of ever-hosts.json (the Ever-owned names and the analytics sinks, with every name under
them) can be allowed: allowed_external_hosts refuses it, and every capture check fails on it.

Exit codes: 0 pass; 1 a violation (a never-allowed host looked up, requested or linked, a connection
attempt out, a module route answering while off, a call outside the mode's rows, a missing positive
control); 2 a harness fault (for example CAP_NET_RAW refused, a page that never loaded) or a usage
error.
`;

function arg(argv, name) {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function main(argv) {
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(HELP);
    return 0;
  }
  const sub = argv[0];
  const rest = argv.slice(1);
  if (sub === 'assert') return (await import('./assert.mjs')).main(rest);
  if (sub === 'assert-call-log') return (await import('./assert-call-log.mjs')).main(rest);
  if (sub === 'static-hostnames') return (await import('./static-hostnames.mjs')).main(rest);
  if (sub === 'cloud-inference') return (await import('./cloud-inference.mjs')).main(rest);
  if (sub === 'ui-routes') return (await import('./routes/cli.mjs')).main(rest);
  if (sub === 'check-baseline-shrink') return (await import('./check-baseline-shrink.mjs')).main(rest);
  const args = sub === 'run' ? rest : argv;
  const verbose = args.includes('--verbose');
  const log = verbose ? (m) => process.stderr.write(`${m}\n`) : () => {};
  const artifactsDir = resolve(arg(args, 'artifacts') ?? 'egress-audit-artifacts');
  const legs = arg(args, 'legs')?.split(',').filter(Boolean);
  const { UsageError, loadConfig, runAudit } = await import('./lib/runner.mjs');
  try {
    if (args.includes('--selftest')) {
      const { selftest } = await import('./lib/selftest.mjs');
      const only = arg(args, 'only')?.split(',');
      const { ok } = await selftest({ artifactsDir, only, legs, log });
      return ok ? 0 : 1;
    }
    const configPath = arg(args, 'config');
    const mode = arg(args, 'mode');
    if (!configPath || !mode) {
      process.stderr.write('ever-egress-audit: --config and --mode are required (see --help)\n');
      return 2;
    }
    const { config, configDir } = loadConfig(configPath);
    const report = await runAudit({
      config,
      configDir,
      modeName: mode,
      noMock: args.includes('--no-mock'),
      artifactsDir: resolve(arg(args, 'artifacts') ?? (config.artifacts_dir ? resolve(configDir, config.artifacts_dir) : artifactsDir)),
      keep: args.includes('--keep'),
      legs,
      log,
    });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.stdout.write(
      `ever-egress-audit: ${mode} ${report.exit === 0 ? 'passed' : report.exit === 1 ? 'FAILED (violations)' : 'FAULT (unproven)'}\n`,
    );
    return report.exit;
  } catch (error) {
    process.stderr.write(`ever-egress-audit: ${error instanceof UsageError ? '' : 'harness fault: '}${error.message}\n`);
    return 2;
  }
}

process.exit(await main(process.argv.slice(2)));
