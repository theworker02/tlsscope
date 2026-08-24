#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import { inspectTarget, parseTarget } from "./inspect.js";
import { evaluate } from "./policy.js";
import { toSarif } from "./sarif.js";
import { defaultPolicy, type Policy } from "./types.js";

function policyFrom(opts: {
  minDays: string;
  minProtocol: string;
  allowUnauthorized?: boolean;
}): Policy {
  return {
    minDaysRemaining: Number(opts.minDays),
    minProtocol: opts.minProtocol === "TLSv1.3" ? "TLSv1.3" : "TLSv1.2",
    requireAuthorization: !opts.allowUnauthorized,
  };
}

const program = new Command();
program
  .name("tlsscope")
  .description("Inspect TLS certificates and handshake policy. JSON or SARIF for CI.")
  .version("1.0.0");

program
  .command("inspect")
  .argument("<target>", "host, host:port, or https URL")
  .option("--timeout <ms>", "connect timeout", "10000")
  .option("-o, --out <file>", "write JSON report")
  .action(async (target: string, opts: { timeout: string; out?: string }) => {
    const { host, port } = parseTarget(target);
    const report = await inspectTarget(host, port, Number(opts.timeout));
    const json = `${JSON.stringify(report, null, 2)}\n`;
    if (opts.out) await writeFile(opts.out, json);
    process.stdout.write(json);
  });

program
  .command("check")
  .argument("<target>", "host, host:port, or https URL")
  .option("--min-days <n>", "warn/fail if leaf expires sooner", "14")
  .option("--min-protocol <p>", "TLSv1.2 or TLSv1.3", "TLSv1.2")
  .option("--allow-unauthorized", "do not fail on untrusted chains")
  .option("--sarif", "print SARIF 2.1 instead of JSON findings")
  .option("-o, --out <file>", "write report")
  .option("--timeout <ms>", "connect timeout", "10000")
  .action(
    async (
      target: string,
      opts: {
        minDays: string;
        minProtocol: string;
        allowUnauthorized?: boolean;
        sarif?: boolean;
        out?: string;
        timeout: string;
      },
    ) => {
      const { host, port } = parseTarget(target);
      const report = await inspectTarget(host, port, Number(opts.timeout));
      const findings = evaluate(report, policyFrom(opts));
      const body = opts.sarif
        ? `${JSON.stringify(toSarif(report, findings), null, 2)}\n`
        : `${JSON.stringify({ ok: findings.every((f) => f.severity !== "error"), host, port, protocol: report.protocol, findings }, null, 2)}\n`;
      if (opts.out) await writeFile(opts.out, body);
      process.stdout.write(body);
      if (findings.some((f) => f.severity === "error")) process.exitCode = 1;
    },
  );

program
  .command("policy")
  .description("Print the default policy JSON")
  .action(() => {
    process.stdout.write(`${JSON.stringify(defaultPolicy(), null, 2)}\n`);
  });

await program.parseAsync(process.argv);
