// Stub binaries for the scanner tests.
//
// The tests never run the real trustdiff binary. It talks to registries, it has to be
// built or downloaded first, and its output would change as advisories change, so a
// suite built on it would be slow, offline-hostile and flaky. Instead each test writes a
// tiny executable that prints a canned document and exits with a canned code, and points
// the scanner at it with TRUSTDIFF_BIN. What is under test is this adapter: the command
// line it builds, the documents it accepts, the levels it maps and what it does when the
// binary is absent or misbehaves.

import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, chmodSync } from "node:fs";
import { join, normalize } from "node:path";
import { tmpdir } from "node:os";

/**
 * StubBehaviour is what the fake binary should do when it is run. It exists so each test
 * reads as one sentence about the binary it is testing against: what it prints, what it
 * complains about and how it exits.
 */
export interface StubBehaviour {
  /** Bytes the stub writes to stdout, usually a trustdiff report document. */
  stdout?: string;
  /** Bytes the stub writes to stderr, so the failure tests can check the message carries it. */
  stderr?: string;
  /** Exit code the stub returns. Defaults to 0. */
  exitCode?: number;
}

/**
 * Stub is a fake trustdiff binary on disk plus the means to inspect how it was called.
 * It exists because two different things need checking: what the scanner does with the
 * output, and what command line it built to get it.
 */
export interface Stub {
  /** Path to give to TRUSTDIFF_BIN. */
  path: string;
  /** The arguments of the last run, as one line, or the empty string if it never ran. */
  args(): string;
  /** Whether the stub was run at all, which is how the empty-package-list test is proved. */
  ran(): boolean;
  /** Deletes the temporary directory. Call it from afterEach. */
  cleanup(): void;
}

/**
 * writeStub creates a fake trustdiff binary in a fresh temporary directory. It is a
 * batch file on Windows and a shell script everywhere else, because those are what the
 * two platforms can spawn directly, and the payloads live in separate files so no test
 * has to escape JSON for cmd.exe or for sh.
 */
export function writeStub(behaviour: StubBehaviour = {}): Stub {
  const dir = mkdtempSync(join(tmpdir(), "trustdiff-bun-scanner-"));
  const windows = process.platform === "win32";
  const outFile = normalize(join(dir, "stdout.txt"));
  const errFile = normalize(join(dir, "stderr.txt"));
  const argsFile = normalize(join(dir, "args.txt"));
  const path = normalize(join(dir, windows ? "trustdiff.cmd" : "trustdiff"));
  const code = behaviour.exitCode ?? 0;

  writeFileSync(outFile, behaviour.stdout ?? "");
  writeFileSync(errFile, behaviour.stderr ?? "");

  if (windows) {
    const lines = ["@echo off", `>"${argsFile}" echo %*`, `type "${outFile}"`];
    if ((behaviour.stderr ?? "") !== "") lines.push(`type "${errFile}" 1>&2`);
    lines.push(`exit /b ${code}`);
    writeFileSync(path, `${lines.join("\r\n")}\r\n`);
  } else {
    // Single quotes around the paths, because a temporary directory name is not something
    // this helper gets to inspect and sh would expand $ and backticks inside double ones.
    const lines = ["#!/bin/sh", `printf '%s\\n' "$*" > '${argsFile}'`, `cat '${outFile}'`];
    if ((behaviour.stderr ?? "") !== "") lines.push(`cat '${errFile}' >&2`);
    lines.push(`exit ${code}`);
    writeFileSync(path, `${lines.join("\n")}\n`);
    chmodSync(path, 0o755);
  }

  return {
    path,
    args: () => (existsSync(argsFile) ? readFileSync(argsFile, "utf8").trim() : ""),
    ran: () => existsSync(argsFile),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * report builds a trustdiff report document around the findings a test cares about. It
 * exists so a test can say "one blocking TD002 on express" without restating the twenty
 * other fields that schema/report.v1.json requires and this adapter never reads.
 */
export function report(findings: unknown[], overrides: Record<string, unknown> = {}): string {
  const document = {
    schema: "trustdiff.report/1",
    tool: { name: "trustdiff", version: "dev", commit: "none", date: "unknown", go_version: "go1.26.8" },
    policy: { path: "", cooldown: "3d", fail_on: "block" },
    subjects: [
      {
        ref: { ecosystem: "npm", name: "express", version: "4.19.2" },
        evaluated: ["TD001", "TD002"],
        skipped: [],
        findings,
        verdict: findings.length === 0 ? "ok" : "block",
      },
    ],
    summary: {
      subjects: 1,
      findings: { block: 0, warn: 0, info: 0 },
      skipped: 0,
      exit_code: 0,
      exit_meaning: "no blocking findings",
    },
    ...overrides,
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}

/**
 * finding builds one finding with the fields this adapter reads. It exists for the same
 * reason as report: the tests should show the level and the check under test and nothing
 * else.
 */
export function finding(level: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "TD002",
    name: "publisher-changed",
    level,
    ref: { ecosystem: "npm", name: "express", version: "4.19.2" },
    title: "published by an account that has not published this package before",
    explanation: "the previous 5 versions were published by dougwilson; 4.19.2 was published by ci-bot",
    ...overrides,
  };
}
