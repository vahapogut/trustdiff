// Stub binaries for the scanner tests.
//
// The tests never run the real trustdiff binary. It talks to registries, it has to be
// built or downloaded first, and its output would change as advisories change, so a
// suite built on it would be slow, offline-hostile and flaky. Instead each test writes a
// tiny executable that prints a canned document and exits with a canned code, and points
// the scanner at it with TRUSTDIFF_BIN. What is under test is this adapter: the command
// line it builds, the documents it accepts, the levels it maps and what it does when the
// binary is absent or misbehaves.
//
// A stub can also be given one behaviour per run, because a large install is split across
// several trustdiff runs and what the adapter does when the fourth one fails is only
// visible if the first three can succeed.

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
  /** Seconds to wait before writing anything, which is how the timeout is tested. */
  sleepSeconds?: number;
}

/**
 * Stub is a fake trustdiff binary on disk plus the means to inspect how it was called.
 * It exists because two different things need checking: what the scanner does with the
 * output, and what command line it built to get it.
 */
export interface Stub {
  /** Path to give to TRUSTDIFF_BIN. */
  path: string;
  /** The arguments of every run so far, one line each, or the empty string if it never ran. */
  args(): string;
  /** Whether the stub was run at all, which is how the empty-package-list test is proved. */
  ran(): boolean;
  /** How many times it was run, which is how the batching test tells one run from several. */
  runs(): number;
  /** Deletes the temporary directory. Call it from afterEach. */
  cleanup(): void;
}

/**
 * writeStub creates a fake trustdiff binary in a fresh temporary directory. It is a
 * batch file on Windows and a shell script everywhere else, because those are what the
 * two platforms can spawn directly, and the payloads live in separate files so no test
 * has to escape JSON for cmd.exe or for sh. Given a list of behaviours, the first run
 * takes the first, the second the second, and every run past the end repeats the last.
 */
export function writeStub(behaviour: StubBehaviour | StubBehaviour[] = {}): Stub {
  const runs = Array.isArray(behaviour) && behaviour.length > 0 ? behaviour : [behaviour].flat();
  const dir = mkdtempSync(join(tmpdir(), "trustdiff-bun-scanner-"));
  const windows = process.platform === "win32";
  const argsFile = normalize(join(dir, "args.txt"));
  const countFile = normalize(join(dir, "runs.txt"));
  const path = normalize(join(dir, windows ? "trustdiff.cmd" : "trustdiff"));
  const last = runs.length;

  runs.forEach((run, index) => {
    const n = index + 1;
    writeFileSync(normalize(join(dir, `stdout-${n}.txt`)), run.stdout ?? "");
    writeFileSync(normalize(join(dir, `stderr-${n}.txt`)), run.stderr ?? "");
    writeFileSync(normalize(join(dir, `code-${n}.txt`)), String(run.exitCode ?? 0));
    writeFileSync(normalize(join(dir, `sleep-${n}.txt`)), String(run.sleepSeconds ?? 0));
  });

  if (windows) {
    // The run counter is clamped at the last behaviour, so a fifth run of a two-behaviour
    // stub answers like the second one. ping is the sleep that cmd.exe does not have, and
    // it waits one second less than the count it is given.
    const file = (kind: string) => `${normalize(join(dir, kind))}-%n%.txt`;
    const lines = [
      "@echo off",
      "set n=0",
      `if exist "${countFile}" set /p n=<"${countFile}"`,
      "set /a n=n+1",
      `if %n% GTR ${last} set n=${last}`,
      `>"${countFile}" echo %n%`,
      `>>"${argsFile}" echo %*`,
      "set s=0",
      `set /p s=<"${file("sleep")}"`,
      "set /a p=s+1",
      `if not "%s%"=="0" ping -n %p% 127.0.0.1 >nul`,
      `type "${file("stdout")}"`,
      `type "${file("stderr")}" 1>&2`,
      "set code=0",
      `set /p code=<"${file("code")}"`,
      "exit /b %code%",
    ];
    writeFileSync(path, `${lines.join("\r\n")}\r\n`);
  } else {
    // Single quotes around the paths, because a temporary directory name is not something
    // this helper gets to inspect and sh would expand $ and backticks inside double ones.
    const file = (kind: string) => `'${normalize(join(dir, kind))}-'"$n"'.txt'`;
    const lines = [
      "#!/bin/sh",
      "n=0",
      `if [ -f '${countFile}' ]; then n=$(cat '${countFile}'); fi`,
      "n=$((n + 1))",
      `if [ "$n" -gt ${last} ]; then n=${last}; fi`,
      `echo "$n" > '${countFile}'`,
      `printf '%s\\n' "$*" >> '${argsFile}'`,
      `s=$(cat ${file("sleep")})`,
      'if [ "$s" != "0" ]; then sleep "$s"; fi',
      `cat ${file("stdout")}`,
      `cat ${file("stderr")} >&2`,
      `exit $(cat ${file("code")})`,
    ];
    writeFileSync(path, `${lines.join("\n")}\n`);
    chmodSync(path, 0o755);
  }

  const read = () => (existsSync(argsFile) ? readFileSync(argsFile, "utf8") : "");
  return {
    path,
    args: () => read().trim(),
    ran: () => existsSync(argsFile),
    runs: () =>
      read()
        .split("\n")
        .filter((line) => line.trim() !== "").length,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/**
 * subject builds one entry of the subjects array with the fields this adapter reads. It
 * exists because three of them, findings, skipped and verdict, together decide whether a
 * package counts as checked, and a test about one of them should not have to restate the
 * other two.
 */
export function subject(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ref: { ecosystem: "npm", name: "express", version: "4.19.2" },
    evaluated: ["TD001", "TD002"],
    skipped: [],
    findings: [],
    verdict: "ok",
    ...overrides,
  };
}

/**
 * skip builds one entry of a subject's skipped array, which is how the report says a check
 * did not run and why.
 */
export function skip(check: string, reason: string): Record<string, unknown> {
  return { check, reason };
}

/**
 * documentOf builds a whole report around the subjects a test cares about. It exists so a
 * test can write the one subject it is about and leave the envelope, which this adapter
 * mostly does not read, to this helper.
 */
export function documentOf(subjects: unknown[], summary: Record<string, unknown> = {}): string {
  const document = {
    schema: "trustdiff.report/1",
    tool: { name: "trustdiff", version: "dev", commit: "none", date: "unknown", go_version: "go1.26.8" },
    policy: { path: "", cooldown: "3d", fail_on: "block" },
    subjects,
    summary: {
      subjects: subjects.length,
      findings: { block: 0, warn: 0, info: 0 },
      skipped: 0,
      exit_code: 0,
      exit_meaning: "no blocking findings",
      ...summary,
    },
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}

/**
 * report builds a trustdiff report document around the findings a test cares about. It
 * exists so a test can say "one blocking TD002 on express" without restating the twenty
 * other fields that schema/report.v1.json requires and this adapter never reads.
 */
export function report(findings: unknown[], overrides: Record<string, unknown> = {}): string {
  const document = {
    ...JSON.parse(documentOf([subject({ findings, verdict: findings.length === 0 ? "ok" : "block" })])),
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
