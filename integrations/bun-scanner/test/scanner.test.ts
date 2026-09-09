// Tests for the trustdiff Bun security scanner.
//
// Everything here runs against a stub binary written by test/stub.ts, so the suite needs
// no network, no Go toolchain and no released trustdiff. Run it with "bun test" from
// integrations/bun-scanner.

import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import {
  advisoriesFrom,
  advisoryFor,
  batchRefs,
  BinaryNotFoundError,
  CHECKS_DOC,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_UNCHECKED,
  ENV_BINARY,
  ENV_REQUIRE_BINARY,
  ENV_TIMEOUT_MS,
  ENV_UNCHECKED,
  parseReport,
  planRefs,
  readConfig,
  refsFor,
  scanner,
  type BunPackage,
} from "../src/index.ts";
import { documentOf, finding, report, skip, subject, writeStub, type Stub } from "./stub.ts";

// The four variables the scanner reads. Each test starts with all of them cleared so no
// test can pass because of something another one left behind.
const VARIABLES = [ENV_BINARY, ENV_REQUIRE_BINARY, ENV_TIMEOUT_MS, ENV_UNCHECKED];

const saved = new Map<string, string | undefined>();
let stub: Stub | null = null;

beforeEach(() => {
  for (const name of VARIABLES) {
    saved.set(name, process.env[name]);
    delete process.env[name];
  }
});

afterEach(() => {
  for (const [name, value] of saved) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  saved.clear();
  stub?.cleanup();
  stub = null;
});

// pkg builds one of the entries Bun hands to the scanner. The tarball and the requested
// range are part of the payload Bun sends even though this adapter reads neither, so the
// fixtures carry them and stay honest about the shape.
function pkg(name: string, version: string): BunPackage {
  return {
    name,
    version,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    requestedRange: `^${version}`,
  };
}

// scanWith points the scanner at a stub with the given behaviour and runs one scan.
function scanWith(behaviour: Parameters<typeof writeStub>[0], packages: BunPackage[]) {
  stub = writeStub(behaviour);
  process.env[ENV_BINARY] = stub.path;
  return scanner.scan({ packages });
}

describe("the module Bun loads", () => {
  test("exports a scanner object at API version 1, which is what Bun's loader reads", () => {
    // Bun's scanner-entry shim does (await import(module)).scanner and rejects anything
    // whose version is not the string "1", so these two assertions are the contract.
    expect(typeof scanner).toBe("object");
    expect(scanner.version).toBe("1");
    expect(typeof scanner.scan).toBe("function");
  });
});

describe("a clean scan", () => {
  test("reports nothing when trustdiff found nothing", async () => {
    const advisories = await scanWith({ stdout: report([]) }, [pkg("express", "4.19.2")]);
    expect(advisories).toEqual([]);
  });

  test("runs check with json output and the refs after an end of options marker", async () => {
    await scanWith({ stdout: report([]) }, [pkg("express", "4.19.2"), pkg("@types/node", "22.5.0")]);
    const args = stub!.args();
    expect(args).toContain("check --format json --");
    expect(args).toContain("npm:express@4.19.2");
    // A scoped name keeps its @scope/ prefix, which is the spelling trustdiff refs use.
    expect(args).toContain("npm:@types/node@22.5.0");
  });

  test("reports nothing when trustdiff exits 1 but every finding is only informational", async () => {
    // Exit code 1 means findings at or above the fail-on level, which is a normal outcome
    // and not a crash. An info finding still has no Bun level, so nothing is reported.
    const advisories = await scanWith({ stdout: report([finding("info")]), exitCode: 1 }, [pkg("express", "4.19.2")]);
    expect(advisories).toEqual([]);
  });
});

describe("a blocking finding", () => {
  test("becomes a fatal advisory that names the check and links to its documentation", async () => {
    const advisories = await scanWith({ stdout: report([finding("block")]), exitCode: 1 }, [pkg("express", "4.19.2")]);
    expect(advisories).toHaveLength(1);
    expect(advisories[0]).toEqual({
      level: "fatal",
      package: "express",
      url: "https://github.com/vahapogut/trustdiff/blob/main/docs/checks.md#td002-publisher-changed",
      description:
        "TD002 publisher-changed on express@4.19.2. " +
        "published by an account that has not published this package before. " +
        "the previous 5 versions were published by dougwilson; 4.19.2 was published by ci-bot.",
    });
  });
});

describe("a warning finding", () => {
  test("becomes a warn advisory, which Bun prompts about on a TTY and cancels in CI", async () => {
    const advisories = await scanWith({ stdout: report([finding("warn")]), exitCode: 1 }, [pkg("express", "4.19.2")]);
    expect(advisories).toHaveLength(1);
    expect(advisories[0]!.level).toBe("warn");
    expect(advisories[0]!.package).toBe("express");
  });

  test("is reported alongside a blocking one, in the order the report listed them", async () => {
    const document = report([finding("block", { id: "TD009", name: "malicious-advisory" }), finding("warn")]);
    const advisories = await scanWith({ stdout: document, exitCode: 1 }, [pkg("express", "4.19.2")]);
    expect(advisories.map((a) => a.level)).toEqual(["fatal", "warn"]);
  });
});

describe("the binary is missing", () => {
  test("says so on stderr and lets the install go on, because that is a setup gap and not a finding", async () => {
    const errors = spyOn(console, "error").mockImplementation(() => {});
    try {
      process.env[ENV_BINARY] = "trustdiff-that-is-definitely-not-installed";
      const advisories = await scanner.scan({ packages: [pkg("express", "4.19.2")] });
      expect(advisories).toEqual([]);
      expect(errors).toHaveBeenCalledTimes(1);
      const message = String(errors.mock.calls[0]![0]);
      expect(message).toContain("was not found, so no package was scanned");
      expect(message).toContain(ENV_REQUIRE_BINARY);
    } finally {
      errors.mockRestore();
    }
  });

  test("is also handled when the configured path does not exist, not only a bare name", async () => {
    const errors = spyOn(console, "error").mockImplementation(() => {});
    try {
      process.env[ENV_BINARY] = `${import.meta.dir}/no-such-directory/trustdiff`;
      expect(await scanner.scan({ packages: [pkg("express", "4.19.2")] })).toEqual([]);
      expect(errors).toHaveBeenCalledTimes(1);
    } finally {
      errors.mockRestore();
    }
  });

  test("stops the install instead when the project insists on the scan", async () => {
    process.env[ENV_BINARY] = "trustdiff-that-is-definitely-not-installed";
    process.env[ENV_REQUIRE_BINARY] = "1";
    const promise = scanner.scan({ packages: [pkg("express", "4.19.2")] });
    await expect(promise).rejects.toThrow(BinaryNotFoundError);
    await expect(promise).rejects.toThrow(/was not found, so no package was scanned/);
  });
});

describe("the binary fails", () => {
  test("throws, which cancels the install, and carries the binary's own error output", async () => {
    // Exit code 2 is a usage or configuration error and comes with no document at all.
    const promise = scanWith({ stderr: "trustdiff: unknown flag --format\n", exitCode: 2 }, [pkg("express", "4.19.2")]);
    await expect(promise).rejects.toThrow(/exited with code 2/);
    await expect(promise).rejects.toThrow(/unknown flag/);
  });
});

describe("the document is malformed", () => {
  test("throws rather than treating unreadable output as a clean bill of health", async () => {
    const promise = scanWith({ stdout: "trustdiff: something went very wrong\n" }, [pkg("express", "4.19.2")]);
    await expect(promise).rejects.toThrow(/did not write a JSON report on stdout/);
  });

  test("throws when the JSON parses but is not a trustdiff report", async () => {
    const promise = scanWith({ stdout: '{"schema":"some.other.tool/2","subjects":[]}' }, [pkg("express", "4.19.2")]);
    await expect(promise).rejects.toThrow(/says schema/);
  });

  test("throws when the report has no subjects array", async () => {
    const promise = scanWith({ stdout: '{"schema":"trustdiff.report/1"}' }, [pkg("express", "4.19.2")]);
    await expect(promise).rejects.toThrow(/no subjects array/);
  });
});

describe("the package list is empty", () => {
  test("reports nothing and never starts a process", async () => {
    stub = writeStub({ stdout: report([]) });
    process.env[ENV_BINARY] = stub.path;
    expect(await scanner.scan({ packages: [] })).toEqual([]);
    expect(stub.ran()).toBe(false);
  });

  test("still starts no process when no entry has a resolved version, and says which ones", async () => {
    // Without an exact version trustdiff would evaluate whatever is published as latest,
    // which is not what Bun is about to install, so the entry cannot be checked. It is
    // reported rather than dropped, because a package nobody checked is not a clean one.
    stub = writeStub({ stdout: report([]) });
    process.env[ENV_BINARY] = stub.path;
    const packages = [{ ...pkg("express", "4.19.2"), version: "" }];
    const advisories = await scanner.scan({ packages });
    expect(advisories).toHaveLength(1);
    expect(advisories[0]!.level).toBe("warn");
    expect(advisories[0]!.package).toBe("express");
    expect(advisories[0]!.description).toContain("trustdiff did not check express");
    expect(stub.ran()).toBe(false);
  });
});

describe("a package trustdiff could not check", () => {
  test("is a warning by default, because bun has no level that means unknown", async () => {
    const advisories = await scanWith({ stdout: report([]) }, [{ ...pkg("express", "4.19.2"), version: "" }]);
    expect(advisories.map((advisory) => advisory.level)).toEqual(["warn"]);
    expect(advisories[0]!.url).toBe(CHECKS_DOC);
  });

  test("stops the install when the project has decided every install is checked in full", async () => {
    process.env[ENV_UNCHECKED] = "fatal";
    const advisories = await scanWith({ stdout: report([]) }, [{ ...pkg("express", "4.19.2"), version: "" }]);
    expect(advisories.map((advisory) => advisory.level)).toEqual(["fatal"]);
  });

  test("is dropped when the project has said it accepts unchecked packages", async () => {
    process.env[ENV_UNCHECKED] = "ignore";
    expect(await scanWith({ stdout: report([]) }, [{ ...pkg("express", "4.19.2"), version: "" }])).toEqual([]);
  });

  test("is reported when every check on it was skipped, which used to read as a clean pass", async () => {
    // This is the case the whole setting exists for: the report carries no finding, and
    // reading only the findings would make a package nothing could be checked on
    // byte-identical to a package that passed everything.
    const document = documentOf([
      subject({
        evaluated: [],
        skipped: [skip("TD002", "the registry did not answer"), skip("TD009", "the advisory database was unreachable")],
        verdict: "skipped",
      }),
    ]);
    const advisories = await scanWith({ stdout: document }, [pkg("express", "4.19.2")]);
    expect(advisories).toHaveLength(1);
    expect(advisories[0]!.level).toBe("warn");
    expect(advisories[0]!.package).toBe("express");
    expect(advisories[0]!.description).toContain("not one check was able to run");
    expect(advisories[0]!.description).toContain("TD002 the registry did not answer");
  });

  test("has its findings reported too when only some checks were skipped, with a note on stderr", async () => {
    // A check that does not cover an ecosystem is skipped on every package of it, so a
    // partial skip is normal and must not stop an install. The count still gets printed.
    const errors = spyOn(console, "error").mockImplementation(() => {});
    try {
      const document = documentOf([
        subject({ findings: [finding("block")], skipped: [skip("TD012", "no download counts")], verdict: "block" }),
      ]);
      const advisories = await scanWith({ stdout: document, exitCode: 1 }, [pkg("express", "4.19.2")]);
      expect(advisories.map((advisory) => advisory.level)).toEqual(["fatal"]);
      expect(String(errors.mock.calls[0]![0])).toContain("1 check could not run");
    } finally {
      errors.mockRestore();
    }
  });
});

describe("a run that could not reach a data source", () => {
  test("is fatal even where the scanner was told to ignore unchecked packages", async () => {
    // Exit code 3 only happens when the project's own trustdiff policy says an unavailable
    // source fails the run. That decision belongs to the policy, not to this adapter.
    process.env[ENV_UNCHECKED] = "ignore";
    const errors = spyOn(console, "error").mockImplementation(() => {});
    try {
      const document = documentOf(
        [subject({ skipped: [skip("TD009", "the advisory database was unreachable")], verdict: "ok" })],
        { exit_code: 3, exit_meaning: "a required data source was unavailable" },
      );
      const advisories = await scanWith({ stdout: document, exitCode: 3 }, [pkg("express", "4.19.2")]);
      expect(advisories).toHaveLength(1);
      expect(advisories[0]!.level).toBe("fatal");
      expect(advisories[0]!.description).toContain("a required data source was unavailable");
    } finally {
      errors.mockRestore();
    }
  });

  test("is fatal when the process said so and the document did not, which is the safe reading", async () => {
    const errors = spyOn(console, "error").mockImplementation(() => {});
    try {
      const document = documentOf([subject({ skipped: [skip("TD009", "offline")], verdict: "ok" })]);
      const advisories = await scanWith({ stdout: document, exitCode: 3 }, [pkg("express", "4.19.2")]);
      expect(advisories.map((advisory) => advisory.level)).toEqual(["fatal"]);
    } finally {
      errors.mockRestore();
    }
  });
});

describe("a run that takes too long", () => {
  test("is reported as the timeout it is, on a platform with signals and on one without", async () => {
    // Windows has no signals, so a killed child comes back with an ordinary exit code and
    // the elapsed time is the only thing that tells a timeout from a broken binary.
    process.env[ENV_TIMEOUT_MS] = "300";
    const promise = scanWith({ stdout: report([]), sleepSeconds: 3 }, [pkg("express", "4.19.2")]);
    await expect(promise).rejects.toThrow(/did not finish within 300 ms and was killed/);
  }, 20000);
});

describe("a failure after some runs finished", () => {
  test("prints what those runs found before it throws, so the findings do not go with the exception", async () => {
    const errors = spyOn(console, "error").mockImplementation(() => {});
    try {
      // Two batches: the first finds something worth blocking, the second cannot run at all.
      const packages = Array.from({ length: 150 }, (_, i) => pkg(`package-${i}`, "1.0.0"));
      const promise = scanWith(
        [
          { stdout: report([finding("block")]), exitCode: 1 },
          { stderr: "trustdiff: unknown flag --format\n", exitCode: 2 },
        ],
        packages,
      );
      await expect(promise).rejects.toThrow(/exited with code 2/);
      expect(stub!.runs()).toBe(2);
      const printed = errors.mock.calls.map((call) => String(call[0])).join("\n");
      expect(printed).toContain("the runs that finished before this failure found 1 advisory");
      expect(printed).toContain("TD002 publisher-changed on express@4.19.2");
    } finally {
      errors.mockRestore();
    }
  }, 20000);
});

describe("building refs and batches", () => {
  test("keeps every package it could not name, with the reason it could not", () => {
    const plan = planRefs([pkg("express", "4.19.2"), { ...pkg("lodash", "4.17.21"), version: "" }, pkg("", "1.0.0")]);
    expect(plan.refs).toEqual(["npm:express@4.19.2"]);
    expect(plan.unchecked.map((entry) => entry.name)).toEqual(["lodash", ""]);
    expect(plan.unchecked[0]!.reason).toContain("no exact version");
    expect(plan.unchecked[1]!.reason).toContain("no name");
  });

  test("drops duplicates and keeps the order Bun gave", () => {
    const packages = [pkg("express", "4.19.2"), pkg("express", "4.19.2"), pkg("lodash", "4.17.21")];
    expect(refsFor(packages)).toEqual(["npm:express@4.19.2", "npm:lodash@4.17.21"]);
  });

  test("splits a large tree into several command lines", () => {
    const refs = Array.from({ length: 250 }, (_, i) => `npm:package-${i}@1.0.0`);
    const batches = batchRefs(refs);
    expect(batches.length).toBeGreaterThan(1);
    expect(batches.flat()).toEqual(refs);
    expect(Math.max(...batches.map((b) => b.length))).toBeLessThanOrEqual(100);
  });

  test("splits on the character budget too, so a very long name cannot overflow a command line", () => {
    const refs = Array.from({ length: 10 }, (_, i) => `npm:${"n".repeat(200)}-${i}@1.0.0`);
    expect(batchRefs(refs, 100, 500).length).toBeGreaterThan(1);
  });
});

describe("mapping one finding", () => {
  test("carries no URL when the check id is not one the report schema allows", () => {
    const advisory = advisoryFor(finding("block", { id: "not-an-id" }) as never);
    expect(advisory!.url).toBeNull();
  });

  test("ignores a finding with no package name, because Bun has nothing to attach it to", () => {
    expect(advisoryFor(finding("block", { ref: {} }) as never)).toBeNull();
  });

  test("collects findings across every subject of every report", () => {
    const parsed = parseReport(report([finding("block"), finding("warn")]));
    expect(advisoriesFrom([parsed, parsed])).toHaveLength(4);
  });
});

describe("configuration", () => {
  test("falls back to the binary on PATH and a bounded run", () => {
    const config = readConfig({});
    expect(config.binary).toBe("trustdiff");
    expect(config.requireBinary).toBe(false);
    expect(config.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
  });

  test("accepts the spellings people write for the require switch", () => {
    expect(readConfig({ [ENV_REQUIRE_BINARY]: "true" }).requireBinary).toBe(true);
    expect(readConfig({ [ENV_REQUIRE_BINARY]: "ON" }).requireBinary).toBe(true);
    expect(readConfig({ [ENV_REQUIRE_BINARY]: "no" }).requireBinary).toBe(false);
  });

  test("refuses a value it cannot read, so a typo never quietly turns the scan off", () => {
    expect(() => readConfig({ [ENV_REQUIRE_BINARY]: "treu" })).toThrow(/neither true nor false/);
    expect(() => readConfig({ [ENV_TIMEOUT_MS]: "two minutes" })).toThrow(/not a whole number/);
    expect(() => readConfig({ [ENV_TIMEOUT_MS]: "0" })).toThrow(/above zero/);
    expect(() => readConfig({ [ENV_UNCHECKED]: "block" })).toThrow(/none of fatal, warn or ignore/);
  });

  test("warns about an unchecked package unless the project says otherwise", () => {
    expect(readConfig({}).unchecked).toBe(DEFAULT_UNCHECKED);
    expect(readConfig({ [ENV_UNCHECKED]: "FATAL" }).unchecked).toBe("fatal");
    expect(readConfig({ [ENV_UNCHECKED]: " ignore " }).unchecked).toBe("ignore");
  });
});
