// Bun security scanner for trustdiff.
//
// "bun install" hands every package it is about to fetch to the scanner named in
// bunfig.toml before it writes anything to disk. This module is that scanner. It runs
// the trustdiff binary in check mode over those packages and turns trustdiff findings
// into the advisories Bun understands, so a trust regression stops the install instead
// of being noticed after the fact.
//
// Bun's Security Scanner API was verified on 2026-09-10 against these sources, and
// nothing in this file is written from memory or from a second-hand description:
//   1. https://bun.com/docs/pm/security-scanner-api, for the bunfig.toml key.
//   2. https://github.com/oven-sh/security-scanner-template, the official template,
//      for the module layout, the test style and the package.json shape.
//   3. packages/bun-types/security.d.ts in oven-sh/bun, for the type declarations.
//   4. src/install/PackageManager/scanner-entry.ts in oven-sh/bun, the shim Bun runs
//      in a subprocess to load a scanner. It is the real contract, so it wins wherever
//      the prose and the code could be read differently.
//
// What that shim requires, and therefore what this file provides:
//   * The module has a named export called "scanner" that is an object. The shim reads
//     (await import(module)).scanner, so a default export alone is never seen.
//   * scanner.version is the string "1". The shim sends INVALID_VERSION and stops the
//     install for any other value.
//   * scanner.scan is a function taking { packages } and returning a promise of an
//     array. Anything else is a SCAN_FAILED error and the install stops.
//   * Every entry in packages carries name, version, tarball and requestedRange, and
//     the list includes transitive dependencies, not only what the user typed.
//   * Every advisory carries level, package, url and description. url and description
//     may be null; level is "fatal" or "warn" and nothing else.
//   * Bun prints every advisory. If any is fatal it cancels the install at once with a
//     non-zero exit code. Otherwise, if any is a warning, it asks on a TTY and cancels
//     everywhere else, which includes CI.
//   * If scan throws, Bun cancels the install as a defensive measure. This module uses
//     that on purpose: a scan that could not be completed must never look like a pass.
//
// Bun has no level for "I do not know", so that same rule has to be applied by hand to
// everything trustdiff could not answer: a package Bun resolved no version for, a package
// every check was skipped on, and a run whose exit code says a required data source was
// unavailable. Each of those becomes an advisory of its own rather than an absence,
// because an absence in the returned list is indistinguishable from a clean report.
//
// The package has no dependencies, not even @types/bun, so that installing it pulls in
// nothing and its tests run with no network. That is why the Bun types below are copied
// out of security.d.ts instead of imported.

/**
 * BunPackage is one package Bun proposes to install. It exists because scan receives a
 * list of these and this module has to read the name and the version off each one to
 * build a trustdiff ref. The fields are those of Bun.Security.Package.
 */
export interface BunPackage {
  /** The package name as the registry spells it, for example "express" or "@types/node". */
  name: string;
  /** The exact version Bun resolved from the requested range, never a range itself. */
  version: string;
  /** The URL of the tarball Bun would download. This scanner does not fetch it. */
  tarball: string;
  /** What the command asked for: a tag such as "beta", or a semver range such as ">=4.0.0". */
  requestedRange: string;
}

/**
 * AdvisoryLevel is the severity Bun accepts on an advisory. It exists as a named type
 * because the two values decide what happens to the install, and no third value is
 * allowed: Bun rejects the whole result when it sees one.
 */
export type AdvisoryLevel = "fatal" | "warn";

/**
 * BunAdvisory is one thing this scanner has to say about one package. It exists because
 * it is the only channel Bun gives a scanner: the level decides whether the install
 * stops, and the other three fields are what the user reads in the terminal. The shape
 * is that of Bun.Security.Advisory.
 */
export interface BunAdvisory {
  /** Fatal cancels the install at once; warn asks on a TTY and cancels everywhere else. */
  level: AdvisoryLevel;
  /** The package the advisory is about, so Bun can point at it in the dependency tree. */
  package: string;
  /** Where the user can read more, or null when there is nothing to link to. */
  url: string | null;
  /** The sentence Bun prints under the package name, or null when there is nothing to say. */
  description: string | null;
}

/**
 * BunScanner is the object Bun loads out of this module. It exists so that the export
 * below is checked against the contract at the point it is written rather than at the
 * point Bun refuses to run it, which happens in the middle of somebody's install.
 */
export interface BunScanner {
  /** The scanner API revision this module implements. Bun accepts only "1" today. */
  version: "1";
  /** The hook Bun calls once per install with every package it proposes to fetch. */
  scan: (info: { packages: BunPackage[] }) => Promise<BunAdvisory[]>;
}

/**
 * TrustdiffLevel is the effective level of a trustdiff finding after the policy has been
 * applied. It exists because the mapping to Bun advisory levels is the one decision this
 * adapter really makes, and it should be readable in one place.
 */
export type TrustdiffLevel = "block" | "warn" | "info";

/**
 * TrustdiffFinding is one result of one trustdiff check for one package version. It
 * exists so the mapping below reads against named fields instead of against untyped JSON.
 * Only the fields this scanner uses are listed. Within schema version 1 trustdiff adds
 * fields and never renames or removes them, so ignoring the rest stays safe.
 */
export interface TrustdiffFinding {
  /** Stable check identifier such as TD002, used for the message and the docs link. */
  id: string;
  /** The check's policy name such as publisher-changed, used for the same two things. */
  name: string;
  /** The level the policy settled on. Checks turned off produce no finding at all. */
  level: TrustdiffLevel;
  /** Which package version the finding is about. */
  ref: { ecosystem?: string; name?: string; version?: string };
  /** One line suitable for a terminal. */
  title: string;
  /** The human account of the evidence behind the title. */
  explanation: string;
}

/**
 * TrustdiffSkip is one check that could not run for one package version. It exists
 * because a skip is the whole difference between "checked and clean" and "not checked",
 * and this adapter has to tell the two apart before it decides what to tell Bun.
 */
export interface TrustdiffSkip {
  /** Id of the check that did not run, for example TD012. */
  check: string;
  /** Why it did not run: an unavailable data source, offline mode, or an ecosystem it does not cover. */
  reason: string;
}

/**
 * TrustdiffSubject is one evaluated package version with everything the checks said about
 * it. It exists as a named type because this adapter reads three of its fields and used to
 * read only findings, which is how a package nothing could be checked on came out looking
 * exactly like a package everything passed on.
 */
export interface TrustdiffSubject {
  /** Which package version the entry is about. */
  ref?: { ecosystem?: string; name?: string; version?: string };
  /** Checks that could not run for this subject, sorted by check id. */
  skipped?: TrustdiffSkip[];
  /** Findings sorted by level, most severe first. */
  findings?: TrustdiffFinding[];
  /** The highest finding level, ok when every check that ran found nothing, skipped when none ran. */
  verdict?: string;
}

/**
 * TrustdiffSummary is the tail of the document: the counts and the exit code. This adapter
 * reads the exit code out of the document rather than only off the process, because one
 * install can take several runs and each of them has to be judged by what it said.
 */
export interface TrustdiffSummary {
  /** Number of skipped checks over all subjects. */
  skipped?: number;
  /** 0 nothing at or above fail_on, 1 something was, 3 a required data source was unavailable. */
  exit_code?: number;
}

/**
 * TrustdiffReport is the document "trustdiff check --format json" writes on stdout, as
 * schema/report.v1.json defines it. It exists so that parsing can assert the shape it
 * depends on and refuse anything else, rather than reading fields off whatever happened
 * to be printed.
 */
export interface TrustdiffReport {
  /** Always REPORT_SCHEMA for a document this scanner will read. */
  schema: string;
  /** One entry per evaluated package version, each carrying its own findings and skips. */
  subjects: TrustdiffSubject[];
  /** The counts and the exit code of the run that wrote the document. */
  summary?: TrustdiffSummary;
}

/**
 * ScannerConfig is everything a project can change about how this scanner behaves. It
 * exists as a separate value so the settings can be read once, tested on their own, and
 * described in one place in the README.
 */
export interface ScannerConfig {
  /** The binary to run: a bare name looked up on PATH, or a path used as given. */
  binary: string;
  /** Whether a missing binary stops the install instead of being reported and skipped. */
  requireBinary: boolean;
  /** How long one trustdiff run may take before it is killed and the install stops. */
  timeoutMs: number;
  /** What a package trustdiff could not check at all counts as. */
  unchecked: UncheckedPolicy;
}

/**
 * UncheckedPolicy says what this scanner does about a package trustdiff could not check at
 * all. It exists because Bun has two levels and neither of them means "unknown", so every
 * project has to decide which one an unknown counts as: fatal for a repository that has
 * decided every install is checked in full, warn for everybody else, and ignore for the
 * rare project that installs on a machine where some data source is never reachable and
 * has accepted what that means.
 */
export type UncheckedPolicy = "fatal" | "warn" | "ignore";

/**
 * ENV_BINARY names the variable that points at the trustdiff binary. It exists so a
 * project can use a binary that is not on PATH, for example one vendored into the
 * repository or installed by a CI step into a private directory.
 */
export const ENV_BINARY = "TRUSTDIFF_BIN";

/**
 * ENV_REQUIRE_BINARY names the variable that turns a missing binary from a skip into a
 * failure. It exists because the safe default for a developer laptop (say so, install
 * nothing, scan nothing) is the wrong default for a repository that has decided every
 * install must be scanned, and that repository needs a way to insist.
 */
export const ENV_REQUIRE_BINARY = "TRUSTDIFF_BUN_REQUIRE_BINARY";

/**
 * ENV_TIMEOUT_MS names the variable that bounds one trustdiff run. It exists so that a
 * slow registry or a very large dependency tree cannot leave an install hanging with no
 * way out short of killing the terminal.
 */
export const ENV_TIMEOUT_MS = "TRUSTDIFF_BUN_TIMEOUT_MS";

/**
 * ENV_UNCHECKED names the variable that sets what an unchecked package counts as. It
 * exists because the honest answer, "nobody knows about this one", lands differently in a
 * repository that installs from a private mirror than on a laptop behind a hotel network,
 * and the scanner is in no position to decide which of those it is running on.
 */
export const ENV_UNCHECKED = "TRUSTDIFF_BUN_UNCHECKED";

/**
 * DEFAULT_UNCHECKED reports an unchecked package as a warning. Bun asks about a warning on
 * a terminal and cancels everywhere else, which is the right shape for something nobody
 * knows: a person gets to look at it, and CI does not go ahead on an unchecked package.
 */
export const DEFAULT_UNCHECKED: UncheckedPolicy = "warn";

/**
 * DEFAULT_BINARY is what this scanner runs when nothing points it elsewhere. It exists
 * as a constant because it is also the name the README tells people to install.
 */
export const DEFAULT_BINARY = "trustdiff";

/**
 * DEFAULT_TIMEOUT_MS bounds one trustdiff run when the project has not said otherwise.
 * Two minutes is long enough for a cold cache over a few hundred packages and short
 * enough that a wedged process is noticed rather than waited out.
 */
export const DEFAULT_TIMEOUT_MS = 120000;

/**
 * REPORT_SCHEMA is the value of the schema field in the document this scanner reads. It
 * exists because a document without it is not a trustdiff report, and reading findings
 * out of some other program's JSON would be worse than reading none.
 */
export const REPORT_SCHEMA = "trustdiff.report/1";

/**
 * REPORT_EXIT_CODES are the exit codes of "trustdiff check" that come with a report on
 * stdout: 0 no blocking findings, 1 findings at or above the fail-on level, 3 a required
 * data source was unavailable. It exists because exit code 1 is the normal outcome for a
 * package worth blocking and must not be mistaken for the tool having crashed. Exit code
 * 2 is a usage or configuration error and is never accompanied by a document.
 */
export const REPORT_EXIT_CODES: readonly number[] = [0, 1, 3];

/**
 * EXIT_DATA_UNAVAILABLE is the exit code that says a required data source was unavailable
 * and the policy trustdiff ran under asked for that to fail the run. It exists as its own
 * constant because it is the one report-bearing exit code that must never be read as a
 * normal outcome: the project already decided, in its own policy file, that a run it could
 * not complete is a failure, and this scanner only has to carry that decision through.
 */
export const EXIT_DATA_UNAVAILABLE = 3;

/**
 * CHECKS_DOC is where every trustdiff check is written up, one section per check. It
 * exists so an advisory can link the reader to the explanation of the check that fired
 * rather than to the project front page.
 */
export const CHECKS_DOC = "https://github.com/vahapogut/trustdiff/blob/main/docs/checks.md";

/**
 * INSTALL_DOC is where the README explains how to install and verify the binary. It
 * exists so the message printed when the binary is missing ends with something the
 * reader can act on.
 */
export const INSTALL_DOC = "https://github.com/vahapogut/trustdiff#install";

// MAX_REFS_PER_RUN and MAX_ARGV_CHARS split a large install across several trustdiff
// runs. A single "bun install" can propose thousands of packages, and Windows caps a
// command line at 32767 characters, so passing every ref at once would fail on the
// biggest trees, which are exactly the ones worth scanning. Both limits are deliberately
// well under the operating system ones, because the operating system counts the binary
// path and the environment too.
const MAX_REFS_PER_RUN = 100;
const MAX_ARGV_CHARS = 8000;

/**
 * BinaryNotFoundError says that the trustdiff binary could not be found or started. It
 * exists as its own type because it is the one failure this scanner is allowed to shrug
 * off: every other failure means the scan did not happen and the install must stop,
 * while a missing binary on a machine that never installed one is a configuration gap,
 * not a security event, unless the project has said it is.
 */
export class BinaryNotFoundError extends Error {
  /** The binary name or path that could not be run, so the message can name it. */
  readonly binary: string;

  constructor(binary: string) {
    super(
      `trustdiff bun scanner: the trustdiff binary ${JSON.stringify(binary)} was not found, so no package was scanned. ` +
        `Install it (${INSTALL_DOC}) or set ${ENV_BINARY} to its full path. ` +
        `Set ${ENV_REQUIRE_BINARY}=1 to make a missing binary stop the install instead of skipping the scan.`,
    );
    this.name = "BinaryNotFoundError";
    this.binary = binary;
  }
}

/**
 * readConfig turns environment variables into the settings for one run. It exists as a
 * function of an explicit environment so the settings can be tested without touching the
 * process, and it refuses values it does not understand rather than falling back to a
 * default, because a typo in a variable that decides whether installs are scanned should
 * be loud.
 */
export function readConfig(env: Record<string, string | undefined> = process.env): ScannerConfig {
  const binary = (env[ENV_BINARY] ?? "").trim() || DEFAULT_BINARY;
  return {
    binary,
    requireBinary: readBoolean(env[ENV_REQUIRE_BINARY], ENV_REQUIRE_BINARY, false),
    timeoutMs: readPositiveInteger(env[ENV_TIMEOUT_MS], ENV_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
    unchecked: readUncheckedPolicy(env[ENV_UNCHECKED]),
  };
}

/**
 * UncheckedPackage is one package Bun proposed that never reached trustdiff. It exists so
 * the reason travels with the name: the scanner has to be able to say which package it
 * failed to ask about and why, and an empty result is not an answer to that.
 */
export interface UncheckedPackage {
  /** The package name as Bun spelled it, or the empty string when even that was missing. */
  name: string;
  /** Why no ref could be built for it, as one sentence for the terminal. */
  reason: string;
}

/**
 * RefPlan is the result of reading Bun's package list: the refs to ask trustdiff about,
 * and the packages that could not be turned into one.
 */
export interface RefPlan {
  /** Refs in the form npm:name@version, deduplicated, in the order Bun listed them. */
  refs: string[];
  /** Packages no ref could be built for, each with the reason. */
  unchecked: UncheckedPackage[];
}

/**
 * planRefs turns the packages Bun proposes into the refs "trustdiff check" takes and,
 * separately, into the list of packages it could not name. It exists because an entry
 * without an exact version cannot be checked at all: trustdiff would evaluate whatever is
 * published as latest, which is not what Bun is about to write to disk, and a finding
 * about the wrong version is worse than no finding. Dropping such an entry is right;
 * dropping it silently is not, which is why it comes back instead of vanishing.
 */
export function planRefs(packages: readonly BunPackage[] | undefined | null): RefPlan {
  const seen = new Set<string>();
  const refs: string[] = [];
  const unchecked: UncheckedPackage[] = [];
  for (const pkg of packages ?? []) {
    const name = typeof pkg?.name === "string" ? pkg.name.trim() : "";
    const version = typeof pkg?.version === "string" ? pkg.version.trim() : "";
    if (name === "" || version === "") {
      unchecked.push({
        name,
        reason:
          name === ""
            ? "bun listed it with no name, so there was nothing to ask trustdiff about"
            : "bun resolved no exact version for it, and asking about whichever version is latest would answer about different code",
      });
      continue;
    }
    const ref = `npm:${name}@${version}`;
    if (seen.has(ref)) continue;
    seen.add(ref);
    refs.push(ref);
  }
  return { refs, unchecked };
}

/**
 * refsFor is planRefs when only the refs are wanted, which is what building the command
 * line and splitting it into batches care about.
 */
export function refsFor(packages: readonly BunPackage[] | undefined | null): string[] {
  return planRefs(packages).refs;
}

/**
 * batchRefs splits the refs into command lines that no operating system will reject. It
 * exists so that scanning a large dependency tree degrades into several runs rather than
 * into a spawn failure, and it is exported so a test can prove the split happens without
 * building a thousand-package fixture.
 */
export function batchRefs(
  refs: readonly string[],
  maxRefs: number = MAX_REFS_PER_RUN,
  maxChars: number = MAX_ARGV_CHARS,
): string[][] {
  const batches: string[][] = [];
  let current: string[] = [];
  let chars = 0;
  for (const ref of refs) {
    const cost = ref.length + 1;
    if (current.length > 0 && (current.length >= maxRefs || chars + cost > maxChars)) {
      batches.push(current);
      current = [];
      chars = 0;
    }
    current.push(ref);
    chars += cost;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

/**
 * advisoryFor maps one trustdiff finding onto one Bun advisory, and this is where the
 * adapter's whole policy lives: a blocking finding is fatal and stops the install, a
 * warning is a warning, and anything lower is not reported at all. Info findings are
 * dropped because Bun has no level for them, and reporting an informational note as a
 * warning would cancel installs in CI over something trustdiff itself does not consider
 * actionable.
 */
export function advisoryFor(finding: TrustdiffFinding): BunAdvisory | null {
  const level = advisoryLevelFor(finding?.level);
  if (level === null) return null;
  const name = typeof finding?.ref?.name === "string" ? finding.ref.name.trim() : "";
  if (name === "") return null;
  return {
    level,
    package: name,
    url: checkDocURL(finding),
    description: describeFinding(finding),
  };
}

/**
 * advisoriesFrom collects the advisories from every report of a run: one per finding Bun
 * has a level for, and one per package the run could not answer about. It exists because
 * one install can take several trustdiff runs (see batchRefs) and Bun wants one flat list,
 * and it is exported so the mapping can be tested against a document without starting a
 * process.
 */
export function advisoriesFrom(
  reports: readonly TrustdiffReport[],
  unchecked: UncheckedPolicy = DEFAULT_UNCHECKED,
): BunAdvisory[] {
  const advisories: BunAdvisory[] = [];
  for (const report of reports) {
    // Exit code 3 is the run saying that a required data source was unavailable and that
    // the policy in force asked for that to fail. That decision was made by the project in
    // its own policy file, so it is carried through whatever this scanner is set to.
    const dataUnavailable = report?.summary?.exit_code === EXIT_DATA_UNAVAILABLE;
    for (const subject of report.subjects ?? []) {
      for (const finding of subject?.findings ?? []) {
        const advisory = advisoryFor(finding);
        if (advisory !== null) advisories.push(advisory);
      }
      const note = uncheckedAdvisory(subject, dataUnavailable, unchecked);
      if (note !== null) advisories.push(note);
    }
  }
  return advisories;
}

/**
 * advisoriesForUnchecked turns the packages that never reached trustdiff into advisories,
 * so a package Bun could not name is reported in the same place, and read by the same
 * pair of eyes, as a package that was checked and failed.
 */
export function advisoriesForUnchecked(
  packages: readonly UncheckedPackage[],
  policy: UncheckedPolicy = DEFAULT_UNCHECKED,
): BunAdvisory[] {
  if (policy === "ignore") return [];
  const advisories: BunAdvisory[] = [];
  for (const pkg of packages) {
    // An advisory reaches the user through a package name, so one that has no name has
    // nowhere to go in the returned list and is written to stderr by the caller instead.
    if (pkg.name === "") continue;
    advisories.push({
      level: policy,
      package: pkg.name,
      url: CHECKS_DOC,
      description: `trustdiff did not check ${pkg.name}: ${pkg.reason}.`,
    });
  }
  return advisories;
}

/**
 * parseReport reads one "trustdiff check --format json" document and refuses anything
 * that is not one. It exists because silently accepting unrecognised output would turn a
 * broken or replaced binary into a clean bill of health, which is the one outcome a
 * security scanner must never produce by accident.
 */
export function parseReport(stdout: string): TrustdiffReport {
  let document: unknown;
  try {
    document = JSON.parse(stdout);
  } catch (error) {
    throw new Error(
      `trustdiff bun scanner: check did not write a JSON report on stdout: ${messageOf(error)}. ` +
        `Read it as ${JSON.stringify(excerpt(stdout))}.`,
    );
  }
  if (typeof document !== "object" || document === null) {
    throw new Error(`trustdiff bun scanner: the report on stdout is ${typeName(document)}, not an object.`);
  }
  const report = document as Partial<TrustdiffReport>;
  if (report.schema !== REPORT_SCHEMA) {
    throw new Error(
      `trustdiff bun scanner: the report on stdout says schema ${JSON.stringify(report.schema ?? null)}, ` +
        `and this scanner reads ${REPORT_SCHEMA}. Upgrade the scanner or the binary so the two agree.`,
    );
  }
  if (!Array.isArray(report.subjects)) {
    throw new Error("trustdiff bun scanner: the report on stdout has no subjects array.");
  }
  return report as TrustdiffReport;
}

/**
 * scanner is what Bun loads out of this package. The name is not a choice: Bun's loader
 * reads the "scanner" property of the imported module and fails the install when it is
 * missing, so this export is the whole public surface as far as bun install is concerned.
 */
export const scanner: BunScanner = {
  version: "1",
  scan: scanPackages,
};

// scanPackages is the body of scanner.scan, kept separate only so the export above reads
// as the small declaration it is.
async function scanPackages({ packages }: { packages: BunPackage[] }): Promise<BunAdvisory[]> {
  const config = readConfig();
  const plan = planRefs(packages);
  reportNameless(plan.unchecked);
  const advisories = advisoriesForUnchecked(plan.unchecked, config.unchecked);
  // An install that resolves to nothing new still calls the scanner. Starting a process
  // to ask about no packages would slow every no-op install down for nothing.
  if (plan.refs.length === 0) return advisories;

  const reports: TrustdiffReport[] = [];
  try {
    for (const batch of batchRefs(plan.refs)) {
      reports.push(await runCheck(batch, config));
    }
  } catch (error) {
    if (error instanceof BinaryNotFoundError && !config.requireBinary) {
      // Skipped, and said out loud. Bun shows the scanner's stderr, so the person running
      // the install learns that nothing was checked instead of assuming it was clean. The
      // advisories built above are dropped with it: naming the one package that had no
      // version, on a run where no package was checked at all, would be a strange thing
      // to single out.
      console.error(error.message);
      return [];
    }
    // Throwing cancels the install, which is the right outcome, but Bun shows an exception
    // and not a returned list, so everything the runs that did finish found would go with
    // it. A blocking finding from the second batch of five is worth reading even when the
    // third batch is the reason the install stopped.
    reportUnread(advisoriesFrom(reports, config.unchecked));
    throw error;
  }
  reportPartialSkips(reports);
  return [...advisories, ...advisoriesFrom(reports, config.unchecked)];
}

// runCheck runs the binary once over one batch of refs and returns the report it wrote.
// The argv is fixed and no shell is involved, so a package name can never be read as a
// flag or as a shell word; "--" separates the refs from the flags for the same reason.
async function runCheck(refs: readonly string[], config: ScannerConfig): Promise<TrustdiffReport> {
  const binary = resolveBinary(config.binary);
  if (binary === null) throw new BinaryNotFoundError(config.binary);

  const startedAt = Date.now();
  let child: ReturnType<typeof Bun.spawn>;
  try {
    child = Bun.spawn([binary, "check", "--format", "json", "--", ...refs], {
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      timeout: config.timeoutMs,
      killSignal: "SIGKILL",
    });
  } catch (error) {
    // A bare name that PATH does not resolve, or a path that is not there any more.
    if (isNotFound(error)) throw new BinaryNotFoundError(config.binary);
    throw new Error(`trustdiff bun scanner: could not start ${JSON.stringify(binary)}: ${messageOf(error)}`);
  }

  // stdout and stderr are drained together, because a report over a large tree can fill
  // a pipe buffer and a process blocked on a full pipe never exits.
  const [stdout, stderr] = await Promise.all([readAll(child.stdout), readAll(child.stderr)]);
  const code = await child.exited;

  // A process that ran out of time is killed with the signal above, so it ends with a
  // signal and no exit code of its own. Verified on Bun 1.4.2 on 2026-09-10 on Windows,
  // which has no real signals: the killed child still comes back with signalCode SIGKILL
  // and a null exitCode, so one test covers every platform. The elapsed time is a second
  // opinion for the cases the signal cannot describe, a child killed by something else or
  // one that lost the race and exited on its own, and it is read only when the run failed
  // another test too, so a run that finished correctly on the last millisecond of its
  // budget is still read as the success it was. The same run showed that killed is true
  // for any finished child, including one that exited normally, so it cannot be the test.
  const outOfTime = Date.now() - startedAt >= config.timeoutMs;
  if (child.signalCode !== null || child.exitCode === null) throw timedOut(binary, config);
  if (!REPORT_EXIT_CODES.includes(code)) {
    if (outOfTime) throw timedOut(binary, config);
    throw new Error(
      `trustdiff bun scanner: ${JSON.stringify(binary)} check exited with code ${code}. ` +
        `Its error output was ${JSON.stringify(excerpt(stderr))}.`,
    );
  }

  let report: TrustdiffReport;
  try {
    report = parseReport(stdout);
  } catch (error) {
    // A child killed in the middle of writing leaves a truncated document behind, and
    // "the report is not JSON" would send the reader looking for a bug that is not there.
    if (outOfTime) throw timedOut(binary, config);
    throw error;
  }
  // Everything downstream reads the exit code out of the summary, which is where trustdiff
  // repeats it. If the document and the process ever disagree, the more severe of the two
  // readings is the safe one: a run whose data source was unavailable must not be able to
  // read as a clean one because a field was missing.
  if (code === EXIT_DATA_UNAVAILABLE) {
    report.summary = { ...report.summary, exit_code: EXIT_DATA_UNAVAILABLE };
  }
  return report;
}

// timedOut is the error a run killed for taking too long produces, in one place because
// three different signs of it lead here.
function timedOut(binary: string, config: ScannerConfig): Error {
  return new Error(
    `trustdiff bun scanner: ${JSON.stringify(binary)} did not finish within ${config.timeoutMs} ms and was killed. ` +
      `Raise ${ENV_TIMEOUT_MS} if this tree is simply large.`,
  );
}

// uncheckedAdvisory reports a subject the run could not answer about. Two shapes count: a
// subject whose verdict is skipped, where not one check ran, and any subject with a skip
// in a run whose exit code says a required data source was unavailable. A subject that
// merely lost one check to an ecosystem that check does not cover is neither of them: the
// checks that did run did run, and stopping an install over every skip of that kind would
// make the scanner useless rather than careful.
function uncheckedAdvisory(
  subject: TrustdiffSubject | undefined,
  dataUnavailable: boolean,
  policy: UncheckedPolicy,
): BunAdvisory | null {
  const reported = subject?.skipped;
  const skipped = Array.isArray(reported) ? reported : [];
  const nothingRan = subject?.verdict === "skipped";
  if (!nothingRan && !(dataUnavailable && skipped.length > 0)) return null;
  const level: AdvisoryLevel | null = dataUnavailable ? "fatal" : policy === "ignore" ? null : policy;
  if (level === null) return null;
  const name = typeof subject?.ref?.name === "string" ? subject.ref.name.trim() : "";
  if (name === "") return null;
  const version = typeof subject?.ref?.version === "string" ? subject.ref.version.trim() : "";
  const target = version === "" ? name : `${name}@${version}`;
  const head = nothingRan
    ? `trustdiff could not check ${target}: not one check was able to run`
    : `trustdiff could not finish checking ${target}: a required data source was unavailable`;
  const reasons = skipped
    .map((skip) => describeSkip(skip))
    .filter((part) => part !== "")
    .join("; ");
  return {
    level,
    package: name,
    url: CHECKS_DOC,
    description: reasons === "" ? `${head}.` : `${head}. ${reasons}.`,
  };
}

// describeSkip writes one skipped check the way the terminal should read it, for example
// "TD012 the download counts were not available".
function describeSkip(skip: TrustdiffSkip | undefined): string {
  const check = typeof skip?.check === "string" ? skip.check.trim() : "";
  const reason = typeof skip?.reason === "string" ? skip.reason.trim().replace(/\.+$/, "").trim() : "";
  return [check, reason].filter((part) => part !== "").join(" ");
}

// reportNameless writes the packages that could not even be named to stderr, because an
// advisory reaches the user through a package name and these have none to give.
function reportNameless(packages: readonly UncheckedPackage[]): void {
  const count = packages.filter((pkg) => pkg.name === "").length;
  if (count === 0) return;
  console.error(
    `trustdiff bun scanner: bun listed ${plural(count, "package")} with no name, and none of them was checked.`,
  );
}

// reportPartialSkips says on stderr how much of the tree was checked only in part. These
// are not advisories: the checks that ran did run, and a check that does not cover an
// ecosystem is skipped on every package of that ecosystem, so an advisory each would bury
// the findings that matter. The count is still worth printing, because it is the whole
// difference between "everything was checked" and "most things were".
function reportPartialSkips(reports: readonly TrustdiffReport[]): void {
  let skips = 0;
  let affected = 0;
  let total = 0;
  for (const report of reports) {
    for (const subject of report.subjects ?? []) {
      total += 1;
      const reported = subject?.skipped;
      const skipped = Array.isArray(reported) ? reported.length : 0;
      if (skipped === 0 || subject?.verdict === "skipped") continue;
      skips += skipped;
      affected += 1;
    }
  }
  if (skips === 0) return;
  console.error(
    `trustdiff bun scanner: ${plural(skips, "check")} could not run, over ${affected} of ${plural(total, "package")}. ` +
      `Those packages were checked only in part. Run "trustdiff check" on them to read why.`,
  );
}

// reportUnread prints what the runs that finished found when the scan as a whole is about
// to throw, since Bun shows an exception and never the list that was being built.
function reportUnread(advisories: readonly BunAdvisory[]): void {
  if (advisories.length === 0) return;
  const count = advisories.length === 1 ? "1 advisory" : `${advisories.length} advisories`;
  const lines = advisories.map((advisory) => `  ${advisory.level}: ${advisory.description ?? advisory.package}`);
  console.error(
    `trustdiff bun scanner: the runs that finished before this failure found ${count}, which the install never saw:\n` +
      lines.join("\n"),
  );
}

// plural keeps these messages readable without reaching for a dependency.
function plural(count: number, noun: string): string {
  return count === 1 ? `1 ${noun}` : `${count} ${noun}s`;
}

// resolveBinary turns the configured binary into something spawnable, or null when there
// is nothing to spawn. A value that carries a separator is treated as a path and used as
// given, so a project can point at a binary outside PATH; a bare name goes through PATH,
// where Bun.which also applies the Windows executable extensions.
function resolveBinary(binary: string): string | null {
  if (binary.includes("/") || binary.includes("\\")) return binary;
  return Bun.which(binary);
}

// advisoryLevelFor is the level mapping on its own, so the table is one readable line
// per trustdiff level and the "anything else is not reported" rule is explicit.
function advisoryLevelFor(level: unknown): AdvisoryLevel | null {
  if (level === "block") return "fatal";
  if (level === "warn") return "warn";
  return null;
}

// checkDocURL builds the link to the section of docs/checks.md that explains the check
// that fired. The two patterns are the ones schema/report.v1.json enforces on the id and
// the name; anything that does not match them would produce a link to nowhere, so the
// advisory carries no URL instead of a broken one.
function checkDocURL(finding: TrustdiffFinding): string | null {
  const id = typeof finding?.id === "string" ? finding.id : "";
  const name = typeof finding?.name === "string" ? finding.name : "";
  if (!/^[A-Z]+[0-9]{3}$/.test(id)) return null;
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name)) return null;
  return `${CHECKS_DOC}#${id.toLowerCase()}-${name}`;
}

// describeFinding writes the sentence Bun prints under the package name. It names the
// check first, because "TD002 publisher-changed" is what the reader searches for in the
// docs and in the policy file, and then repeats trustdiff's own words rather than
// inventing new ones.
function describeFinding(finding: TrustdiffFinding): string | null {
  const name = typeof finding?.ref?.name === "string" ? finding.ref.name : "";
  const version = typeof finding?.ref?.version === "string" ? finding.ref.version : "";
  const subject = version === "" ? name : `${name}@${version}`;
  const id = typeof finding?.id === "string" ? finding.id : "";
  const check = typeof finding?.name === "string" ? finding.name : "";
  const title = typeof finding?.title === "string" ? finding.title : "";
  const explanation = typeof finding?.explanation === "string" ? finding.explanation : "";

  const head = [id, check].filter((part) => part !== "").join(" ");
  const parts = [head === "" ? "" : `${head} on ${subject}`, title, explanation === title ? "" : explanation];
  const sentence = parts
    .map((part) => part.trim().replace(/\.+$/, "").trim())
    .filter((part) => part !== "")
    .join(". ");
  return sentence === "" ? null : `${sentence}.`;
}

// readBoolean accepts the spellings people actually write and rejects the rest, so a
// value such as "treu" is an error the user sees rather than a silent false.
function readBoolean(raw: string | undefined, variable: string, fallback: boolean): boolean {
  const value = (raw ?? "").trim().toLowerCase();
  if (value === "") return fallback;
  if (["1", "true", "yes", "on"].includes(value)) return true;
  if (["0", "false", "no", "off"].includes(value)) return false;
  throw new Error(
    `trustdiff bun scanner: ${variable} is ${JSON.stringify(raw)}, which is neither true nor false. ` +
      "Use 1, true, yes, on, 0, false, no or off.",
  );
}

// readUncheckedPolicy reads the one setting with three values, and refuses the rest for
// the same reason readBoolean does: a typo in the variable that decides whether an
// unchecked package can stop an install must never be read as "ignore".
function readUncheckedPolicy(raw: string | undefined): UncheckedPolicy {
  const value = (raw ?? "").trim().toLowerCase();
  if (value === "") return DEFAULT_UNCHECKED;
  if (value === "fatal" || value === "warn" || value === "ignore") return value;
  throw new Error(
    `trustdiff bun scanner: ${ENV_UNCHECKED} is ${JSON.stringify(raw)}, which is none of fatal, warn or ignore.`,
  );
}

// readPositiveInteger is the same idea for the timeout: a value that is not a positive
// whole number of milliseconds is a mistake worth reporting, not a reason to guess.
function readPositiveInteger(raw: string | undefined, variable: string, fallback: number): number {
  const value = (raw ?? "").trim();
  if (value === "") return fallback;
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(
      `trustdiff bun scanner: ${variable} is ${JSON.stringify(raw)}, which is not a whole number of milliseconds.`,
    );
  }
  const parsed = Number(value);
  if (parsed <= 0) {
    throw new Error(`trustdiff bun scanner: ${variable} is ${JSON.stringify(raw)}, and it has to be above zero.`);
  }
  return parsed;
}

// isNotFound recognises the one spawn failure that means "there is no such binary".
// A permission failure is deliberately not included: a binary that is present but cannot
// be executed is a real problem and should stop the install.
function isNotFound(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { code?: unknown }).code === "ENOENT";
}

// readAll drains one of the child's pipes to a string.
async function readAll(stream: ReadableStream<Uint8Array> | undefined | null): Promise<string> {
  if (!stream) return "";
  return await new Response(stream).text();
}

// excerpt keeps an error message readable when the thing being quoted is a whole report
// or a long stack trace.
function excerpt(text: string, limit = 400): string {
  const trimmed = text.trim();
  return trimmed.length <= limit ? trimmed : `${trimmed.slice(0, limit)} ...`;
}

// messageOf gets a sentence out of a thrown value, which in JavaScript need not be an Error.
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// typeName names what was parsed when it was valid JSON but not an object, so the error
// says "the report on stdout is an array" rather than repeating the whole document.
function typeName(value: unknown): string {
  if (value === null) return "null";
  return Array.isArray(value) ? "an array" : `a ${typeof value}`;
}
