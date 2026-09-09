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
 * TrustdiffReport is the document "trustdiff check --format json" writes on stdout, as
 * schema/report.v1.json defines it. It exists so that parsing can assert the shape it
 * depends on and refuse anything else, rather than reading fields off whatever happened
 * to be printed.
 */
export interface TrustdiffReport {
  /** Always REPORT_SCHEMA for a document this scanner will read. */
  schema: string;
  /** One entry per evaluated package version, each carrying its own findings. */
  subjects: Array<{ findings?: TrustdiffFinding[] }>;
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
}

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
  };
}

/**
 * refsFor turns the packages Bun proposes into the refs "trustdiff check" takes, in the
 * form npm:name@version. It exists because Bun can list the same package version more
 * than once in a tree and because an entry without an exact version has to be dropped:
 * trustdiff would otherwise evaluate the latest published version, which is not the one
 * Bun is about to write to disk, and a finding about the wrong version is worse than no
 * finding at all.
 */
export function refsFor(packages: readonly BunPackage[] | undefined | null): string[] {
  const seen = new Set<string>();
  const refs: string[] = [];
  for (const pkg of packages ?? []) {
    const name = typeof pkg?.name === "string" ? pkg.name.trim() : "";
    const version = typeof pkg?.version === "string" ? pkg.version.trim() : "";
    if (name === "" || version === "") continue;
    const ref = `npm:${name}@${version}`;
    if (seen.has(ref)) continue;
    seen.add(ref);
    refs.push(ref);
  }
  return refs;
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
 * advisoriesFrom collects the advisories from every report of a run. It exists because
 * one install can take several trustdiff runs (see batchRefs) and Bun wants one flat
 * list, and it is exported so the mapping can be tested against a document without
 * starting a process.
 */
export function advisoriesFrom(reports: readonly TrustdiffReport[]): BunAdvisory[] {
  const advisories: BunAdvisory[] = [];
  for (const report of reports) {
    for (const subject of report.subjects ?? []) {
      for (const finding of subject?.findings ?? []) {
        const advisory = advisoryFor(finding);
        if (advisory !== null) advisories.push(advisory);
      }
    }
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
  const refs = refsFor(packages);
  // An install that resolves to nothing new still calls the scanner. Starting a process
  // to ask about no packages would slow every no-op install down for nothing.
  if (refs.length === 0) return [];

  const config = readConfig();
  const reports: TrustdiffReport[] = [];
  try {
    for (const batch of batchRefs(refs)) {
      reports.push(await runCheck(batch, config));
    }
  } catch (error) {
    if (error instanceof BinaryNotFoundError && !config.requireBinary) {
      // Skipped, and said out loud. Bun shows the scanner's stderr, so the person running
      // the install learns that nothing was checked instead of assuming it was clean.
      console.error(error.message);
      return [];
    }
    throw error;
  }
  return advisoriesFrom(reports);
}

// runCheck runs the binary once over one batch of refs and returns the report it wrote.
// The argv is fixed and no shell is involved, so a package name can never be read as a
// flag or as a shell word; "--" separates the refs from the flags for the same reason.
async function runCheck(refs: readonly string[], config: ScannerConfig): Promise<TrustdiffReport> {
  const binary = resolveBinary(config.binary);
  if (binary === null) throw new BinaryNotFoundError(config.binary);

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
  // signal and no exit code of its own. Verified on Bun 1.3.14 on 2026-09-10: killed is
  // true for any finished child, including one that exited normally, so it cannot be the
  // test here.
  if (child.signalCode !== null || child.exitCode === null) {
    throw new Error(
      `trustdiff bun scanner: ${JSON.stringify(binary)} did not finish within ${config.timeoutMs} ms and was killed. ` +
        `Raise ${ENV_TIMEOUT_MS} if this tree is simply large.`,
    );
  }
  if (!REPORT_EXIT_CODES.includes(code)) {
    throw new Error(
      `trustdiff bun scanner: ${JSON.stringify(binary)} check exited with code ${code}. ` +
        `Its error output was ${JSON.stringify(excerpt(stderr))}.`,
    );
  }
  return parseReport(stdout);
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
