# The doctor rules

`trustdiff doctor` reads the hardening settings your package managers already
support and says which are set, which are missing, and which are set to something
that does not do what the person who wrote it expected.

Every setting here is native to the package manager. trustdiff configures nothing of
its own and runs nothing at install time. What it does is find the eight or ten
places these settings live, judge each one against the cooldown your policy already
states, and, with `--fix`, write the ones that can be written without reformatting
your file.

## Why a scorecard and not a linter

The units disagree. The same three days is `3` for npm, `4320` for pnpm and Yarn,
`259200` for Bun, `P3D` for Deno and pip, and `"3 days"` for uv and Renovate. Nothing
warns you when you get it wrong, because every one of those is a valid number in
every one of those files. A person who writes `minimumReleaseAge = 10080` into
`bunfig.toml`, meaning a week the way pnpm counts, has asked Bun to wait 168 minutes,
and the install log says nothing at all.

So a row can be present and still hold less than you think, and the scorecard says
which:

```
bun 1.4.2  (version from the packageManager field of apps/native/package.json, apps/native)
  weak            DR030 bun-minimum-release-age  apps/native/bunfig.toml:3
      10080 is 168 minutes, and the policy asks for 3 days (259200 here). 10080 is 1 week in
      minutes, the unit pnpm and Yarn count in
```

That row is `weak` and not `wrong`, and the difference runs through the whole
command. Bun really does wait the 168 minutes the file asks for: the number is a
value Bun accepts and acts on, and whoever wrote it made a choice, even if they made
it by mistake. `wrong` is kept for the case where the manager will not do what the
file says at all, and those two get different treatment from `--fix`.

## Statuses

| Status | Meaning |
|---|---|
| `set` | the file holds a value that does what the rule asks, or the manager's own default already does |
| `wrong` | the manager will not do what the file says: a value it does not accept, or one it reads as something other than what is written |
| `weak` | the manager accepts the value and does exactly what it says, and what it says is less than the policy asks |
| `missing` | the file does not state the key |
| `unreadable` | the file exists and could not be read, or the value sits somewhere the writer will not touch |
| `advice` | the rule has no value to check and its sentence is the whole row: which packages may run a build script, what a manager offers instead of a setting it does not have |
| `not applicable` | this version of the manager does not have the setting, or a newer key replaced it |

`--ci` exits 1 on any `wrong`, `weak`, `missing` or `unreadable` at or above
`doctor.ci_min_severity`, which defaults to `warn`. `set`, `advice` and
`not applicable` never fail a gate.

## Which version a rule is judged against

A rule that exists only from a given version is judged by the version this project
runs, which is what a `packageManager` field, a committed Yarn release or the
manager on this machine answers. A lockfile format marker is not that: pnpm 10 and
pnpm 11 both write `lockfileVersion: '9.0'`, and npm 7 through 12 all write
`lockfileVersion: 3`. A marker gives a floor, and where the floor does not already
answer the question, the rule is judged as if the manager were current and the line
says so. A manager's own default is credited only against an exact version, because
a project pinned to pnpm 10 does not get pnpm 11's day of waiting.

## What `--fix` writes, and what it refuses

A fix replaces the lines that hold the value, or inserts the key where it belongs. It
never re-serializes the file, so your comments, your key order, your indentation and
your blank lines survive. [ADR 0003](adr/0003-config-edits.md) records why.

Before writing, the original is copied to `<file>.trustdiff-backup-<timestamp>` and
the change is printed as a unified diff. Running `--fix` twice changes nothing the
second time.

Four things it will not do:

- **A value that is already there.** `--fix` writes a key the file does not have and
  nothing else. A setting somebody wrote is theirs: a tool run over a repository it
  does not own has no business deciding they meant something different, and the one
  place it could be sure is where there is nothing to overwrite. A `weak` or a
  `wrong` row is reported, with the sentence that says what the value really does,
  and the line is left for a person to change.
- A rule whose answer is a judgment is reported and never written. Which packages may
  run a build script, which security scanner to trust, whether to turn hardened mode
  on: those are decisions, not values.
- A value inside a YAML anchor, an alias, a flow mapping that spans lines or a
  multi-line string is left alone with the reason on its line. A wrong write into a
  configuration file is worse than no write, because the setting looks present
  afterwards.
- A file that does not exist is created only where creating it means something. An
  `.npmrc` is created; a `package.json` is not.

## The rules

Every row was read against the linked documentation on the date in the last column.
The dates matter: all of these settings are younger than a year, two have already
changed their key name once, and one changed its default unit handling between minor
releases.

| Id | Manager | Setting | File | Unit | Since | Level |
|---|---|---|---|---|---|---|
| DR001 | npm | `min-release-age` | `.npmrc` | days | 11.10.0 | warn |
| DR002 | npm | `strict-allow-scripts` | `.npmrc` | boolean | 11.16.0 | warn |
| DR003 | npm | `allow-git` | `.npmrc` | `none`/`root`/`all` | 11.9.0 | info |
| DR004 | npm | `allow-remote` | `.npmrc` | `none`/`root`/`all` | 11.14.0 | info |
| DR005 | npm | `strict-npmrc` | `.npmrc` | boolean | 12.0.0 | info |
| DR010 | pnpm | `minimumReleaseAge` | `pnpm-workspace.yaml` | minutes | 10.16.0 | warn |
| DR011 | pnpm | `strictDepBuilds` | `pnpm-workspace.yaml` | boolean | 10.3.0 | warn |
| DR012 | pnpm | `allowBuilds` | `pnpm-workspace.yaml` | map | 10.26.0 | info |
| DR013 | pnpm | `onlyBuiltDependencies` | `pnpm-workspace.yaml` | list | 10.0.0 to 11 | info |
| DR014 | pnpm | `blockExoticSubdeps` | `pnpm-workspace.yaml` | boolean | 10.26.0 | info |
| DR015 | pnpm | `trustPolicy` | `pnpm-workspace.yaml` | `no-downgrade`/`off` | 10.21.0 | warn |
| DR020 | Yarn | `npmMinimalAgeGate` | `.yarnrc.yml` | minutes | 4.10.0 | warn |
| DR021 | Yarn | `enableScripts` | `.yarnrc.yml` | boolean | | warn |
| DR022 | Yarn | `checksumBehavior` | `.yarnrc.yml` | `throw`/`update`/`ignore`/`reset` | | warn |
| DR023 | Yarn | `enableHardenedMode` | `.yarnrc.yml` | boolean | | info |
| DR030 | Bun | `[install] minimumReleaseAge` | `bunfig.toml` | seconds | 1.3 | warn |
| DR031 | Bun | `[install.security] scanner` | `bunfig.toml` | package name | 1.3 | info |
| DR040 | Deno | `minimumDependencyAge` | `deno.json` | ISO 8601, minutes or a cutoff | 2.6 | warn |
| DR041 | Deno | `lock.frozen` | `deno.json` | boolean | | warn |
| DR042 | Deno | `lock` | `deno.json` | boolean or object | | warn |
| DR050 | uv | `exclude-newer` | `pyproject.toml`, `uv.toml` | words | 0.9.17 | warn |
| DR051 | uv | `audit.malware-check` | `pyproject.toml`, `uv.toml` | boolean | 0.11.31 | info |
| DR060 | pip | `uploaded-prior-to` | `pip.conf` | ISO 8601 | 26.1 | warn |
| DR061 | pip | `require-hashes` | `pip.conf` | boolean | | info |
| DR070 | Poetry | `solver.min-release-age` | `poetry.toml` | days | 2.4.0 | warn |
| DR080 | Cargo | none yet | | | | info |
| DR081 | Cargo | `registry.global-min-publish-age` | `.cargo/config.toml` | words, nightly only | | info |
| DR090 | Dependabot | `cooldown.default-days` | `.github/dependabot.yml` | days | | warn |
| DR100 | Renovate | `minimumReleaseAge` | `renovate.json` | words | | warn |
| DR110 | Actions | `uses:` pinned to a commit sha | `.github/workflows/*.yml` | | | warn |

## Notes that change what a row means

**npm counts whole days.** A cooldown shorter than a day rounds up to one.
`min-release-age-exclude`, from 11.17.0, takes the names and globs that skip the
wait. npm accepts the key beside an absolute `before` date and then follows `before`.

**npm warns about a key it does not recognize**, and has since 11.2, so a misspelled
setting is a line in an install log nobody reads. `strict-npmrc`, from npm 12, turns
that into a failure. Turn it on last: it fails on every unrecognized key in the file,
including one an older npm on another machine needs.

**pnpm reads these from `pnpm-workspace.yaml`, not from `.npmrc`.** pnpm reads only
authentication and registry settings from an `.npmrc`, so a `minimumReleaseAge`
written there does nothing at all. From pnpm 12, an unrecognized key in
`pnpm-workspace.yaml` fails the command when the project pins a pnpm version.

**pnpm 11 removed `onlyBuiltDependencies`** along with `neverBuiltDependencies` and
`ignoredBuiltDependencies`, in favour of `allowBuilds`, which arrived in 10.26 and
maps a package to true or false. doctor judges whichever key your pnpm version reads,
so a project on pnpm 10 is never told to write a key its pnpm rejects, and one on 11
is never told about a key that is gone.

**Yarn reads a bare number as minutes.** Yarn 4.11 and later also accept a duration
such as `3d`, and 4.10 silently ignores one, which is why the fix writes the number.
Yarn 4.15 raised the default to one day. `npmPreapprovedPackages` takes the packages
that skip the wait, and the gate can also be set per scope under `npmScopes`.

**Bun counts seconds**, the only manager here that does.

**Deno's `lock` key turns the lockfile itself on and off**, which is a different
thing from not freezing it: `"lock": false` means nothing pins what an install
fetches, and the frozen setting then has nothing to freeze. The object form,
`{"path": "deno.lock", "frozen": true}`, keeps it on and configures it. Neither is
written by a fix, because turning a lockfile back on changes what the next install
resolves.

**Deno takes several spellings**: an ISO 8601 duration, a bare number of minutes, an
absolute date, an RFC 3339 timestamp, `0` to turn the wait off, or an object with an
`age` and an `exclude` list. All of them are read as written, so a project that used
Deno's own minutes is told how long it waits rather than that it wrote the wrong
unit. A cutoff is a point in time where the policy asks for a length of one, so the
two are compared through the clock the run started on: what a cutoff buys today is
at least today minus the cutoff. The fix writes the ISO 8601 form, which cannot be
misread as another manager's unit. Deno 2.9 waits a day even with the key absent.

**uv measures upload time, not release date**, and resolves the duration into
`uv.lock` when the lock is written. The relative form arrived in 0.9.17; before that
the key took an absolute timestamp only. `exclude-newer-package` exempts named
packages.

**pip's configuration belongs to the machine**, not to the repository. A `pip.conf`
committed to a repository does nothing until `PIP_CONFIG_FILE` names it. In CI, pass
`--uploaded-prior-to P3D` or set `PIP_UPLOADED_PRIOR_TO`. pip 26.0 accepted an
absolute date only, and the wait applies only where the index reports upload times.

**Poetry reads `poetry.toml`, not `pyproject.toml`**, which is the mistake worth
catching: every other Poetry setting a person remembers lives in `pyproject.toml`.
`poetry config solver.min-release-age <days> --local` writes the same file.

**Cargo has no cooldown.** RFC 3923 was merged on 2026-05-18 and the implementation
is nightly only, behind `-Zmin-publish-age`. A `global-min-publish-age` in
`.cargo/config.toml` is accepted and ignored on a stable toolchain, so a project that
set it is not protected and has no way to tell. Until it lands, a Rust project's
defences are `cargo-deny`, `cargo-vet`, `cargo-audit` and `cargo install --locked`.

**Dependabot waits three days by default** on version updates, since 2026-07-14, and
never on security updates. The `cooldown` block goes inside each update block and
takes `default-days` between 1 and 90, so a repository usually has several. doctor
reports one line per update block and does not write them: where to insert a key in a
list somebody else ordered is not a judgment this tool makes.

**A workflow that names an action by a tag** runs whatever that tag points at today.
It is a dependency with no lockfile and the most access in the job. A local action
needs no pin, and a `docker://` image is pinned by its `@sha256:` digest: a tag on an
image moves exactly the way a tag on an action does. A `uses:` line inside a `run: |`
block is a line of a shell script and is not judged. The SLSA generator is the one published workflow
that must stay on a tag, because its verifier checks the reference of the workflow
that built an artifact; doctor reports it as pinned by design when it carries a full
version tag such as `@v2.1.0`, and as wrong when it carries a shortened one.
`doctor` never rewrites a tag into a sha: resolving it means asking GitHub which
commit to trust, which is a network call and a decision that belongs to a person.

## Turning a rule off

```yaml
doctor:
  ci_min_severity: warn
  rules:
    actions-sha-pin: off
    npm-strict-npmrc: info
  pin_exceptions:
    - "myorg/*"
```

A rule set to `off` is not evaluated and never appears in the scorecard. A rule given
a level is reported at that level, which is what `--ci` compares against.
