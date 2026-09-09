# The demo repository

`make demo` runs trustdiff on `testdata/demo-repo` and prints the human report. It
is the smallest complete example of what `diff` is for, the scenario the M2
acceptance criterion is measured on, and the scenario the README GIF records.

## What it shows

`testdata/demo-repo` holds one project on two branches. The base branch locks five
packages. The head branch is the same project after a pull request added one
dependency, `demo-crypto-helper` at 1.0.2, on line 32 of
`head/package-lock.json`. Nothing else changed, so `diff` evaluates that one entry
and leaves the other five alone: the point of the command is that a pull request
is judged by what it adds, not by everything the project already trusts.

The added version is two days old and runs an install script, which is the pair of
signals behind most of the npm supply chain incidents of the last years:

| Check | Level | Why it fires |
|---|---|---|
| TD001 `young-version` | warn | 1.0.2 was published on 2026-09-07, inside the default 3d cooldown of the pinned run clock |
| TD006 `install-script-present` | warn | 1.0.2 declares `postinstall`, which npm runs with the installing user's permissions |

TD005 `install-script-introduced` is the check that does not fire, and the report
says why: the registry fixture knows a single version, so there is no earlier
release to compare the script against. Every check that cannot be answered is
listed with its reason instead of passing quietly. That is worth as much in a demo
as the two findings.

Every package name in the demo is fictitious and `testdata/demo-repo/README.md`
describes each file, including the fixtures that supply the publish time and the
install script.

## The command

```
make demo
```

which runs, from the repository root:

```
TRUSTDIFF_NOW=2026-09-09T12:00:00Z TRUSTDIFF_CACHE_DIR=<a fresh temporary directory> \
go run ./cmd/trustdiff diff \
  --base-file testdata/demo-repo/base/package-lock.json \
  testdata/demo-repo/head/package-lock.json \
  --policy testdata/demo-repo/.trustdiff.yaml \
  --offline --format human
```

Four of those are what make the output reproducible rather than merely nice:

- `TRUSTDIFF_NOW` pins the run clock, so "published two days ago" stays true after
  the demo is a year old.
- `--offline` forbids every request. The one registry answer the run needs is
  seeded into the temporary cache directory from `testdata/demo-repo/cache`
  before the command starts, which is why no server has to be started and why the
  demo works on a laptop with no network.
- `TRUSTDIFF_CACHE_DIR` points at that throwaway directory, so the demo neither
  reads nor writes the developer's own cache, and the target removes it afterwards.
- `--policy` uses the demo's own policy file, which sets nothing but the version.
  The levels and the cooldown are the built-in defaults, and a user-level policy on
  the machine cannot change what the demo prints.

The target reports the tool's exit code rather than inheriting it, so a demo that
finds something never fails `make`. Today it exits 0: both findings are warnings
and `--fail-on` is `block`.

## The output

The report as `make demo` prints it, at the time of writing:

```
compared testdata/demo-repo/head/package-lock.json with testdata/demo-repo/base/package-lock.json

npm:demo-crypto-helper@1.0.2  WARN  (testdata/demo-repo/head/package-lock.json:32, direct)
  warn
    TD001 young-version: Published 2d2h47m15s ago, inside the 3d cooldown
      1.0.2 was published on 2026-09-07T09:12:44Z, 2d2h47m15s before this run; the cooldown is 3d,
      so the version has been public for too short a time for problems to be noticed and reported,
      and it leaves the cooldown on 2026-09-10T09:12:44Z
    TD006 install-script-present: Runs code at install time: postinstall
      1.0.2 declares postinstall (node ./scripts/setup.js), which npm runs with the installing
      user's permissions on every install of the package
  skipped TD002: no earlier release to compare with
  skipped TD003: no earlier release to compare with
  skipped TD004: no earlier release to compare with
  skipped TD005: no earlier release to compare with
  skipped TD007: no earlier release to compare with
  skipped TD009: osv unavailable: ...
  skipped TD010: osv unavailable: ...
  skipped TD012: downloads unavailable: ...
  skipped TD015: no earlier release of npm:demo-crypto-helper to compare 1.0.2 with

1 subject, 0 block, 2 warn, 0 info, 9 skipped checks. Exit code 0 (no blocking findings).
```

Three of the skipped lines are shortened above. Their reasons name OSV, deps.dev
and the download counts API, all of which the demo forbids by running offline. An
offline run that cannot reach an advisory source says so; it never reports a clean
package it did not check.

The shape to expect, whatever the wording becomes: a note naming the two files
compared, one card for the one added entry with its lockfile line and the `direct`
marker, the findings grouped by level with the evidence under each, the skipped
checks with a reason each, and a summary line with the counts and the meaning of
the exit code.

## The other formats

Adding `--format sarif` to the same command produces the document the M2
acceptance criterion is stated in: a SARIF 2.1.0 log with two results, `TD001` and
`TD006`, both at `level: "warning"`, both with a `physicalLocation` whose
`artifactLocation.uri` is `testdata/demo-repo/head/package-lock.json` and whose
`region.startLine` is 32, against a `tool.driver` that declares one rule per check
with a `helpUri` into `docs/checks.md`. That is what a code scanning upload turns
into two annotations on the added lockfile line.

`--format markdown` is the same run as the table a CI job pastes into a pull
request:

```
## trustdiff: 1 subject, 0 block, 2 warn, 0 info, 9 skipped checks

| Package | Level | Check | Finding | Location |
| --- | --- | --- | --- | --- |
| npm:demo-crypto-helper@1.0.2 | warn | TD001 young-version | Published 2d2h47m15s ago, inside the 3d cooldown | testdata/demo-repo/head/package-lock.json:32 |
| npm:demo-crypto-helper@1.0.2 | warn | TD006 install-script-present | Runs code at install time: postinstall | testdata/demo-repo/head/package-lock.json:32 |

Exit code 0 (no blocking findings).
```

`--format json` produces the report the JSON schema in `schema/report.v1.json`
describes.

## Extending it

`testdata/demo-repo/README.md` is the file to read and to update: it explains what
each fixture is for, how the integrity values and the seeded cache entry are
regenerated, and which checks a new fixture would reach. Two rules keep the demo
worth running:

- A change that adds a finding to the added entry changes the acceptance criterion.
  Either keep the entry at its two findings and add a second changed entry for the
  new one, or change the milestone document with it.
- Keep the demo offline and clock-pinned. A demo that needs the network is a demo
  that breaks on the day it is recorded, and a demo that reads the wall clock stops
  being young.
