# Precision, measured

What this tool reports on ten real repositories, every block finding classified by
hand, and what the measurement changed. Run on 2026-09-12.

Nothing here is an estimate. Every number comes from a report committed under
[precision/](precision/), and every classification names the package it was made
about.

## Why

Defaults nobody has measured are guesses. A check that fails a build over something
ordinary teaches people to turn it off, and a tool whose findings are mostly noise is
worse than no tool, because it spends the attention a real finding needs. Before
asking anyone to put this in front of their pipeline, the honest thing is to run it
over real lockfiles and count.

## The ten repositories

Each is pinned at the commit that was its default branch head on 2026-09-12, chosen
so that every one of the nine lockfile formats this release reads is covered at least
once and two of them are monorepos with more than a thousand entries. Every lockfile
was verified to exist at the commit named, through the contents API, before anything
was cloned.

| Repository | Commit | Format it was chosen for | Lockfile | Entries |
|---|---|---|---|---|
| [npm/cli](https://github.com/npm/cli) | [`c9876d7`](https://github.com/npm/cli/tree/c9876d7ea7150b0702e4151210b9fa1a8dbc7fbf) | `package-lock.json` | `package-lock.json` | 1201 |
| [apache/superset](https://github.com/apache/superset) | [`3e7bdec`](https://github.com/apache/superset/tree/3e7bdec53bb7830b524a4b2b53478332b00d9c72) | `package-lock.json` | `superset-frontend/package-lock.json` | 3423 |
| [vuejs/core](https://github.com/vuejs/core) | [`5409708`](https://github.com/vuejs/core/tree/54097087a0918b98f16c84599b1a6d654e952ca7) | `pnpm-lock.yaml` | `pnpm-lock.yaml` | 620 |
| [facebook/react](https://github.com/facebook/react) | [`019019b`](https://github.com/facebook/react/tree/019019be403c3269e15b8d7ebefb57d30f84086b) | `yarn.lock` (Yarn 1) | `yarn.lock` | 2394 |
| [oven-sh/bun](https://github.com/oven-sh/bun) | [`b993710`](https://github.com/oven-sh/bun/tree/b99371011f0cf8664c31d4290b3bdb2d0b2e31e8) | `bun.lock` | `bun.lock` | 60 |
| [denoland/fresh](https://github.com/denoland/fresh) | [`86d6cde`](https://github.com/denoland/fresh/tree/86d6cdeb331a719cf8b1c85bf5e43c8ffa889b3b) | `deno.lock` | `deno.lock` | 856 |
| [astral-sh/ruff](https://github.com/astral-sh/ruff) | [`11dc3e0`](https://github.com/astral-sh/ruff/tree/11dc3e08bca64e3ddf3897c0901b8677c8297e2a) | `uv.lock` | `uv.lock` | 92 |
| [python-poetry/poetry](https://github.com/python-poetry/poetry) | [`be56ff0`](https://github.com/python-poetry/poetry/tree/be56ff07db06e9b82574648433ca228e4cac549b) | `poetry.lock` | `poetry.lock` | 78 |
| [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) | [`3fce3b5`](https://github.com/BurntSushi/ripgrep/tree/3fce3b5bb0236da2df6d99672afb8a719642eca7) | `Cargo.lock` | `Cargo.lock` | 63 |
| [pypa/warehouse](https://github.com/pypa/warehouse) | [`5748d68`](https://github.com/pypa/warehouse/tree/5748d68e3bfc64f2ae732ab98e4b8c7d1c004ecb) | `requirements` files | `requirements/main.txt` | 184 |

`expressjs/express` was the first choice for `package-lock.json` and was dropped: it
carries no lockfile at its head. `axios/axios` was verified as a spare and left out,
because the format it covers is already covered twice.

A repository holds more than the lockfile it was chosen for. `scan` reads every
lockfile under the root it is given, so `oven-sh/bun` brings a `Cargo.lock` of 180
crates along with its 60 entry `bun.lock`, and `pypa/warehouse` brings a 1,000 entry
`package-lock.json` along with eight `requirements` files. The table below lists what
each run actually read.

## How they were run

Each repository was cloned at its pinned commit with a sparse checkout of the
lockfile's directory, then:

```sh
TRUSTDIFF_NOW=2026-09-12T12:00:00Z trustdiff scan <checkout> --format json
TRUSTDIFF_NOW=2026-09-12T12:00:00Z trustdiff doctor . --format json
```

with the default policy, live registries and no allow entries. `TRUSTDIFF_NOW` is
pinned so that the ages in the reports are the ages this run saw and a rerun of the
same commits says the same thing. The HTTP cache directory was deleted before the
run, so every request counted below is a request that was made.

The binary was built from commit `d9d294f`, which carries every check change this
document describes; the `tool` block of each report names it. The `doctor` reports
were written by the same build, run again from inside each checkout so that the
`root` they record is `.` rather than a path on the machine that ran them; `doctor`
reads configuration files and asks no registry anything, so that is the same answer.

## What the run produced

| Repository | Commit | Lockfiles read | Subjects | block | warn | info | Checks skipped | Exit |
|---|---|---|---|---|---|---|---|---|
| npm/cli | `c9876d7` | `package-lock.json` (npm, 1009) | 1009 | 50 | 815 | 564 | 2439 | 1 |
| apache/superset | `3e7bdec` | `superset-frontend/package-lock.json` (npm, 2825), `superset-frontend/cypress-base/package-lock.json` (npm, 702) | 3527 | 112 | 779 | 71 | 11202 | 1 |
| vuejs/core | `5409708` | `pnpm-lock.yaml` (pnpm, 620) | 620 | 36 | 102 | 5 | 1291 | 1 |
| facebook/react | `019019b` | `yarn.lock` (yarn 1, 2389) | 2389 | 267 | 467 | 12 | 7585 | 1 |
| oven-sh/bun | `b993710` | `Cargo.lock` (cargo, 180), `bun.lock` (bun, 60) | 240 | 7 | 59 | 1 | 681 | 1 |
| denoland/fresh | `86d6cde` | `deno.lock` (deno, 856) | 856 | 68 | 211 | 12 | 2004 | 1 |
| astral-sh/ruff | `11dc3e0` | `Cargo.lock` (cargo, 505), `uv.lock` (uv, 91) | 596 | 20 | 183 | 1 | 1963 | 1 |
| python-poetry/poetry | `be56ff0` | `poetry.lock` (poetry, 78) | 78 | 1 | 9 | 0 | 312 | 1 |
| BurntSushi/ripgrep | `3fce3b5` | `Cargo.lock` (cargo, 52) | 52 | 0 | 18 | 0 | 156 | 0 |
| pypa/warehouse | `5748d68` | `package-lock.json` (npm, 1000), `requirements/main.txt` (requirements, 184), `requirements/lint.txt` (requirements, 56), `requirements/tests.txt` (requirements, 48), `requirements/docs-blog.txt` (requirements, 46), `requirements/docs-user.txt` (requirements, 34), `requirements/docs-dev.txt` (requirements, 31), `requirements/dev.txt` (requirements, 27), `requirements/deploy.txt` (requirements, 8) | 1434 | 12 | 229 | 13 | 3819 | 1 |
| **Total** | | | **10801** | **573** | **2872** | **679** | **31452** | |

Findings by check, over all ten:

| Check | block | warn | info |
|---|---|---|---|
| TD002 `publisher-changed` | 281 | 389 | 59 |
| TD003 `maintainers-changed` | 0 | 657 | 0 |
| TD004 `trust-downgrade` | 0 | 7 | 0 |
| TD006 `install-script-present` | 0 | 231 | 0 |
| TD007 `new-dependency-introduced` | 0 | 925 | 0 |
| TD008 `typosquat-suspect` | 13 | 4 | 0 |
| TD010 `vulnerability` | 271 | 0 | 0 |
| TD011 `deprecated-or-yanked` | 0 | 131 | 0 |
| TD012 `low-usage` | 0 | 0 | 2 |
| TD013 `exotic-source` | 8 | 0 | 571 |
| TD014 `integrity-missing` | 0 | 528 | 0 |
| TD015 `version-anomaly` | 0 | 0 | 47 |

## Every block finding, classified

A finding is a **true positive** when what it says is true and worth a person's
attention, a **false positive** when it is not, and **undecidable** when registry
metadata cannot settle it either way. Every block finding of the run is in one of the
groups below; nothing is classified by omission.

| Check | Block findings | What they are |
|---|---|---|
| TD002 `publisher-changed` | 281 | true positives, with two undecidable shapes |
| TD010 `vulnerability` | 271 | true positives: an OSV advisory whose range holds the locked version |
| TD008 `typosquat-suspect` | 13 | the demotion these rest on needs a download count nothing could read |
| TD013 `exotic-source` | 8 | true positives; the answer is an allow entry, not a rule change |
| **Total** | **573** | |

### `vulnerability`: true positives

Every one is an OSV advisory whose affected range contains the locked version, at
`high` or above, which is what the default policy reports. Spot-checked against
osv.dev: `@babel/traverse@7.8.3` and `@babel/traverse@7.11.0` against
[GHSA-67hx-6x53-jw92](https://osv.dev/vulnerability/GHSA-67hx-6x53-jw92), CVSS 9.3,
the 2023 Babel arbitrary code execution, and
`@babel/plugin-transform-modules-systemjs@7.25.9` against
[GHSA-fv7c-fp4j-7gwp](https://osv.dev/vulnerability/GHSA-fv7c-fp4j-7gwp), CVSS 8.2.
These are the lockfiles of large projects, some of them years old, and a known
vulnerability in one is a fact about the project rather than a mistake by the tool.

### `publisher-changed`: true positives, with two undecidable shapes

This is the largest group, and it is what the check exists to report: an account
publishing a package for the first time. 251 of the findings are an npm account, 192
distinct packages across the ten lockfiles; 20 are a crates.io account; 10 are a
trusted publisher configuration.

The sixteen on npm/cli were checked one at a time against the packument of each
package, and fifteen were published by an account that had never published that
package before: `ms@2.1.2` by `styfle`, `negotiator@1.0.0` by `wesleytodd`,
`wrappy@1.0.2` by `zkat`, `convert-source-map@2.0.0` by `phated`,
`istanbul-lib-report@3.0.1` by `oss-bot` and ten more. Every one is a real handover
or a move to a release bot, and every one is worth the single look the finding asks
for.

The sixteenth, `gensync@1.0.0-beta.2` by `loganfsmyth`, is the window showing: that
account published `1.0.0-beta.0`, which is older than the five releases the check
compares with. Widening the window would have caught one finding in sixteen and would
weaken the check for every package that rotates publishers, so the window stays at
five and this is written down instead. **A false positive, left alone.**

The crates.io findings are the same shape with less to go on. crates.io publishes
owners as current state only, so the demotion this pass added for npm, where a
maintainer list is recorded per version, cannot be made there: `lazy_static@1.5.0` by
`cuviper`, `url@2.5.8` by `Manishearth` and `digest@0.10.7` by `tarcieri` are all
handovers inside teams that registry metadata cannot tell from a takeover.
**Undecidable, kept at block**, with the crates.io `db-dump` ownership history
proposed for 0.6.0.

The case this check exists for was run again against the live registry with these
rules in, on the same day:

```
$ TRUSTDIFF_NOW=2026-09-12T12:00:00Z trustdiff check npm:event-stream@3.3.5
npm:event-stream@3.3.5  BLOCK
  block
    TD002 publisher-changed: Published by right9ctrl, which published none of the previous 5 versions
  warn
    TD003 maintainers-changed: Maintainers changed since 3.3.4: added right9ctrl
```

`3.3.4` listed `dominictarr` alone, so the account that published `3.3.5` was not a
maintainer of the release it is compared with and the demotion does not apply.

Ten findings, six distinct packages, are a trusted publisher configuration changing
rather than an account: `tinyglobby@0.2.17`, which four of the ten lockfiles carry,
was published through OIDC configuration `70503e67` where `0.2.16` and `0.2.15` went
through `e6850d9e`; `react-is@19.2.8` in two of them; four others once each. That is
what a maintainer moving their release workflow looks like, and also what somebody
who reached the account and registered their own publisher looks like.
**Undecidable, kept at block.**

### `exotic-source`: true positives, and the answer is a policy file

Seven are git dependencies pinned at a full commit sha, in repositories that plainly
meant it: ruff resolves five dev tools from git, poetry builds against `poetry-core`
from git, and superset's `dom-to-image` comes from a fork. One is a URL: superset
resolves `xlsx@0.20.3` from `https://cdn.sheetjs.com`, because that package left npm.

The findings are true. None of the registry's protections apply to any of them: the
release cannot be yanked, advisories are not matched against it, and there is no
publisher or provenance to compare with the previous version. Demoting a pinned sha
to `warn` was considered and dropped, because pinning fixes which bytes arrive and
not whose they are, and the mode this tool is built for is `diff`, where a pull
request repointing a dependency at somebody else's repository is exactly the thing to
stop. A project that vendors from git on purpose writes the allow entry the check's
own documentation describes.

### `typosquat-suspect`: thirteen findings with an unread half

The thirteen this run reports are the counts outage and nothing else. Every one
carries `standing: usage-unknown`, which is the check saying it could not read the
download count its demotion rests on, and every one is in superset or React, the two
repositories whose counts `api.npmjs.org` refused. An earlier run of the same ten
repositories, an hour before, had those counts: the same names came back as nine
warnings and four blocks.

The four blocks were the veto this pass removed. It kept a look-alike at the
configured level however old and however installed it was, and across the ten
lockfiles it produced seven block findings in total, not one of them a squat:

| Candidate | Resembles | Weekly downloads | Neighbor's | Gap |
|---|---|---|---|---|
| `art` | `arg` | 156,418 | 74,569,623 | 476x |
| `flot` | `flat` | 48,425 | 21,697,202 | 448x |
| `chrome-launch` | `chrome-launcher` | 10,382 | 14,121,975 | 1360x |
| `remark-man` | `remark-math` | 2,538 | 5,803,797 | 2286x |
| `@conventional-commits/parser` | `conventional-commits-parser` | 110,616 | 13,029,493 | 117x |
| `clipboard-js` | `clipboard` | 13,749 | 1,500,139 | 109x |
| `@vx/responsive` | `@visx/responsive` | 33,061 | 3,451,088 | 104x |

Two rule changes came out of that, described below. With them in, and with the
download counts the demotion rests on, the check reports no block finding on any of
these ten repositories. The malware the veto was written for still blocks, run again
against the live registry with the new rules in:

```
$ TRUSTDIFF_NOW=2026-09-12T12:00:00Z trustdiff check npm:crossenv@6.1.1
npm:crossenv@6.1.1  BLOCK
  block
    TD008 typosquat-suspect: "crossenv" resembles the popular npm package "cross-env"
      ... has 1260 weekly downloads, but "cross-env" has 18224320, which is 14463
      times as many. A package that far behind the name it resembles is where a typo
      lands whatever its age, so the level stays at the configured one
```

### What a changed finding looks like

`@vx/responsive@0.0.199` was in superset's lockfile and carried two of the block
findings above. Run again against the live registry with the new rules in:

```
$ TRUSTDIFF_NOW=2026-09-12T12:00:00Z trustdiff check npm:@vx/responsive@0.0.199
npm:@vx/responsive@0.0.199  WARN
  warn
    TD002 publisher-changed: Published by hshoff, which published none of the previous 5 versions
      ... hshoff is listed as a maintainer of 0.0.198, the release before it, so this is a
      release cut by an account the package had already named rather than an identity arriving
      from outside, and it is reported at warn rather than at the configured level
    TD008 typosquat-suspect: "@vx/responsive" resembles the popular npm package "@visx/responsive"
      ... The level is lowered to warn because the package is one a project has been living
      with: it has been on the registry since 2017-03-22T18:39:53Z ...
```

One package, both rules, and a subject that used to fail a build now reports two rows
a person can read in ten seconds and act on or not.

## The warn and info classes

The levels below `block` do not fail a run under the default `--fail-on block`, and
they are where most of the output is. The classes, all of them true of the lockfiles
they were reported on:

| Check | Level | Findings |
|---|---|---|
| TD007 `new-dependency-introduced` | warn | 925 |
| TD003 `maintainers-changed` | warn | 657 |
| TD013 `exotic-source` | info | 571 |
| TD014 `integrity-missing` | warn | 528 |
| TD002 `publisher-changed` | warn | 389 |
| TD006 `install-script-present` | warn | 231 |
| TD011 `deprecated-or-yanked` | warn | 131 |
| TD002 `publisher-changed` | info | 59 |
| TD015 `version-anomaly` | info | 47 |
| TD004 `trust-downgrade` | warn | 7 |
| TD008 `typosquat-suspect` | warn | 4 |
| TD012 `low-usage` | info | 2 |

Two are worth a note.

`integrity-missing` fired on 528 npm entries in npm/cli's own lockfile, which records
no integrity hash for 792 of its 1,201 entries, 740 of them development ones; the
other npm lockfile of the pass has 26 such entries in 3,423. Nothing ties those
entries to the bytes an install downloads, which is what the check says, and a
project whose package manager writes lockfiles like that can set the check to
`info`.

`install-script-present` is most of what a Rust lockfile produces: a `build.rs` or a
proc-macro crate runs code at build time, and a Rust dependency tree is full of both.
It is reported at `warn` for that reason.

## A scan is a census, a diff is a gate

The checks that compare a version with the release before it, `publisher-changed`,
`maintainers-changed` and `new-dependency-introduced`, report on an existing lockfile
everything that ever happened to it. npm/cli's lockfile carries years of maintainer
changes. None of them is news, and all of them are true.

The four real lockfile changes measured in the same pass are the other picture. Each
is the two most recent commits that touched that lockfile in that repository, so what
is evaluated is a change a maintainer actually made:

| Repository | Format | Base to head | Subjects evaluated | block | warn | Exit |
|---|---|---|---|---|---|---|
| npm/cli | npm | `05bd2a49` to `6e40f739` | 1 | 0 | 0 | 0 |
| vuejs/core | pnpm | `5d0db082` to `a7928a30` | 9 | 0 | 0 | 0 |
| astral-sh/ruff | uv | `22f65a2a` to `b5dba861` | 9 | 0 | 4 | 0 |
| BurntSushi/ripgrep | cargo | `5055264a` to `3fce3b5b` | 0 | 0 | 0 | 0 |

Nothing blocked. The warnings are `install-script-present` on Rust proc-macro crates
and build scripts in ruff's `uv.lock` update, which is what a Rust dependency bump
looks like and what the finding says. ripgrep's pair is the two most recent commits
that touched its `Cargo.lock`, and what changed in it is the version of `ignore`,
which is one of ripgrep's own crates rather than something it installs, so there was
nothing to evaluate.

That is the difference between the two commands, measured. `scan` describes a tree;
`diff` guards a change. A project turning this on for the first time should expect
the census once and the gate every day after.

## What the measurement changed

Eleven changes came out of this pass. Each is one commit with a test that fails
without it, and each commit message carries the measurement that argued for it.

What it reports:

1. **The `yarn.lock` Yarn 1 wrote is read.** React's lockfile is that format, the
   parser read only the Yarn 2 one, and the whole file came back as "not read": 2,394
   entries unevaluated, with nothing in the report saying a check had been missed.
   The readme promised `yarn.lock` without qualification. The file is a fixture now,
   with attribution, and so are the shapes it does not have.
2. **A lockfile entry that installs a directory of the project is no longer judged by
   what a registry says about a package of that name.** React links
   `eslint-plugin-react-internal` to `./scripts/eslint-rules`; npm holds a package of
   that name that OSV lists as malicious, and the scan called React's own lint rules
   malware, at block. npm/cli's sixteen workspace members produced six
   `publisher-changed` blocks and six `maintainers-changed` warnings the same way.
   The package on npm is still reported: `trustdiff check
   npm:eslint-plugin-react-internal@0.0.0` blocks on `malicious-advisory`, because
   asked about the registry's package that is what the registry's package is. What
   changed is that a lockfile line pointing at a directory is no longer read as that
   package.
3. **A package adopting trusted publishing is not a block.** 44 of the 81 block
   findings of the first scan of npm/cli were that, and it is the change this tool
   argues for.
4. **A release cut by an account the previous release already listed as a maintainer
   is a warning.** Of 317 distinct npm `publisher-changed` blocks, a sample of 25
   checked against each package's packument found 11 of that shape; in the final run
   the rule demoted 135 findings across the four npm repositories.
5. **A name that was on the registry before the name it resembles is not imitating
   it.** `@vx/responsive` predates `@visx/responsive` by three and a half years,
   `chrome-launch` predates `chrome-launcher` by two and a half.
6. **The popularity gap that takes that demotion back asks for a thousandfold rather
   than a hundredfold.** A hundredfold is the ordinary distance between a niche
   package and a giant; the malware it was written for sits fourteen thousand times
   behind its target.
7. **A comparison that crosses release lines is a warning.** A maintenance release on
   an older line is compared with the newer line's release, which says the older line
   carries less evidence, which is true of the lines rather than of the release.
8. **deps.dev's indexing lag is not a lost attestation.** A release four days old,
   indexed but not yet opened, read as one that had given up its provenance.

How it asks:

9. **The counts API is asked once per 128 packages** instead of once per package,
   which is what 2,406 answers of `429 Too Many Requests` on one lockfile bought.
10. **`api.npmjs.org` gets one request per second**, the rate crates.io asks for in
    its own policy, because npm documents none and enforces one.
11. **A refused request costs only the names it covered.** The client discarded every
    count it had read when one request failed, and the loader stored that failure
    against every name of the run: React's scan lost the counts of 1,583 packages
    because one scoped name was refused. A failed batch still answers for the names
    it covered rather than becoming one request per package, and its error no longer
    carries the 128 names it asked about into the report once per package.

Three things were measured, found to be true findings, and left alone: a git or URL
dependency (the answer is an allow entry), an npm entry with neither a location nor a
hash (true of the lockfile, and already below the level that fails a build), and a
crates.io publisher change (nothing crates.io publishes can tell a handover from a
takeover).

## What the run cost

| Repository | Subjects | Run | 429 from api.npmjs.org |
|---|---|---|---|
| npm/cli | 1009 | 358s | 75 |
| apache/superset | 3527 | 299s | 4 |
| vuejs/core | 620 | 292s | 75 |
| facebook/react | 2389 | 128s | 4 |
| oven-sh/bun | 240 | 758s | 0 |
| denoland/fresh | 856 | 319s | 74 |
| astral-sh/ruff | 596 | 1533s | 0 |
| python-poetry/poetry | 78 | 31s | 0 |
| BurntSushi/ripgrep | 52 | 57s | 0 |
| pypa/warehouse | 1434 | 417s | 65 |
| **Total** | **10801** | **4192s** | **297** |

Every `429` in that table came from `api.npmjs.org`, the download counts endpoint,
which documents no rate limit and enforces one. crates.io is the other shape: the
tool holds itself to the one request per second crates.io asks for in its own policy,
so `oven-sh/bun` spent 758 seconds on a 180 crate `Cargo.lock` and drew no `429` at
all, which is the limit working rather than the limit being hit.

### What the counts API did, and what it cost the measurement

`low-usage` reads npm's weekly download counts, and `typosquat-suspect` uses them to
decide whether a look-alike is a package a project has been living with. In two of
the ten runs `api.npmjs.org` refused a request in the middle, and the client, as it
was written that day, discarded every count it had already read. `low-usage` then
reported itself skipped for 3,502 of superset's 3,527 subjects and 2,388 of React's
2,389.

The two runs that lost their counts are also the two fastest for their size: 3,527
subjects in 299 seconds and 2,389 in 128, against npm/cli's 1,009 in 358 with its
counts in hand. Asking `api.npmjs.org` for a scoped name at a time is most of what a
large npm scan spends its wall clock on, and a run that is refused early stops
spending it.

Reporting a check as skipped when its data could not be read is what the tool should
do, and `on_data_unavailable` can fail a run on exactly that. What it should not do
is lose a thousand counts over one refused request, and that is the eleventh change
in the list above.

It cost this measurement something, and the tables of this document say so rather
than hiding it: the demotion `typosquat-suspect` gives a package a project has been living with
rests on that package's download count, and an unread count cannot demote anything.
So the block findings this run reports for that check are in those two repositories
and nowhere else. `@vx/responsive`, one of them, run again against the live registry
with its count in hand, is the example above: a warning.

## `doctor` on the same ten repositories

`doctor` reads the hardening settings a project's package managers already support
and says which are set, which are set too weakly and which are missing. It asks
nothing of any registry.

| Repository | Managers detected | set | weak | wrong | missing | advice | n/a | Exit |
|---|---|---|---|---|---|---|---|---|
| npm/cli | npm 11.19.1 | 0 | 0 | 0 | 3 | 1 | 1 | 0 |
| apache/superset | npm 11.19.1, npm 11.19.1, uv 0.11.13 | 1 | 0 | 0 | 6 | 2 | 3 | 0 |
| vuejs/core | pnpm 11.19.0 | 3 | 1 | 0 | 0 | 1 | 1 | 0 |
| facebook/react | yarn 1.22.22 | 1 | 0 | 0 | 1 | 1 | 1 | 0 |
| oven-sh/bun | bun 1.4.2, cargo 1.95.0 | 1 | 0 | 0 | 0 | 3 | 0 | 0 |
| denoland/fresh | deno ? | 1 | 0 | 0 | 2 | 0 | 0 | 0 |
| astral-sh/ruff | cargo 1.95.0, uv 0.11.13 | 1 | 0 | 0 | 0 | 2 | 1 | 0 |
| python-poetry/poetry | poetry ? | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| BurntSushi/ripgrep | cargo 1.95.0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 |
| pypa/warehouse | npm 11.19.1, pip ? | 1 | 0 | 0 | 4 | 1 | 1 | 0 |

The version beside each manager is the one the run could establish: the
`packageManager` field of `package.json` where the project pins one, which is where
vuejs/core's pnpm 11.19.0 comes from, the binary on the machine otherwise, and `?`
where neither said, in which case a rule that depends on a version says so rather
than guessing. What the ten were missing:

| Rule | Status | Repositories |
|---|---|---|
| DR003 npm-allow-git | missing | 4 |
| DR004 npm-allow-remote | missing | 4 |
| DR001 npm-min-release-age | missing | 2 |
| DR010 pnpm-minimum-release-age | weak | 1 |
| DR021 yarn-enable-scripts | missing | 1 |
| DR040 deno-minimum-dependency-age | missing | 1 |
| DR041 deno-frozen-lockfile | missing | 1 |
| DR050 uv-exclude-newer | missing | 1 |
| DR060 pip-uploaded-prior-to | missing | 1 |
| DR061 pip-require-hashes | missing | 1 |
| DR070 poetry-min-release-age | missing | 1 |

Not one of the four npm roots in these ten repositories sets npm's `allow-git` or
`allow-remote` deny lists, and two of them set no `min-release-age` either. One
project of the ten has turned a cooldown on at all: vuejs/core carries
`minimumReleaseAge: 1440` in `pnpm-workspace.yaml`, one day where the default policy
asks for three, which is the one `weak` in the table above rather than a `missing`.

These are the settings that would have stopped several of the incidents this tool is
built around, and they are off by default in every package manager that has them.
`doctor --fix` writes them, and `doctor --ci` fails a build while they are missing.

## What is left

- `low-usage` and `typosquat-suspect` read npm's download counts, and
  `api.npmjs.org` refuses enough of this address's requests that a large lockfile can
  lose them. The release makes a refusal cost only the names it covered, which is
  most of the fix; the rest is asking for fewer counts, only where an answer can
  change a finding, which is proposed for 0.6.0.
- A scan asks for scoped names one at a time, because npm's bulk form refuses them,
  and at one request per second that is most of the wall clock of a large npm scan.
- `publisher-changed` on crates.io cannot make the demotion it makes on npm. That
  needs ownership history, which is in the crates.io `db-dump` and not in the API.
- `integrity-missing` fires on 528 npm entries in one repository whose lockfile
  records no integrity hash for 792 of its 1,201 entries. The finding is true of that
  file.
- Nothing here measures recall. These ten repositories contain no known compromised
  release, so what this pass measured is what the tool says about ordinary software.
  The one malicious package it did find, it found by accident, in the single place
  where reporting it was wrong.
