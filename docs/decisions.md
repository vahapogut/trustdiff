# Decisions

Decisions taken during a run where asking was not an option, one line each, with
the date and the reason. A decision that changed a file names the commit that
carries it. This file is a record, not a policy: what it says was true when it was
written, and a decision that is later reversed gets a new line rather than an edit.

## 2026-09-12

- An untracked directory holding this run's own prompt file was moved out of the
  repository rather than committed or deleted. It is not repository content, every
  commit of this run has to leave the tree clean, and destroying a file somebody
  else put there is not this run's business, so it was moved to the session's
  scratchpad instead.
- The `release` environment was created with `can_admins_bypass` set to false. The
  API defaults it to true, which leaves an admin able to deploy without the
  approval the environment exists to require, and what this gate is for is a tag
  push that cannot sign anything on its own.
- The tag ruleset bypasses the admin repository role rather than naming a person.
  A ruleset cannot name the owner of a personal repository as a bypass actor, and
  the admin role here is one account, so the effect is the one asked for: only that
  account can create a `v*` tag.
- Every commit of this run is verified with `gofmt`, `go vet`, the offline
  `go test ./...` and `golangci-lint` at the pinned version. The gate runs once per
  push rather than once per commit where the commits of that push touch
  documentation alone, and again whenever Go code changes. Nothing lands
  unverified.
- The precision pass uses ten public repositories, each pinned at the commit that
  was its default branch head on 2026-09-12, one for every lockfile format this
  release reads and two of them monorepos. `expressjs/express` was the first
  choice for `package-lock.json` and was dropped: it carries no lockfile at its
  head, checked through the contents API before anything was cloned.
  `axios/axios` was verified as a spare and left out, because the format it covers
  is already covered twice, by `npm/cli` and by the `apache/superset` frontend.
- Every command of the precision pass runs with `TRUSTDIFF_NOW` pinned to
  2026-09-12T12:00:00Z, so the ages in the reports are the ages this run saw and a
  rerun of the same commits says the same thing.
- The bulk download counts client deleted in 0.5.0 as code nothing called is
  restored and wired into the loader's prefetch. The deletion was right when it was
  made and the precision pass produced the reason to reverse it: a scan of
  `npm/cli` drew 1684 answers of 429 from the counts API because it asked once per
  package. Restoring the method, its tests and its fixture by reversing that commit
  keeps the recorded facts about the endpoint rather than rediscovering them.
- The first scan of the pass ran against the binary of the release under test and
  was stopped once it had measured the rate limiting, rather than left to finish.
  Its numbers are the baseline this fix is measured against; the numbers in
  `docs/precision.md` come from a rerun of all ten repositories with the fix in.
- `api.npmjs.org` was given one request per second rather than a rate measured to
  be safe. No rate could be measured: by the time the question was asked the
  address was already throttled, and twenty probes one second apart were refused
  eighteen times. npm documents no limit at all, crates.io asks for one request per
  second in its own policy, and the batch form carries most of a run, so the limit
  costs only the tail of scoped names.
- The Yarn 1 lockfile format was implemented rather than documented as
  unsupported. The precision pass picked React for the `yarn.lock` format and the
  parser refused the file: two formats answer to that name and only the Yarn 2 one
  was read, while the readme promised `yarn.lock` without qualification. The rule
  for this run says a parser failure on one of these files is a bug, and the
  repositories still on Yarn 1 are not a rounding error, so the format is read now.
- `publisher-changed` stops blocking a move to trusted publishing that nothing can
  place. The rule that blocked it was deliberate and tested: without two verified
  attestations naming the same repository, a trusted publisher is what an account
  takeover looks like. The measurement changed the balance rather than the
  reasoning: 44 of the 81 block findings of one scan were legitimate migrations,
  and a check that fails a build on the safest change a package can make is a check
  people turn off. Two attestations that name different repositories still block.
- `trust-downgrade` reports a cross line comparison at `warn` rather than skipping
  it. Skipping was the first fix and it threw away a real signal: a patch published
  to an old line from a stolen token is exactly a maintenance release whose
  provenance is weaker than the newer line's. `docs/checks.md` already carried such
  a case as its example, which is what settled it.
- A download counts batch that fails now reports that failure for every name it
  carried, rather than leaving those names to the per name path. The measurement
  decided it: one refused batch used to become one request per package, which is
  what drew the block in the first place. The cost is that the checks reading
  counts report themselves as skipped for the whole run when the batch fails, which
  `on_data_unavailable` can act on, and the previous behavior hid the outage behind
  a thousand requests that mostly failed too.
- The download counts batching, the rate limit and the check changes of this pass
  were measured against a rerun of all ten repositories with a cold HTTP cache,
  and that rerun is what `docs/precision.md` reports. A warm cache would have made
  the run times a lower bound of nothing in particular and the 429 counts an
  artifact of what an earlier run had already fetched.
- `exotic-source` keeps its `block` for a git dependency pinned at a full commit
  sha. Seven of the eight block findings of this shape in the pass were pinned
  ones, in repositories that clearly meant it, and demoting them was considered and
  dropped: the check's whole claim is that none of the registry's protections apply
  to such an entry, and pinning the sha fixes which bytes arrive, not whose they
  are. The mode that matters is `diff`, where a pull request repointing a
  dependency at somebody else's repository, pinned at a sha, is exactly what this
  is for. The answer for a repository that vendors dev tools from git is the allow
  entry the check documents.
- `integrity-missing` keeps its `warn` for npm entries with neither a location nor
  a hash. 528 of the 810 warn findings of one scan were that, all of them in
  npm/cli's own lockfile, which records no `resolved` and no `integrity` for 740
  dev entries; the other npm lockfile of the pass had 26 in 3,424 entries. The
  finding is true either way, it is already below the level that fails a build, and
  a project whose manager writes lockfiles like that can set the check to `info`.
- `publisher-changed` demotes on the maintainer set npm records per version and
  does not attempt the same for crates.io. crates.io publishes owners as current
  state only, so the set a run reads is the set after whatever it is being asked
  about; npm's per-version list is a snapshot from before the release under review,
  which is what makes the comparison worth anything. The fifteen crates.io findings
  of the pass stay at block.
- `typosquat-suspect`'s popularity gap moved from a hundredfold to a thousandfold
  on the strength of seven findings. It is a measured constant, not a derived one,
  and the residual risk is written where it is set: a squat between a hundred and a
  thousand times behind its target, older than a year and above the low-usage
  threshold, is now reported at warn rather than at the configured level.
- A failed batch of download counts answers for the names it covered and not for the
  rest, which reverses half of the decision above about a batch that fails. That one
  was right about the storm it prevented and wrong about its scope: the cold run
  showed one refused request for a single scoped name costing React's scan the counts
  of 1,583 packages, and superset's the same. The names a failure did cover still get
  that failure as their answer and nothing asks again for them.
- `docs/precision.md` reports one run rather than two. The cold run of all ten
  repositories is what its tables count, including the two repositories whose
  download counts `api.npmjs.org` refused, and the document says what that cost
  rather than repeating the run until the numbers looked better. The three findings
  a run with counts reports differently are shown as single package checks against
  the live registry instead.
- The release is tagged v0.5.2. It carries a Changed section, and this repository's
  changelog preamble ties those to a minor release; the instruction that ran this
  work named the patch. Every level change in it lowers a level, so nothing that
  passed for one of those reasons starts failing, and the one change that can fail a
  run which used to pass is reading a Yarn 1 `yarn.lock` that used to come back as
  "not read", which is the fix a Yarn 1 project would ask for. The tag waits for an
  approval in the `release` environment, so the number can still be changed before
  anything is published: reject the deployment and delete the tag.
- `.pre-commit-hooks.yaml` moves its `rev:` from v0.5.0 to v0.5.2. The rule written
  next to it is to move it when the release changes what the hook does, and this one
  does: a repository on Yarn 1 gets a hook that reads its lockfile instead of one
  that matches it, runs, and reports that it could not be read.

## 2026-09-13

- An untracked directory holding this run's prompt file appeared in the repository
  root. It was moved to the session's scratchpad rather than committed or deleted,
  as the first one was on 2026-09-12: it is not repository content, and its name is
  one this repository keeps out of every file name and commit.
- Secret scanning and push protection were already enabled when this run read the
  repository's settings back, so the PATCH that enables them was not sent: it would
  have changed nothing and recorded a change that did not happen. Dependabot alerts
  and Dependabot security updates were off, and were turned on with the two PUT
  calls, then read back as enabled.
- `SECURITY.md` now states the tag ruleset and the release environment as facts
  rather than telling a reader to go and check whether they exist. Both were read
  back through the API on 2026-09-13, and the sentence carries that date, because a
  setting can be changed without a commit and a document cannot notice.
- Discussions was already enabled when this run read it back, so nothing was
  changed there.
- The npm half of this run goes through the browser and through a person, not
  through this session. `npm whoami` answered 401 in the terminal this run uses, and
  the package's settings page on npmjs.com asked for a security key before it would
  show anything. Neither a login nor a second factor is something this session
  enters, so it stopped at that page and asked for one.
- The race detector runs as one more leg of the existing test job rather than as a
  job of its own. It shares the job's checkout, toolchain and proxy settings, so it
  cannot drift from the run it is a stricter copy of, and matrix include makes it a
  new combination because race: true overwrites the race: false every other leg
  carries.
- The Show HN form gets the title and the repository URL and nothing else, and the
  r/golang form gets the title and an empty body. Hacker News's guidelines say not
  to post generated or AI-edited text, and r/golang's rule 12 allows no AI-generated
  content as posts; both read on 2026-09-13. The drafts in `docs/announcement.md`
  were written by a model, so pasting them into a body field would have prepared a
  post those two communities forbid, for somebody else to press the button on. The
  drafts stay as notes for the author to rewrite in their own words, and the file
  says so at the top.
- The announcement's per package figure is 1,684 answers of 429, not 2,406, and
  `docs/precision.md` item 9 now agrees. Two scans of npm/cli's lockfile produced
  the two numbers: 1,684 is the one commit 1d4b939 quotes for asking once per
  package, before the batch form existed; 2,406 is the one commit 89d951e quotes,
  from a run in which the batch form was refused and every name fell back to a
  request of its own. The changelog already kept them apart; the announcement and
  item 9 had put the larger number on the wrong cause. The Show HN title lost its
  dash and "they land" to fit Hacker News's 80 character limit.
- Scanner stage `79904f8b-6c41-4b5d-8c80-06cc38eed826` is approved rather than rejected
  and replaced with 0.5.1. Checked on 2026-09-13 before approving: its tarball's sha1
  is the `0ac5c2fc78ec0b45cd6825c83d4f5064dde863b0` npm lists for the stage; it holds
  four files, `LICENSE`, `README.md`, `package.json` and `src/index.ts`, and all
  four are byte for byte the files at tag `v0.5.0` (`f914f06`); `package.json`
  declares no dependency of any kind; and `src/index.ts` carries the F19 change,
  `unscannedAdvisory`, which reports an install nothing could scan instead of
  returning the empty list Bun reads as clean. The approval itself is typed by the
  owner in their own terminal, because npm asks for the security key again and that
  is not something this session touches.
