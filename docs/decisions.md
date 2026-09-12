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
