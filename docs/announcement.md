# Announcement drafts

Nothing here has been posted anywhere. These are drafts for a person to read, edit
and decide about. Every number in them comes from [precision.md](precision.md) or
from the CHANGELOG, and every one of those is counted from a report committed under
[precision/](precision/).

If any of this is posted, the link to give is the repository, and the part worth
reading is `docs/precision.md` rather than the feature list.

## Show HN

Title:

```
Show HN: Trustdiff – catch trust regressions in a lockfile change before they land
```

Text:

Trustdiff reads a lockfile change and asks a different question from a vulnerability
scanner: not "does this package have a known CVE" but "did the signals that made
this package trustworthy just change". A version published by an account that never
published one before. A release that lost the provenance every earlier release had.
A new dependency three days old with forty downloads. A name one keystroke from a
popular package. Each of those preceded a real incident, and each is visible in
registry metadata before anybody has read the code.

One Go binary, no account, no telemetry. It reads nine lockfile formats across npm,
PyPI, crates.io and JSR, runs as a GitHub Action, a pre-commit hook or a Bun install
scanner, and writes SARIF.

Before asking anyone to put it in front of their pipeline I ran it over ten large
public repositories and classified every finding by hand. It got things wrong, the
write-up says which, and the defaults changed because of it. That part is
docs/precision.md, and the reports it counts from are committed next to it.

## r/golang

Title:

```
I measured my own tool's false positives on ten real repositories, and it changed the defaults
```

Body:

Trustdiff is a supply chain tool I have been writing in Go: it evaluates what a
lockfile change adds or modifies and reports trust regressions, the signals that
change before an incident rather than after it. One static binary, six third party
modules, no telemetry.

Last week I did the thing I should have done before shipping defaults: ran it over
ten real repositories, pinned at real commits, covering every lockfile format it
reads, and classified every block finding by hand.

It found real problems in my own work.

The one I am least proud of: React's `yarn.lock` links `eslint-plugin-react-internal`
to a directory inside the repository. npm holds a package of that name, OSV lists it
as malicious, and my tool reported React's own lint rules as malware, at block. A
lockfile entry that installs a directory of the project is not the registry's package
of that name, and nothing I had run before asked that question. The same bug compared
npm/cli's sixteen workspace members against the release history of the packages npm
publishes under those names.

The one that taught me most about defaults: 44 of 81 block findings on one npm
lockfile were packages adopting npm's trusted publishing. The check read that as "the
publisher changed" and failed the build for the safest change a package can make.

The one that was pure guesswork on my part: a constant saying that a package a
hundred times behind the name it resembles is where a typo lands. Across ten
lockfiles it fired eight times and caught no squats, only old packages with real
users: `art` behind `arg`, `flot` behind `flat`, `@vx/responsive` behind the
`@visx/responsive` the project renamed itself to three years later. The malware it
was written for sits fourteen thousand times behind its target.

And one that was not about findings at all: evaluating a 1,201 entry lockfile drew
2,406 answers of `429 Too Many Requests` from npm's download counts API, because I
asked once per package instead of using the batch form the API documents.

Eight changes to what it reports and three to how it asks came out of that, each one
a commit with the measurement in the message and a test that fails without it. The
reasoning is in docs/decisions.md, the classification in docs/precision.md, and the
reports are committed too, so the counts can be checked rather than believed.

What I would do differently: measure precision before shipping defaults, not after.

## r/netsec

Title:

```
Trustdiff: lockfile trust regressions, and what measuring them on ten real repositories changed
```

Body:

Most supply chain tooling answers "is this package known bad". Trustdiff answers a
narrower question that is available earlier: did the trust signals of this package
change in the way they changed before event-stream, ua-parser-js, Shai-Hulud and the
axios compromise. Publisher changes, provenance downgrades, new install scripts, new
dependencies that are themselves days old, typosquat neighbours, malicious
advisories.

It runs on a lockfile diff in CI, on a full lockfile scan, or as a Bun install
scanner, and writes SARIF for code scanning. npm, PyPI, crates.io and JSR; nine
lockfile formats; one static binary with no account and no telemetry. Releases are
signed with cosign, carry SBOMs and GitHub build provenance, and the release workflow
waits for a human approval before it can sign anything.

The part worth your time is the precision work. Ten pinned public repositories, every
lockfile format, every block finding classified, the false positives fixed rather
than documented, and the reports committed as evidence. One of them is worth the
click on its own: the tool reported a repository's own workspace directory as malware,
because a squatter had taken that name on npm and nothing asked whether the entry was
a directory or a download.

It also says plainly what it still gets wrong, and which findings are true ones whose
answer is a policy file rather than a rule change.

Findings, method and raw reports: docs/precision.md and docs/precision/.

## GitHub release note, five lines

- Reads the `yarn.lock` Yarn 1 wrote, which a great many repositories still carry.
- A workspace directory is no longer judged by what a registry says about that name,
  which is how a repository's own lint rules got reported as malware.
- Stops blocking a package for adopting trusted publishing, and a maintainer for
  cutting a release.
- Asks npm's download counts API once per 128 packages instead of once per package.
- Ten public repositories measured, every block finding classified: `docs/precision.md`.
