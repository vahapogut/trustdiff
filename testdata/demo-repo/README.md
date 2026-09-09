# The demo repository

Two npm lockfiles, `base/package-lock.json` and `head/package-lock.json`, that
differ the way a dependency-adding pull request differs from its base branch. They
are the input of `make demo` and of the M2 acceptance criterion.

Every package named here is fictitious. `trustdiff-demo-app`,
`demo-crypto-helper`, `demo-color-tty`, `demo-http-client`,
`trustdiff-demo-logger`, `demo-mime-types` and `demo-test-runner` are published on
no registry and describe no real package or person, which is the point: the demo
must keep saying the same thing however the real registries change, and it must
not put words in a real maintainer's mouth. Each of the seven was checked against
registry.npmjs.org on 2026-09-09 and answered 404; the project and the logger
carry the `trustdiff-` prefix because the shorter `demo-app` and `demo-logger` are
names somebody else already published. The lockfiles are hand written in the shape
npm 10 writes, not recordings. The real recorded lockfiles live in
`internal/lockfile/npm/testdata`.

## What the change shows

The head side adds one entry, `node_modules/demo-crypto-helper` at 1.0.2, on line
32, and the matching requirement in the project's `dependencies`. Nothing else
moves: the other five entries are byte for byte what the base locks, so the diff
is exactly one added entry and `diff` evaluates that entry alone.

The added version is two days old and runs a `postinstall` script, so it is the
pair of signals that made the demo worth writing:

- **TD001 young-version**, because 1.0.2 was published on 2026-09-07 and the run
  clock is pinned to 2026-09-09, inside the default 3d cooldown.
- **TD006 install-script-present**, because 1.0.2 declares
  `postinstall: node ./scripts/setup.js`, which npm runs with the installing
  user's permissions.

**TD005 install-script-introduced** is the check a reader expects here and does
not get: it needs the previous version to compare the script against, and the
registry fixture lists 1.0.2 as the only version there is. The report says so, as
a skipped check with a reason, instead of passing the entry quietly. That is the
behavior the demo is there to show as much as the two findings.

Age comes from the registry, not from a lockfile, so the fixtures cannot make a
package young on their own. `registry.json` is the packument that supplies it.

## How to run it

```
make demo
```

The target pins the clock with `TRUSTDIFF_NOW=2026-09-09T12:00:00Z`, seeds a
throwaway cache directory from `cache/`, and runs, from the repository root:

```
trustdiff diff \
  --base-file testdata/demo-repo/base/package-lock.json \
  testdata/demo-repo/head/package-lock.json \
  --policy testdata/demo-repo/.trustdiff.yaml \
  --offline --format human
```

`docs/demo-repo.md` walks through the output and shows the other formats.

## The files

- `base/package-lock.json` and `base/package.json`: the base branch, five locked
  packages, lockfileVersion 3.
- `head/package-lock.json` and `head/package.json`: the same project after the
  pull request added `demo-crypto-helper`.
- `registry.json`: the packument of `demo-crypto-helper` as registry.npmjs.org
  would answer it, hand written in the recorded shape (and indented, which a
  recording never is, because this one is meant to be read and edited). A fake
  registry serves it: point the client at an `httptest` server with
  `npm.WithRegistryURL` and answer `/demo-crypto-helper` with this body. Its
  `time` map dates exactly the versions `versions` holds, so a reader who opens
  it to check why TD005 and TD015 skip finds no earlier release there either.
- `cache/`: the same answer as one seeded HTTP cache entry, so `make demo` can run
  `--offline` with no server at all. See below.
- `.trustdiff.yaml`: a policy that sets nothing but the version, so every level and
  the cooldown stay at their built-in defaults even on a machine that has a
  user-level policy of its own.

The `integrity` values are well formed and deliberately not tarball hashes: each
one is the sha512 of the string `<name>@<version>`, so they can be recomputed
rather than trusted.

```
printf '%s' 'demo-crypto-helper@1.0.2' | sha512sum | cut -d' ' -f1 | xxd -r -p | base64 -w0
```

The name is part of that string, so renaming a package here means recomputing its
`integrity` and rewriting its `resolved` URL in both lockfiles.

The packument carries no `dist.signatures` block. Nothing in trustdiff verifies
signature bytes locally, and a made up signature in a repository is worse than an
absent one; the checks that read provenance (TD004) are skipped here anyway,
because they too need a previous version.

There is no download-counts fixture on purpose. Without one, TD012 low-usage
reports itself as skipped rather than adding a third finding to a demo whose
subject is the other two, and a brand new package's download count is not the
signal being shown.

## The seeded cache entry

`cache/` holds one entry of the disk cache described in
`internal/httpcache/httpcache.go`: a metadata file `<key>.json` and a body file
`<key>.body`, where the key is the sha256 of the method, the URL and the Accept
header, joined with newlines. `make demo` copies both into a fresh temporary
directory, points `TRUSTDIFF_CACHE_DIR` at it and runs `--offline`, which serves
the cache regardless of TTL and forbids every request. The demo therefore needs no
network, no server and no live registry, and it never reads or writes the
developer's own cache.

To regenerate the entry after editing `registry.json`:

```
key=$(printf 'GET\nhttps://registry.npmjs.org/demo-crypto-helper\napplication/json' \
  | sha256sum | cut -d' ' -f1)
cp registry.json "cache/$key.body"
# then set "length" in cache/$key.json to the byte count:
wc -c < registry.json
```

The body must stay byte for byte identical to `registry.json` and `length` must be
its byte count, or the entry is a miss: a cache entry whose body has another
length is treated as truncated. A miss costs the demo its two findings and turns
them into skipped checks, which is visible in the report and never a false pass.
The repository keeps LF endings everywhere (`.gitattributes`), so the byte count
is the same on every platform.

## Extending it

- **Another finding on the same entry.** Add the evidence to `registry.json`: a
  second version with an earlier publish time makes TD005 and TD002 comparable, a
  `deprecated` field on the version raises TD011, a dependency in `dependencies`
  gives TD007 something to introduce. Then regenerate the cache entry.
- **Another kind of change.** Add an entry to the head lockfile whose `resolved`
  is a git or http URL for TD013, or one without `integrity` for TD014. Both are
  lockfile-only checks and need no registry answer at all.
- **Another ecosystem.** Add `base/` and `head/` copies of a `pnpm-lock.yaml`,
  `uv.lock` or `Cargo.lock` and a packument fixture for the registry it belongs
  to. `diff --base-file` compares one file at a time, so a second pair is a second
  invocation.
- **Another name.** Check it against every registry the demo names before it is
  added, with `curl -s -o /dev/null -w '%{http_code}' https://registry.npmjs.org/<name>`,
  and pick another one unless the answer is 404. A name somebody has published is
  a name the demo can put words in the mouth of, and a run without `--offline`
  would query it against the versions and the `integrity` values invented here.

Whatever is added, the acceptance criterion of the milestone is measured on this
directory: keep the two findings on the added entry's line, and say in this file
what a new file is for. `TestDemoRepositoryIsTheAcceptanceScenario` in
`internal/cli` runs these inputs on every `go test ./...`, so a fixture that stops
producing the two findings fails the build rather than the demo.
