# bun.lock fixtures

Real lockfiles, recorded once so the tests never touch the network. Each was
downloaded from `raw.githubusercontent.com` at the pinned commit named below and
is committed unmodified, under the license the project carried at that commit.
Neither needed trimming: both are well under 200 KB as they stand.

| File | Project | Source | Commit or release | Date | License | lockfileVersion | Entries asserted |
|---|---|---|---|---|---|---|---|
| `bun-v1.bun.lock` | Bun | https://github.com/oven-sh/bun/blob/5f554969bc8ab2159583cdf5ff26f5277ca35e91/bun.lock | branch `main` at commit `5f554969bc8ab2159583cdf5ff26f5277ca35e91` | 2026-09-09 | MIT (`LICENSE.md`: "Bun itself is MIT-licensed"; the rest of that file is the notices for the libraries Bun statically links) | 1 (configVersion 1) | 60 |
| `elysia-v1.bun.lock` | Elysia | https://github.com/elysiajs/elysia/blob/e037eca710e7ad193be09cc6615ab0dbe54af914/bun.lock | branch `main` at commit `e037eca710e7ad193be09cc6615ab0dbe54af914` | 2026-09-09 | MIT | 1 (configVersion 1) | 291 |

What each one is here for:

- **Bun**'s own lockfile is the small one, 15 KB, and it is a workspace: two
  entries in `workspaces`, the repository itself and `packages/bun-types`, and a
  `packages` entry whose array holds nothing but the resolution
  (`["bun-types@workspace:packages/bun-types"]`), which is the shortest shape the
  format has. It also pins that a dependency a workspace member declares
  (`@types/node`) is direct without being a development dependency of the
  repository.
- **Elysia** is the larger one, 64 KB and 291 entries, with nested install paths
  two levels deep (`eslint-plugin-sonarjs/minimatch/brace-expansion`) and the same
  package version under more than one of them, which is why the tests match an
  entry by the line it sits on rather than by its name.

Both files were written by a Bun that installs everything from the default
registry, so every one of their `packages` entries leaves the registry element
empty. The hand-written file below is what covers a stated registry URL.

`edge-cases.bun.lock`, `crlf.bun.lock` and `truncated.bun.lock` are not
recordings. They are written by hand for this test suite and describe no real
package.

- `edge-cases.bun.lock` collects the shapes the recordings do not hold: a git
  resolution over `git+ssh:` and a `github:` shorthand (whose third element is
  Bun's own checkout tag and not a hash), a tarball URL, `file:` and `link:`
  directories, a workspace member whose version comes from its `workspaces`
  entry, an alias whose key is `widgets-v1`, an entry whose hash is the empty
  string, a `"bundled": true` entry, a copy nested under another package, three
  entries that agree on one private registry and one entry on a host nothing else
  installs from, which is what `lockfile.RegistryHosts` exists to tell apart. It
  also carries `//` and `/* */` comments and trailing commas, because bun.lock is
  JSONC. Its `integrity` values are the sha512 of `<name>@<version>` in base64, so
  a new entry's hash is
  `printf '%s' '<name>@<version>' | openssl dgst -sha512 -binary | openssl base64 -A`.
- `crlf.bun.lock` is the same shape with Windows line endings, which is what a
  repository checked out on Windows without a `.gitattributes` holds.
- `truncated.bun.lock` is the first 1371 bytes of `edge-cases.bun.lock`, which
  stops in the middle of an entry. It pins that a half written file is reported
  rather than read as an empty one.

To record another file, download it at a fixed commit and add a row above:

```sh
curl -fsS -o <name>-<version>.bun.lock \
  https://raw.githubusercontent.com/<owner>/<repo>/<commit>/bun.lock
```
