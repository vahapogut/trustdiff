# yarn.lock fixtures

Real lockfiles, recorded once so the tests never touch the network. Each was
downloaded from `raw.githubusercontent.com` at the pinned commit named below,
under the license the project carried at that commit, and then trimmed as
described under the table.

| File | Project | Source | Commit or release | Date | License | Entries asserted |
|---|---|---|---|---|---|---|
| `slate-v8.yarn.lock` | Slate | https://github.com/ianstormtaylor/slate/blob/45a16ee53fa7c54a551c755cb96af5cb39eb868d/yarn.lock | branch `main` at commit `45a16ee53fa7c54a551c755cb96af5cb39eb868d` | 2026-09-09 | MIT | 339 |
| `babel-v6.yarn.lock` | Babel | https://github.com/babel/babel/blob/de7d75a78b770fa3fdad2e5a94fe7ae208b5bd63/yarn.lock | release `v7.21.0`, commit `de7d75a78b770fa3fdad2e5a94fe7ae208b5bd63` | 2026-09-09 | MIT | 279 |

**Both files are trimmed, not verbatim.** The originals are 604 KB and 583 KB,
which is more than a fixture should weigh. Whole entries were removed and
nothing inside an entry was touched, so every entry that is still there is
exactly as Yarn wrote it, on its own line, in the order Yarn sorted it. What was
kept:

- the header comments and the whole `__metadata` block;
- every entry whose resolution is not a plain `npm:` one, which is what carries
  the cases the tests are about: the workspace entries (capped at 14 members plus
  the root in Babel's file, which has 170), the `patch:` entries, the `link:`
  entries and the `condition:` entries a Babel plugin writes;
- every aliased entry, whose key names one package and whose resolution names
  another;
- every fifth `npm:` entry of Slate's file and every sixth of Babel's, taken
  across the whole file rather than off the front so that the trimmed file still
  covers the alphabet the real one does.

What each one is here for:

- **Slate** is `__metadata` version 8, which Yarn 4 writes: the ranges on a key
  carry their `npm:` protocol, and the checksums carry the `10c0/` cache key. It
  is a real Yarn workspace monorepo, so it holds five workspace members plus the
  root, five builtin `patch:` entries (one of which, `fsevents`, is the only
  entry that package has, which is why a patch is kept rather than dropped), and
  five aliases (`react-is-18`, `string-width-cjs` and the rest).
- **Babel** is `__metadata` version 6, which Yarn 3 writes: a key's range is
  written without its `npm:` protocol, and one key mixes both spellings
  (`resolve@^1.1.4, resolve@npm:^1.10.1`), which is the case that decides how a
  workspace's dependency map is matched to an entry. It also carries two `link:`
  entries, thirteen `condition:` entries from a Yarn plugin Babel wrote, and the
  `dependenciesMeta` that marks two dependencies optional.

`edge-cases.yarn.lock`, `crlf.yarn.lock` and `truncated.yarn.lock` are not
recordings. They are written by hand for this test suite and describe no real
package.

- `edge-cases.yarn.lock` collects the shapes the two recordings do not hold at
  once, in the spelling Yarn 4 writes them: a scoped registry package, an alias
  whose key is `widgets-v1`, a git dependency over `git+ssh:` and one over
  `https:` ending in `.git`, a tarball URL, `file:`, `link:` and `portal:`
  directories, a workspace member, a `patch:` of a registry package and a
  `patch:` of a git one, an `exec:` protocol no parser should guess at, an entry
  with no checksum, a `devDependencies` map (which a real Yarn does not write,
  because it folds those into `dependencies`) and a `dependenciesMeta` that marks
  one dependency optional. Its `checksum` values are the sha512 of
  `<name>@<version>` in hex behind the `10c0/` cache key, so a new entry's hash is
  `printf '%s' '<name>@<version>' | openssl dgst -sha512 -hex`.
- `crlf.yarn.lock` is the same shape with Windows line endings, which is what a
  repository checked out on Windows without a `.gitattributes` holds.
- `truncated.yarn.lock` is the first 508 bytes of `edge-cases.yarn.lock`, which
  stops in the middle of a quoted value. It pins that a half written file is
  reported rather than read as an empty one.

To record another file, download it at a fixed commit and add a row above:

```sh
curl -fsS -o <name>-<version>.yarn.lock \
  https://raw.githubusercontent.com/<owner>/<repo>/<commit>/yarn.lock
```
