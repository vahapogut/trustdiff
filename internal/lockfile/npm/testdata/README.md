# package-lock.json fixtures

Real lockfiles, recorded once so the tests never touch the network. Each was
downloaded from `raw.githubusercontent.com` at the pinned commit named below and
is committed unmodified, under the license the project carried at that commit.

| File | Project | Source | Commit or release | Date | License |
|---|---|---|---|---|---|
| `superset-frontend-package-lock.json` | Apache Superset | https://github.com/apache/superset/blob/68528e33086f8324895131ff4085c96747a5add4/superset-frontend/package-lock.json | commit `68528e33086f8324895131ff4085c96747a5add4` | 2026-09-09 | Apache-2.0 |
| `minimatch-package-lock.json` | minimatch | https://github.com/isaacs/minimatch/blob/6410ef32f59e4842121ca13eefacdf0b3da8533c/package-lock.json | release `v5.1.0`, commit `6410ef32f59e4842121ca13eefacdf0b3da8533c` | 2022-05-16 | ISC |
| `rimraf-v1-package-lock.json` | rimraf | https://github.com/isaacs/rimraf/blob/8c10fb8d685d5cc35708e0ffc4dac9ec5dd5b444/package-lock.json | release `v3.0.2`, commit `8c10fb8d685d5cc35708e0ffc4dac9ec5dd5b444` | 2020-02-09 | ISC |

What each one is here for:

- **Apache Superset** is the large one: lockfileVersion 3, 3425 entries in
  `packages`, which is where the performance target of a 2000 entry lockfile is
  measured. It is a real npm workspace monorepo, so it carries the cases a small
  file cannot: 25 `"link": true` entries pointing at workspace members, workspace
  members of their own with a `name` that differs from their directory, 1071
  nested `node_modules` duplicates, eight aliased dependencies (`d3v3`,
  `string-width-cjs` and the rest, whose key is the alias and whose `name` is the
  package that is really installed), a `devOptional` entry, an install resolved
  from git and one resolved from a tarball URL that is not a registry.
- **minimatch** is lockfileVersion 2, which carries both the `packages` map and
  the lockfileVersion 1 `dependencies` tree that npm 6 reads. It proves the
  legacy tree is walked past rather than parsed, and its bundled `tap` subtree
  gives real entries that carry no `resolved` and no `integrity`.
- **rimraf** is lockfileVersion 1, the format npm 5 and npm 6 wrote. It has no
  `packages` map at all and exists to pin the error message.

`edge-cases-package-lock.json` is not a recording. It is written by hand for this
test suite and describes no real package: it collects the cases the recordings do
not all hold at once, in the shape npm writes them, so one table test can cover a
scoped name, a nested duplicate, a git dependency, a tarball URL, a `file:` path,
a workspace link, a bundled entry with no integrity, an extraneous entry, an
aliased dependency (`"widgets-v1": "npm:@acme/widgets@^1"`, whose key is the alias
and whose `name` is what is installed), a dependency declared by the workspace
member rather than by the root, and the `dev`, `optional` and `devOptional` flags.
Its `integrity` values are the sha512 of `<name>@<version>`, so a new entry's hash
is `printf '%s' '<name>@<version>' | openssl dgst -sha512 -binary | openssl base64 -A`.

To record another file, download it at a fixed commit and add a row above:

```
curl -fsS -o <name>-package-lock.json \
  https://raw.githubusercontent.com/<owner>/<repo>/<commit>/<path>/package-lock.json
```
