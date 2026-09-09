# poetry.lock fixtures

Two real lockfiles, committed exactly as their projects published them, so that a
change in the format shows up here as a failing test rather than in somebody's
repository. Both were downloaded from `raw.githubusercontent.com` at the commit
named below. Neither needed trimming; both are well under the 200 KB a fixture is
allowed.

| File | Project | Repository | Taken from | Downloaded | License | Entries asserted |
| --- | --- | --- | --- | --- | --- | --- |
| `pendulum.poetry.lock` | pendulum | https://github.com/sdispater/pendulum | commit `6572356e3ad1d83b6ffb09f070bfd1ef1be39b80` | 2026-09-09 | MIT | 52 entries, 0 dropped |
| `cleo.poetry.lock` | cleo | https://github.com/python-poetry/cleo | commit `9c5197d407ac18806b1531b57a2a723760ef5c36` | 2026-09-09 | MIT | 53 entries, 0 dropped |

pendulum was locked by Poetry 2.3.2 and is `lock-version` 2.1. It is the one with
both kinds of group: four of its packages carry `groups = ["main", ...]` and are
runtime dependencies, and the other forty eight are only in `benchmark`, `build`,
`dev`, `doc`, `lint`, `test` or `typing`, which is what makes an entry Dev. Every
package in it comes from the default index, so none carries a source table.

cleo was locked by Poetry 2.2.1 and is `lock-version` 2.1 as well. At that commit
cleo declares no runtime dependencies at all, so not one of its 53 packages is in
the `main` group and every entry is Dev. It is here as the file that proves the flag
is read from the file rather than guessed from the position of an entry.

The rest are written by hand for these tests and describe no real distribution. They
are not Poetry output:

| File | What it covers |
| --- | --- |
| `sources.poetry.lock` | every source kind including git with and without a resolved commit, a directory, a file, a URL and an origin the parser does not know; a name PEP 503 rewrites; `optional = true`; a version with only wheels; a version with no artifact at all |
| `legacy-v1.poetry.lock` | the first format versions: `lock-version` 1.1, one group named in `category`, and the artifact hashes in a `[metadata.files]` table instead of on the package |
| `broken.poetry.lock` | tables the parser has to drop, followed by a package it can still read |
| `crlf.poetry.lock` | `sources.poetry.lock` with CRLF line endings, so the line numbers are proved against a Windows checkout |
| `truncated.poetry.lock` | the first 900 bytes of `pendulum.poetry.lock`, cut inside an inline table, which must be reported and must not panic |

The hashes in the hand written files are the sha256 of the file name they sit next
to rather than of any archive, so a new artifact's hash is
`printf '%s' '<file name>' | openssl dgst -sha256`.

To record another file, download it at a fixed commit and add a row above:

```
curl -fsS -o <name>.poetry.lock \
  https://raw.githubusercontent.com/<owner>/<repo>/<commit>/poetry.lock
```
