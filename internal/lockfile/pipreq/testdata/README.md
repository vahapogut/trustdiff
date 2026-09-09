# requirements file fixtures

One real requirements file, committed exactly as its project published it, so that a
change in what pip-compile writes shows up here as a failing test rather than in
somebody's repository. It was downloaded from `raw.githubusercontent.com` at the
commit named below. It needed no trimming: at 186 KB it is under the 200 KB a
fixture is allowed.

| File | Project | Repository | Taken from | Downloaded | License | Entries asserted |
| --- | --- | --- | --- | --- | --- | --- |
| `warehouse-main.requirements.txt` | Warehouse, the software that runs PyPI | https://github.com/pypa/warehouse | `requirements/main.txt` at commit `14cccca465443051fc905781b74d7489eb60e190` | 2026-09-09 | Apache-2.0 | 184 entries, 0 dropped |

Warehouse is the file this parser was written for: 2681 lines of `pip-compile
--generate-hashes` output, every one of its 184 requirements pinned with `==` and
carrying between two and twenty six `--hash=sha256:` continuations, and a `# via`
comment under each one. It also carries the two things a generated file does that a
hand written one does not: the `setuptools` requirement under the "considered to be
unsafe" comment at the end, and requirements whose hash list runs to more than
twenty physical lines, which is what proves the line number reported is the one the
requirement starts on.

The rest are written by hand for these tests. They are not pip-compile output:

| File | What it covers |
| --- | --- |
| `edge-cases.requirements.txt` | every shape of line the parser decides about: four entries, including one with extras and a marker, one with the hash as a separate argument and one after a comment that ends in a backslash; and fifteen lines that are dropped, one per reason |
| `crlf.requirements.txt` | `edge-cases.requirements.txt` with CRLF line endings, so the line numbers and the continuations are proved against a Windows checkout |
| `truncated.requirements.txt` | a file that ends on a line continuation with nothing after it, which must be reported and must not panic |

The hashes in the hand written files are the sha256 of the artifact name they stand
for rather than of any artifact, so a new one is
`printf '%s' '<file name>' | openssl dgst -sha256`.

To record another file, download it at a fixed commit and add a row above:

```
curl -fsS -o <name>.requirements.txt \
  https://raw.githubusercontent.com/<owner>/<repo>/<commit>/<path>/requirements.txt
```
