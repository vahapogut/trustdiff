# deno.lock fixtures

Two real lockfiles, committed exactly as their projects published them, so that a
change in the format shows up here as a failing test rather than in somebody's
repository. Both were downloaded from `raw.githubusercontent.com` at the commit
named below. Neither needed trimming; both are well under the 200 KB a fixture is
allowed.

| File | Project | Repository | Taken from | Downloaded | License | Entries asserted |
| --- | --- | --- | --- | --- | --- | --- |
| `deployctl-v4.deno.lock` | deployctl | https://github.com/denoland/deployctl | commit `873e36ef145b98c8762b777e2b1532e4096f4f94` | 2026-09-09 | MIT | 24 entries, 4 dropped |
| `deno-graph-v5.deno.lock` | deno_graph | https://github.com/denoland/deno_graph | commit `d0b13ee74e7d93aaac118b53ac4f1905b4d06404` | 2026-09-09 | MIT | 53 entries, 0 dropped |

deployctl is format version 4 and is the one that mixes everything: 23 JSR packages,
one npm package, four `remote` URL entries that the parser drops, and a `workspace`
block naming thirteen of the JSR packages. Its npm package, `keychain`, is imported
in code with a full `npm:keychain@1.5.0` specifier rather than through the
deno.json, so the workspace block does not name it and it is transitive; that is the
case that proves Direct is read from `workspace` and not from `specifiers`.

deno_graph is format version 5, which is what a current Deno writes. It has no
`remote` section at all, and its npm section carries the peer suffixed keys that
version 5 introduced, `@octokit/plugin-paginate-rest@14.0.0_@octokit+core@7.0.7`,
where the version is only the part before the underscore.

The rest are written by hand for these tests and describe no real package. They are
not Deno output:

| File | What it covers |
| --- | --- |
| `sources.deno.lock` | a workspace with members and a `packageJson` list, a JSR entry with no integrity, an npm key with a peer suffix, a transitive JSR package, and a `remote` URL that is dropped |
| `broken.deno.lock` | keys that hold no version, an entry whose value is a string, and a workspace requirement that `specifiers` never resolves |
| `wrong-types.deno.lock` | one member of `specifiers` and three of `workspace` written with a value of the wrong type, each of which must cost only itself while the three packages of the file are still read |
| `crlf.deno.lock` | `sources.deno.lock` with CRLF line endings, so the line numbers are proved against a Windows checkout |
| `version-3.deno.lock` | the format before version 4, which keeps its maps under `packages` and is refused with a message saying so |
| `truncated.deno.lock` | the first 700 bytes of `deno-graph-v5.deno.lock`, cut in the middle of a string, which must be reported and must not panic |

The integrity values in the hand written files are real hashes of the package name
and version rather than of any archive, so a new entry's JSR hash is
`printf '%s' '<name>@<version>' | openssl dgst -sha256` and its npm hash is
`printf '%s' '<name>@<version>' | openssl dgst -sha512 -binary | openssl base64 -A`
with `sha512-` in front.

To record another file, download it at a fixed commit and add a row above:

```
curl -fsS -o <name>.deno.lock \
  https://raw.githubusercontent.com/<owner>/<repo>/<commit>/deno.lock
```
