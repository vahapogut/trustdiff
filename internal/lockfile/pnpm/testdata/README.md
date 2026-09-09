# pnpm-lock.yaml fixtures

Real lockfiles, committed as their projects published them, so that a change in the
format is caught by a test rather than by a user. Each line names the project, the
file, the commit it came from, the date of that commit and the project's license.

| File | Project | Source | Commit | Date | License |
|---|---|---|---|---|---|
| `pathe-v9.yaml` | unjs/pathe | https://github.com/unjs/pathe/blob/bc7477a01f0bd60ada017add8142c9f9d69ccdc5/pnpm-lock.yaml | `bc7477a01f0bd60ada017add8142c9f9d69ccdc5` | 2026-07-08 | MIT |
| `pathe-v6.yaml` | unjs/pathe, release v1.1.1 | https://github.com/unjs/pathe/blob/055f50a6f1131f4e5c56cf259dd8816168fba329/pnpm-lock.yaml | `055f50a6f1131f4e5c56cf259dd8816168fba329` | 2023-06-01 | MIT |
| `workspace-v9.yaml` | pnpm/pnpm, test fixture `workspace-with-2-pkgs` | https://github.com/pnpm/pnpm/blob/fc2f33912e0dc3e05d4da906b3d838447a74868f/pnpm11/__fixtures__/workspace-with-2-pkgs/pnpm-lock.yaml | `fc2f33912e0dc3e05d4da906b3d838447a74868f` | 2026-06-20 | MIT |
| `workspace-v6.yaml` | pnpm/pnpm, release v8.15.9, test fixture `workspace-with-2-pkgs` | https://github.com/pnpm/pnpm/blob/afe8ecef1f24812845b699c141d52643d1524079/__fixtures__/workspace-with-2-pkgs/pnpm-lock.yaml | `afe8ecef1f24812845b699c141d52643d1524079` | 2024-07-17 | MIT |
| `git-protocol-v9.yaml` | pnpm/pnpm, test fixture `with-git-protocol-dep` | https://github.com/pnpm/pnpm/blob/fecfe8334b47f0acb742a4d78f8cc9e50c64c52b/pnpm11/__fixtures__/with-git-protocol-dep/pnpm-lock.yaml | `fecfe8334b47f0acb742a4d78f8cc9e50c64c52b` | 2026-07-09 | MIT |
| `git-protocol-v6.yaml` | pnpm/pnpm, release v8.15.9, test fixture `with-git-protocol-dep` | https://github.com/pnpm/pnpm/blob/afe8ecef1f24812845b699c141d52643d1524079/__fixtures__/with-git-protocol-dep/pnpm-lock.yaml | `afe8ecef1f24812845b699c141d52643d1524079` | 2024-07-17 | MIT |
| `h3-v9.yaml` | h3js/h3 | https://github.com/h3js/h3/blob/a5fdc86a6075506d71510aa5208739aa0b2bec29/pnpm-lock.yaml | `a5fdc86a6075506d71510aa5208739aa0b2bec29` | 2026-09-04 | MIT |

`pathe-v9.yaml` and `pathe-v6.yaml` are the same project four years apart, which is
why they are the pair the line numbers and the whole-file counts are asserted
against. The two pnpm fixtures cover what a small project rarely has: a workspace
with two importers depending on the same version, and a dependency written as
`github:kevva/is-negative#master`, which pnpm resolves to a tarball on the git host
rather than to a git checkout.

`h3-v9.yaml` is the file a current pnpm writes: two yaml documents joined by a
`---`, the first locking the package manager the project pins (nine entries, the
`pnpm` binary for each platform) and the second the project's own 428. It is here
because a parser that reads only the first document reports nine entries of a real
project and says nothing about the rest, which no other fixture would catch. It was
downloaded with:

```
curl -fsS -o h3-v9.yaml \
  https://raw.githubusercontent.com/h3js/h3/a5fdc86a6075506d71510aa5208739aa0b2bec29/pnpm-lock.yaml
```

## Hand-built

`exotic-v9.yaml`, `exotic-v6.yaml` and `tarballs-v9.yaml` are written by hand, not
produced by pnpm. Every package in them is invented, the hosts are under `.test`
(RFC 6761 reserves it and it can never resolve), and the integrity hashes are the
sha512 of the package key rather than of any tarball.

The two exotic files exist because the origins the checks care about most are the
ones a healthy public project does not have: a git checkout with a `repo` and a
`commit`, a tarball fetched from a URL, a linked directory, a package with no
integrity hash at all, and a dependency named by one importer and by no other. Each
file writes those in its own version's spelling, including the peer suffix pnpm
appends to a resolved version.

`tarballs-v9.yaml` is about the one field that cannot be read on its own. pnpm
keeps a `tarball` URL for a registry whose downloads are not spelled
`<registry>/<name>/-/<file>.tgz`, which is the case for GitHub Packages and npm
Enterprise and for every package when `lockfile-include-tarball-url` is set, so a
tarball is not by itself a package from outside the registry. The file holds a
GitHub Packages download, three packages from one private registry, the same layout
on a host nothing else in the file installs from, a dependency whose key states a
URL, and a resolution reached through a yaml alias, which pnpm resolves and a parser
reading the node tree has to resolve too.
