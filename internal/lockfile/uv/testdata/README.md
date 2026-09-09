# uv.lock fixtures

Two real lockfiles, committed exactly as their projects published them, so that a
change in the format shows up here as a failing test rather than in somebody's
repository. Both were downloaded from `raw.githubusercontent.com` at the commit
named below.

| File | Project | Repository | Taken from | Date | License |
| --- | --- | --- | --- | --- | --- |
| `uv-fastapi-example.uv.lock` | uv-fastapi-example | https://github.com/astral-sh/uv-fastapi-example | commit `a5e5d41ec407e7268c7eebb2253f8b4da6c6acc9` | 2024-08-28 | MIT |
| `uv-docker-example.uv.lock` | uv-docker-example | https://github.com/astral-sh/uv-docker-example | commit `5748835918ec293d547bbe0e42df34e140aca1eb` | 2025-10-05 | Apache-2.0 |

The FastAPI example is an early uv.lock: format version 1 with no revision, and the
project itself is virtual, which is the entry the parser drops. The Docker example
is what a current uv writes: a revision, upload times on every artifact, an editable
project, and a dependency group next to the runtime dependencies.

The rest are hand written for the tests and say so in their first line. They are not
uv output:

| File | What it covers |
| --- | --- |
| `sources.uv.lock` | every source kind, artifacts with no hash, the `[manifest]` table, workspace members, a package locked at two versions |
| `broken.uv.lock` | tables the parser has to drop, followed by a package it can still read |
