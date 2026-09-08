# trustdiff

trustdiff is a single-binary command line tool that finds trust regressions in a project's dependency tree before they land: a version published by a different account than the previous ones, a package that quietly lost its provenance, a release that introduces an install script or a new transitive dependency, a suspiciously young or look-alike package, a version with a known malicious or vulnerable advisory. It works across npm (npm, pnpm, yarn, bun), PyPI (pip, uv, poetry) and crates.io, with Deno and JSR planned. A `doctor` command audits, and can fix, the native supply-chain hardening settings of every package manager it finds in a repository.

Status: early development. Version 0.0.1 is the project skeleton; the first usable release is 0.1.0. See [docs/PLAN.md](docs/PLAN.md) for the roadmap.

## Principles

- One static binary, no runtime, no vendor account.
- No telemetry, no auto-update, no analytics, no phone-home of any kind. The only network calls are the registry and advisory requests needed for the packages you ask about, and `--offline` turns those off too.
- Almost no dependencies of its own, because a tool about dependency risk should not add much of it.
- Anything that could not be evaluated is reported as skipped, never as a pass.

## License

Apache-2.0. See [LICENSE](LICENSE).
