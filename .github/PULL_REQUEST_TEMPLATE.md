<!-- Title as a conventional commit: type(scope): summary, for example feat(checks): add TD016 abandoned-package -->

## What and why

<!-- One paragraph. Link the issue or the ADR this implements. -->

## Checklist

- [ ] Tests added or updated, table-driven where there is more than one case, and none of them touch the network (fixtures under `testdata/`, served with `httptest`).
- [ ] `make lint`, `make test` and `make vet` pass locally and `gofmt -l` prints nothing.
- [ ] `CHANGELOG.md` has an entry under Unreleased, or the change has no user-visible effect.
- [ ] Documentation updated where behavior changed: README, `docs/checks.md`, the `policy init` comments, the schemas.
- [ ] The title is a conventional commit (`type(scope): summary`) and each commit contains one change.
- [ ] No new Go module. If one was unavoidable, the dependency policy discussion in CONTRIBUTING.md happened first and an ADR is part of this change.
