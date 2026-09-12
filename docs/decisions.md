# Decisions

Decisions taken during a run where asking was not an option, one line each, with
the date and the reason. A decision that changed a file names the commit that
carries it. This file is a record, not a policy: what it says was true when it was
written, and a decision that is later reversed gets a new line rather than an edit.

## 2026-09-12

- An untracked directory holding this run's own prompt file was moved out of the
  repository rather than committed or deleted. It is not repository content, every
  commit of this run has to leave the tree clean, and destroying a file somebody
  else put there is not this run's business, so it was moved to the session's
  scratchpad instead.
- The `release` environment was created with `can_admins_bypass` set to false. The
  API defaults it to true, which leaves an admin able to deploy without the
  approval the environment exists to require, and what this gate is for is a tag
  push that cannot sign anything on its own.
- The tag ruleset bypasses the admin repository role rather than naming a person.
  A ruleset cannot name the owner of a personal repository as a bypass actor, and
  the admin role here is one account, so the effect is the one asked for: only that
  account can create a `v*` tag.
- Every commit of this run is verified with `gofmt`, `go vet`, the offline
  `go test ./...` and `golangci-lint` at the pinned version. The gate runs once per
  push rather than once per commit where the commits of that push touch
  documentation alone, and again whenever Go code changes. Nothing lands
  unverified.
