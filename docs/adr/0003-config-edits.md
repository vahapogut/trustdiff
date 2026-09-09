# ADR 0003: Locate keys with a parser, edit configuration files by line

Date: 2026-09-09
Status: accepted

## Context

Milestone M3 adds `doctor`, which reads the hardening settings of every package
manager in a repository and, with `--fix`, writes the ones that are missing or wrong.
The files it touches are in eight shapes: ini (`.npmrc`, `pip.conf`), YAML
(`pnpm-workspace.yaml`, `.yarnrc.yml`, `.github/dependabot.yml`, workflow files),
TOML (`bunfig.toml`, `pyproject.toml`, `uv.toml`, `poetry.toml`), JSON
(`package.json`, `renovate.json`) and JSONC (`deno.jsonc`, and `bun.lock` in M4).

These are not files a tool owns. A person wrote them, a reviewer reads the diff, and
what they hold beyond the key names carries meaning: the comment above a setting, the
order the keys are in, two-space or four-space indentation, a blank line separating
two blocks, a YAML anchor reused three keys later, a trailing comma somebody left for
the next edit. A JSON `package.json` sits in the same commit as a lockfile and a
formatter's configuration, so even the choice of tabs is somebody's decision.

Reading a file into a document, changing one value and writing the document back
loses that. `yaml.v3` marshals comments only through the node API and reflows what it
does keep; `encoding/json` orders the keys of a map by name and knows nothing of the
indentation the file had; `BurntSushi/toml` has no encoder that preserves comment
placement. A `doctor --fix` that reformatted `package.json` while adding one key
would produce a diff nobody can review and would be turned off after the first use.

A second requirement pulls the same way. `--fix` has to be idempotent: running it
twice must produce one change, not two, and running it on an already correct file
must produce none. That is easy when the tool knows exactly which bytes hold the
value and compares them before writing, and hard when it rebuilds the file every time.

## Decision

**Parse to locate, never to rewrite.** Every format's reader answers three questions
and nothing else: does this key exist, what value does it hold, and where in the file
does that value sit. The edit is then a line operation on the original bytes.

- YAML through `yaml.v3`'s node API, which reports `Line` and `Column` for every node.
- JSON through `encoding/json`'s `Decoder.InputOffset`, turned into a line by the
  `LineIndex` that `internal/lockfile` already has.
- JSONC through a pre-processor that replaces comments and trailing commas with
  spaces rather than removing them, so every offset in the stripped text is the same
  offset in the file on disk.
- TOML through `BurntSushi/toml`'s `MetaData`, which says which keys are defined, plus
  the line scanner written for `Cargo.lock`, which finds the line a key sits on.
- ini through a reader written here: `key=value`, the repeated `key[]=value` npm
  accepts, `;` and `#` comments, and `[section]` headers for `pip.conf`. It keeps the
  line of every key, leaves `${ENV}` unexpanded, and surfaces only the keys a rule
  asks for.

**Write by line.** A value that exists is replaced in the line range it occupies. A
key that does not exist is inserted at an anchor the rule names: after the last key of
its section for ini and TOML, at the end of the mapping it belongs to for YAML and
JSON. The file's own indentation is measured from the block being edited and reused,
the newline style is preserved as found, and the presence or absence of a trailing
newline is left as it was. Nothing else in the file changes, which is what makes the
unified diff short enough to read.

**Refuse rather than guess.** A key whose value sits in a construct the writer cannot
edit safely is reported at its current value and left alone, with the reason in the
scorecard: a YAML anchor, an alias or a merge key, a flow mapping that spans lines, a
multi-line string, a value that interpolates an environment variable. `doctor` says
what to set and where, and the person edits it. A wrong fix in a configuration file is
worse than no fix, because the setting looks present afterwards.

**Write atomically, with a backup and a preview.** The new content goes to a temporary
file in the same directory and is renamed over the original, so an interrupted run
leaves either the old file or the new one. The original is first copied to
`<file>.trustdiff-backup-<timestamp>` with its mode preserved. The preview is a
unified diff from `internal/textdiff`, a line-based diff ported from the Go standard
library's `internal/diff` with its BSD copyright notice kept, because shelling out to
`git diff` would make the output depend on a binary that need not be there and on the
user's own diff configuration.

**A separate document schema for `doctor`.** The scorecard is published as
`schema/doctor.v1.json` with `"schema": "trustdiff.doctor/1"`, not as a subject inside
`report.v1`. A report subject requires a package ref whose ecosystem is one of the
registries, and its check ids match `TD###`. A configuration file is not a package in
a registry, and a doctor rule is not a check that read one. Fitting it in would mean
either widening the report schema's ecosystem enum with something that is not an
ecosystem, or writing a package ref that names no package. The two documents share
their `tool`, `policy` and `summary` shapes, including the exit code, so a script that
reads one already knows how to read the other.

## Consequences

Each format needs a reader and a writer of its own, which is more code than calling a
marshaller. That cost buys a diff a reviewer can approve in a pull request, an idempotent
`--fix`, and a tool that can be pointed at somebody else's repository without
reformatting it.

Round-trip tests are the guard, one per format, asserting that a file with comments,
blank lines and its own indentation comes out byte for byte identical except for the
line the rule changed: a two-space `pnpm-workspace.yaml` with a comment above the key
and a blank line after it, an `.npmrc` with repeated `key[]=` entries, a `deno.jsonc`
with trailing commas and a block comment, a `pyproject.toml` where the key belongs in
a table that already exists and one where the table has to be created.

The refusal cases are a known limit, not a defect to fix later. They are reported, so
a project that uses anchors in `.yarnrc.yml` still gets the scorecard and the
instruction, and only loses the automatic write.
