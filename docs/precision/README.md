# The reports docs/precision.md counts from

Every number in [../precision.md](../precision.md) is counted from a file in this
directory. They are `trustdiff --format json` output, unedited, from the run of
2026-09-12 that document describes.

| File | Command |
|---|---|
| `<owner>-<repo>.json` | `trustdiff scan <checkout> --format json` |
| `<owner>-<repo>.doctor.json` | `trustdiff doctor . --format json`, run from inside the checkout so the `root` it records is `.` |
| `<owner>-<repo>.diff.json` | `trustdiff diff --base <commit> --format json`, run from inside the checkout |

Every command ran with `TRUSTDIFF_NOW=2026-09-12T12:00:00Z`, the default policy, no
allow entries and live registries. Which repository each file belongs to, the commit
it was pinned at and what the run cost are in the tables of `precision.md`.

The `tool` block of each file names the build that produced it. These are not
fixtures and no test reads them: they are the evidence for a document, and a rerun at
the same commits with a later release will not reproduce them, because the registries
keep changing underneath.
