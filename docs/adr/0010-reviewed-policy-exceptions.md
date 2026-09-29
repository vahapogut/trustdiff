# 0010: Narrow, reviewed policy exceptions

Status: accepted, 2026-09-29.

`policy allow <check> <package-ref> --reason ... --expires YYYY-MM-DD` builds an
entry in the existing policy schema. Check IDs and names are accepted, while
wildcards, missing ecosystems, empty reasons and expired dates are refused.
Versioned references restrict the exception to that version; an unversioned
reference explicitly selects all versions of that one package.

The default is a unified-diff preview. `--write` opts into a timestamped backup
and atomic replacement, preserving the original file's comments and all lines
outside the allow sequence. Ambiguous anchors or flow-style containers are
refused rather than rewritten. Existing identical entries are a no-op; existing
entries selecting the same check/package with a different review are not silently
replaced. A strict schema parse validates both before and after the edit.
