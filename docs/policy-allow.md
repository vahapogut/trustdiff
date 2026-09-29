# Review one policy exception

```sh
trustdiff policy allow TD013 npm:vendored-lib@1.2.3 \
  --reason 'Reviewed pinned source commit and its changes' --expires 2026-12-31
```

This prints a unified diff. Add `--write` to save it with a timestamped backup
and atomic replacement. Check names such as `exotic-source` also work. The
policy is found using the normal discovery rules, or selected with `--policy`.
Create a new policy first with `trustdiff policy init` if none exists.

The helper accepts one exact package and check. A version restricts the exception
to that version; omitting it explicitly covers all versions of that package.
Wildcards and missing ecosystem prefixes are rejected. The reason and a
non-expired UTC date are required. An exception is valid through its expiry day;
after that normal policy processing reports TD000 and the check applies again.

Comments and unrelated settings are preserved. Ambiguous anchors, multiline
allow values and populated flow-style allow sequences must be edited manually.
An identical existing exception makes no change. A conflicting review is refused
instead of silently extending its lifetime. `--format json` reports the path,
diff, whether anything changed, whether it was written and the backup path.
