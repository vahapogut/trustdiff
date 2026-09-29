# Unicode homoglyph data

`homoglyph_data.go` is derived from Unicode's official `confusables.txt`, not a
hand-maintained list of look-alike letters.

- Source: https://www.unicode.org/Public/security/latest/confusables.txt
- Upstream version: 18.0.0
- Upstream date: 2026-08-06, 01:05:35 GMT
- Retrieved: 2026-09-29
- SHA256: `6ed3ee967c9dfdf6677d563c9985182fbc50a2efb7d6059cd57b2e2ce18f5b92`
- License: Unicode License V3, reproduced in `LICENSE-Unicode` and the root
  `THIRD_PARTY_NOTICES`. Copyright 1991-2026 Unicode, Inc.

The official versioned 18.0.0 path returned 404 when recorded. The generator
therefore uses the official `latest` URL with a pinned checksum. A changed
upstream file fails regeneration until its version and data have been reviewed;
it never silently changes the embedded mapping.

Run `go run ./scripts/gen-confusables` from the repository root to fetch and
verify those bytes and regenerate the Go file. For an offline repeat from an
already downloaded copy, run:

```sh
go run ./scripts/gen-confusables -in /path/to/confusables.txt
git diff --exit-code -- internal/typosquat/homoglyph_data.go
```

The retained subset consists of one-scalar `MA` source records whose complete
target contains only ASCII letters, digits, dot, underscore or hyphen. Targets
are lowercased to match this package's canonical spelling and repeatedly mapped
through the same ASCII subset until stable, for example `m` becomes `rn`.
Multi-character targets are preserved. Records are sorted by source scalar so
regeneration is deterministic. There are 1,862 retained records.

Runtime comparison uses the same skeleton for the candidate and popular name,
including scope and separators. A new finding requires at least one non-ASCII
source substitution and an exact match to an ASCII popular name's skeleton. The
older digit-confusable rule keeps its existing behavior and evidence. An
unmapped character is preserved; it is never removed or transliterated. A
single-script non-Latin name is not suspicious by itself, although an exact
skeleton collision with a different popular ASCII name is still reported.

This subset is not a complete UTS #39 implementation. It intentionally omits NFD
normalization, script classification and non-ASCII target mappings. The tests
cover Cyrillic, Greek and mathematical-letter substitutions, legitimate
non-Latin names, scope substitutions, multi-character mappings, all retained
canonical scalars and skeleton idempotence. Generator tests use synthetic input
and normal `go test` never downloads Unicode data.
