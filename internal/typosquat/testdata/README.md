# Test data for internal/typosquat

## typosquats.csv (recall corpus)

- Source: https://github.com/ecosyste-ms/typosquatting-dataset, file `typosquats.csv` at the repository root (the only data file in the repository; layout verified 2026-09-09).
- Fetched 2026-09-09 from https://raw.githubusercontent.com/ecosyste-ms/typosquatting-dataset/main/typosquats.csv at commit `fd0bde98d200efe5c282a07edc4c68fba13252c6` (2025-12-17, the head of `main` that day).
- License: CC0 1.0 Universal (the repository's LICENSE file).
- Copied whole, unmodified: 143 rows with the columns `malicious_package, target_package, ecosystem, registry, classification, source`. By ecosystem: 95 PyPI, 35 npm, 8 Go, 4 GitHub Actions, 1 crates.io. The dataset is smaller than the roughly 200 entries the plan expected; it is the complete curated set the project publishes.
- `TestRecall` uses the npm, PyPI and crates.io rows whose target is in the embedded lists (the Go and GitHub Actions rows have no list) and requires at least 80 percent of them to be flagged.

## Popular list sources (fixtures for Fetch and Refresh)

The live artifacts are large, so the fixtures below carry the live shape, verified 2026-09-09, truncated by hand to a handful of entries. The parsers read only the fields kept here.

- `top-pypi-packages.json`: https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json (789 KB, 15000 rows live). The envelope (`last_update`, `source`, `meta`) is kept and `rows` is cut to the first five, in the live order (by 30-day downloads).
- `npm-high-impact-top.js`: https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js (404 KB, 17338 names live). The `export const top = [` line and the first five names, most downloaded first.
- `npm-rank.json`: https://github.com/tristan-f-r/npm-rank/releases/download/latest/raw.json (6.1 MB, 10000 objects live; the release asset is dated 2024-11-27). The first five objects, reduced to `name`, `version` and `description`; the live objects also carry `keywords`, `publisher`, `maintainers` (with e-mail addresses) and `links`, none of which the parser reads.
- `crates-page1.json`, `crates-page2.json`: recorded whole with `record-fixture` (see below) using `per_page=5` rather than the 100 `Fetch` asks for, because a live page of 100 crates is about 97 KB. The test server serves them by page number and ignores `per_page`.

## Embedded snapshot (internal/typosquat/data)

Generated with `go run ./scripts/gen-toplists` on 2026-09-09 from the sources above plus 50 pages of https://crates.io/api/v1/crates?sort=downloads&per_page=100 (5000 crates). The NOTICE line of each file records the source URL, the fetch date and the license observed:

- PyPI: the hugovk/top-pypi-packages repository has no license file; the Zenodo record its README links to (https://zenodo.org/records/22225583) lists CC BY 4.0.
- npm: both sources are MIT (LICENSE files in wooorm/npm-high-impact and tristan-f-r/npm-rank, the latter formerly LeoDog896/npm-rank).
- crates.io: https://crates.io/data-access states no license for API data; it asks for at most one request per second and an identifying User-Agent, which internal/httpcache sends.

`cache refresh-lists` (typosquat.Refresh) downloads the same sources into the `lists` directory under the trustdiff cache directory; that copy is preferred for 30 days.

### Regenerating the snapshot with gen-toplists

```bash
go run ./scripts/gen-toplists            # writes internal/typosquat/data/{npm,pypi,cargo}.txt
go run ./scripts/gen-toplists -v         # logs every request
go run ./scripts/gen-toplists -pages 10  # fewer crates.io pages, for a quick local check
go run ./scripts/gen-toplists -out /tmp/lists
```

The script downloads the four sources through `internal/httpcache` with the trustdiff User-Agent and no disk cache, so a run never reuses a copy a previous run left behind. It makes one request to hugovk.dev, two to GitHub and, by default, 50 to crates.io, which the client spaces at one request per second: a full run takes about a minute. Nothing is written unless every source succeeds, and each file is written to a temporary name and renamed into place. Every list is capped at 14900 names, so each file stays under 15000 lines; the least popular names are the ones dropped.

Regenerate when a source changes shape (`TestFetch` serves the truncated fixtures above and breaks first), or roughly once per release so the snapshot tracks the sources, which update monthly at most. After a run: check that `TestEmbedded` still passes (size, order, NOTICE line), check the recall figure `TestRecall` logs with `go test ./internal/typosquat -run TestRecall -v`, update the fetch date in this README, and commit the three data files together.

# Recorded fixtures

Real responses recorded once with `go run ./scripts/record-fixture`; tests serve them with httptest. Do not edit by hand.

- `crates-page1.json`: GET https://crates.io/api/v1/crates?sort=downloads&per_page=5&page=1 (HTTP 200, 4736 bytes, recorded 2026-09-09)
- `crates-page2.json`: GET https://crates.io/api/v1/crates?sort=downloads&per_page=5&page=2 (HTTP 200, 4741 bytes, recorded 2026-09-09)
