# Baseline test fixtures

Nothing here is downloaded and no real package is described: the values are invented,
so no fixture in this directory carries a source URL, a recording date or a license.

## baseline.json.golden

`go test ./internal/baseline/ -update` regenerates it from the fixture file built in
`file_test.go`. It is the document `.trustdiff/baseline.json` contract: entries sorted
by ecosystem and then name, times in UTC with second precision, two-space indentation
and a trailing newline. Review the diff of a regenerated golden file like code, and
keep it in LF line endings.
