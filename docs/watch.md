# Monitoring a reviewed baseline

`watch` re-evaluates packages a project already uses, even when no lockfile
changes. It can notice a newly published advisory, a changed current owner set,
or a change in which checks have enough data to run.

Create a baseline, review its observations, and commit the reviewed file first:

```sh
trustdiff baseline .
git diff -- .trustdiff/baseline.json
trustdiff watch . --interval 1h
```

The path must be a directory. The command finds `.trustdiff/baseline.json` upward
from that directory, like `baseline`. A missing, empty or malformed baseline is
an error. Policy discovery starts from the working directory; pass `--policy`
when watching a project from elsewhere.

The baseline and policy are loaded once. Each cycle evaluates the exact versions
recorded in that file. It never overwrites the baseline, approves new owners,
follows lockfile changes, writes persistent watch state, or opens GitHub issues.
Restart after intentionally reviewing a different baseline or changing policy.
`baseline` records one version per package, so watch cannot cover additional
locked versions absent from that record; use `scan` to evaluate every lock entry.

## Scheduling and freshness

The first evaluation starts immediately. Subsequent evaluations start after the
preceding evaluation finishes plus `--interval`. The default is one hour; valid
values are Go durations from `1m` through `24h` (for example `90m` or `2h30m`).
Slow evaluations never overlap or queue missed intervals.

Online cycles request fresh registry and advisory data using a new loader and
bypass the persistent HTTP cache. They neither read nor update that cache, so
normal cache TTLs do not delay detection beyond the polling schedule. Registry
rate limits, upstream publication/indexing delays and the time a full evaluation
takes still apply. Cargo uses the regular API, not the bulk snapshot. Short
intervals can be expensive for a large baseline.

`--offline` reads existing caches and the installed OSV index, even if they are
old. It cannot discover changes that have not reached those local sources.
Missing data appears as skipped checks; `on_data_unavailable: fail` can make a
one-shot run exit 3. `--offline` and `--no-cache` cannot be combined.

For an external scheduler, run one evaluation and let the scheduler retain the
output and decide how to notify you:

```sh
trustdiff watch . --once --format json > observation.jsonl
trustdiff watch . --once --offline --format json
```

`--once` returns the ordinary report status: 0 for no findings at the configured
failure threshold, 1 for findings at that threshold, 2 for invalid input, or 3
for required unavailable data. Continuous mode keeps running through findings
and source outages; inspect each emitted report's `summary.exit_code`. Ctrl+C
cancels requests or waiting and exits 3. Completed earlier events remain valid;
an interrupted output write may leave a partial final line.

## Reading events

Human output prints the initial report, then only changed observations. JSON is
one complete [`trustdiff.watch/1`](../schema/watch.v1.json) event per line, with
these fields (its schema references the sibling report schema):

| Field | Meaning |
| --- | --- |
| `schema` | Always `trustdiff.watch/1`. |
| `kind` | `initial` for the first observation, otherwise `changed`. |
| `observed_at` | UTC time when the evaluation completed, not the upstream incident time. |
| `changes` | Sorted by package reference and check ID; empty for the initial event. |
| `report` | A complete ordinary [`trustdiff.report/1`](../schema/report.v1.json) report. |

Each change has `ref`, `check`, and `kind`. Trust checks use `findings_added`,
`findings_changed`, `findings_cleared`, `coverage_lost`, `coverage_restored`, or
`skip_changed`. A disappeared finding is called cleared only if that check ran
successfully on both adjacent observations. Losing data is never called a fix.
Recovery after an outage emits `coverage_restored`; inspect its current report.
Elapsed age text alone produces no event, but a cooldown ending does.

`--guarddog` adds the optional external analysis to each cycle before comparison.
Its change records use `check: "guarddog"`, with `analysis_added`,
`analysis_changed`, `analysis_not_requested`, or coverage lost/restored. A package
that no longer has a warn/block metadata finding is no longer selected for that
analysis; this is not a source-code clearance. Normal GuardDog availability,
offline, timeout and exit rules still apply.

JSON notes go to stderr. SARIF and Markdown are rejected because this command
produces an event stream. Restarting always emits a fresh initial report; events
are not deduplicated across process restarts. There is no heartbeat output for
unchanged observations.

TD003 in watch compares the recorded maintainers with **current** registry
owners, including npm releases whose publication metadata still names the old
owners. Evidence retains the baseline's observation date and pinned version.
That comparison cannot establish who owned a crate at an earlier release date:
the registry and public dump do not provide complete historical ownership. The
other checks retain their usual evidence and limitations; lockfile-only checks
are skipped because a baseline contains no lockfile entries.

See [ADR 0006](adr/0006-watch-observations.md) for the design decision.
