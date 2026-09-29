# 0006: Watch reviewed baseline observations without approving changes

Status: accepted

## Context

A pinned version can gain an advisory or its package can change owners without a
lockfile edit. `diff` cannot notice that event. A baseline already records exact
package versions and observed trust signals, but updating that file would approve
the very changes a monitor should report.

## Decision

`watch [path]` loads an existing, nonempty baseline and the policy once. It
evaluates those pinned versions immediately and then sequentially, waiting the
configured interval after each completed evaluation. The interval defaults to
one hour and accepts one minute through 24 hours. `--once` performs one evaluation
for an external scheduler. Neither form writes the baseline or persistent watch
state, follows lockfile edits, or sends messages to external services.

Each online cycle uses a fresh loader and bypasses the HTTP cache, so a polling
interval is not silently extended by registry or advisory cache TTLs. Offline
runs use existing caches and explicitly cannot observe new remote information.
The current-owner comparison replaces TD003's usual npm per-release preference:
watch compares current owners with the reviewed baseline even when the pinned
version and its publication-time maintainer list have not changed. Other checks
and the existing policy, failure thresholds and unavailable-data rules apply.

The first observation is always emitted. Subsequent output contains only changes
in check coverage, skip reasons or finding facts. Elapsed age text alone does not
trigger an event; a cooldown ending does. A missing finding is called cleared
only when the check completed on both observations. Coverage loss is never a
claim that a finding was resolved. Events are sorted by package and check.

Human output includes the current ordinary report. JSON is newline-delimited
`trustdiff.watch/1` events embedding the unchanged `trustdiff.report/1` document.
SARIF and Markdown are rejected because concatenating those document formats
would produce an ambiguous stream. `--once` returns the report's exit code;
continuous runs keep monitoring findings and source failures. Cancellation stops
the loop and retains the existing exit-3 contract.

## Consequences

Online polling has the cost of a fresh audit, so requests retain the normal
per-host rate limits and runs never overlap. Restarting emits a new initial
observation. Users explicitly review and refresh a baseline outside this command.
Baseline observations prove what the registry reported at observation time; they
do not reconstruct crates.io ownership at a release date. An event timestamp is
the time of evaluation, not the time an upstream incident happened.
