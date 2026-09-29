# ADR 0007: Fetch download counts when an enabled check needs them

Date: 2026-09-29
Status: accepted

## Context

The loader currently prefetches downloads for every resolved package and the
runner reads them into every subject. Most checks do not use counts. npm supports
at most 128 unscoped names per bulk request, but scoped names need separate
requests. The official [download count documentation](https://github.com/npm/registry/blob/main/docs/download-counts.md)
was rechecked on 2026-09-29. A scan dominated by scoped packages pays for these
requests even when low-usage is disabled and typosquat-suspect needs no counts.

Counts are evidence, so leaving a check enabled while quietly omitting a count
it needs would change the security result. TD012 gives registry counts precedence
over deps.dev LOW_USAGE, including when the numeric threshold is zero. TD008 can
use counts to identify a non-list neighbor and to decide whether an old candidate
has enough users to lower the finding's level. TD007 also uses counts on demand
for a newly introduced dependency.

## Decision

Remove download counts from the generic prefetch and subject-loading phases.
Offer an optional PrefetchDownloads operation on the loader, forwarded by the
baseline wrapper. The runner selects only resolved subjects with an enabled,
applicable, non-allowlisted low-usage check for that batch. The existing npm bulk
partitioning, memoization, partial-result handling and failure handling remain.
Loaders without the optional operation still work through their Downloads method.

TD012 obtains its count through the loader when it runs. TD008 obtains the
candidate count only when a non-list similarly named package needs comparison,
or after a real candidate's age permits the established-package demotion.
TD007 keeps its existing on-demand lookups. Checks use a private copy of the
subject's download state so a timed-out check cannot race with a later check.
Transport failures keep their unavailable status; an unrequested count is neither
a fabricated zero nor an outage. Active allow entries for TD008 and TD012 produce
an explicit policy skip before those checks request data.

Always loading counts was rejected because disabled and allowed findings cannot
use them. Disabling the default low-usage check or substituting deps.dev for an
unrequested registry count was rejected because either changes the findings.
Moving all requests into checks without batching was rejected because it would
replace efficient unscoped npm batches with individual requests.

## Consequences

Scans that disable or allow low-usage avoid counts unless TD008 or TD007 needs
them. Default low-usage still requires counts for every evaluated package, so this
change does not promise fewer scoped npm requests under the default policy.
Counts shared by checks and package versions remain memoized for the run.
Regression tests count real httptest requests as well as fake loader calls, and
assert findings, levels, fallback behavior, outages and allow expiry. No module,
report schema or policy schema is added.
