// Package jsr is the JSR (jsr.io) client. It implements registry.Source on top of
// the two hosts JSR serves, and it is the only code that knows their HTTP shapes.
//
// # Endpoints
//
// Verified 2026-09-09 against live responses, the documentation at
// https://jsr.io/docs/api and the OpenAPI document at
// https://api.jsr.io/.well-known/openapi (jsr API 1.1.0):
//
//	GET https://jsr.io/@<scope>/<name>/meta.json                          the version set
//	GET https://jsr.io/@<scope>/<name>/<version>_meta.json                the file manifest
//	GET https://api.jsr.io/scopes/<scope>/packages/<name>                 the package record
//	GET https://api.jsr.io/scopes/<scope>/packages/<name>/versions        publisher and provenance
//	GET https://api.jsr.io/scopes/<scope>/packages/<name>/versions/<v>    one version's record
//	GET https://api.jsr.io/scopes/<scope>/packages/<name>/versions/<v>/dependencies
//	GET https://api.jsr.io/scopes/<scope>/packages/<name>/downloads       90 days of daily counts
//	GET https://api.jsr.io/scopes/<scope>/members                         the scope members
//
// Two of those are recorded in testdata but never requested by this client, because
// nothing in model.VersionInfo comes from them. <version>_meta.json carries a file
// manifest (path, size and a sha256 per file), an exports map and a module graph,
// none of which the model has a place for; it deliberately omits the yanked flag,
// which the documentation says to read from meta.json instead, because the
// per-version document is immutable. The single-version record repeats what the
// versions list already gave and adds an SPDX license string, a newerVersionsCount
// and a symbolCount, none of which the model has a field for; unlike the versions
// list it does not carry the publishing user, so it cannot replace that request
// either.
//
// # Which host answers what
//
// meta.json is the registry API, the one JSR documents for tools that resolve and
// download packages. It carries the complete version set, the yanked flag per
// version, the latest version, and, for packages whose meta.json was regenerated
// after JSR started writing it, a createdAt per version. It carries no publisher,
// no provenance and no download count at all.
//
// Everything else comes from api.jsr.io, the management API. Its documentation asks
// callers not to use it "during registry operations", naming version lists and
// version metadata; trustdiff is not resolving or installing anything, and the
// publishing account, the Rekor log id and the download counts exist on no other
// host, so the version list stays the registry API's answer and the management API
// is asked only for the facts that are nowhere else. Every request identifies
// itself with the trustdiff User-Agent, which the same documentation asks for.
//
// JSR documents no numeric rate limit for reads: the quotas at
// https://jsr.io/docs/quotas-and-limits are all about publishing (scopes per user,
// packages per scope, publish attempts per week). The shared internal/httpcache
// client's default of ten requests per second per host therefore applies to both
// hosts, and nothing here times or throttles on its own.
//
// # What the API carries, and what it does not
//
// Carried, and mapped onto model.VersionInfo:
//
//	publish time    createdAt, from meta.json when it is there and from the
//	                management versions list otherwise
//	publisher       versions[].user.name, the account that published the version
//	yanked          meta.json versions[<v>].yanked
//	provenance      versions[].rekorLogId, the Sigstore Rekor transparency log
//	                entry of the SLSA statement JSR writes for a version published
//	                from GitHub Actions
//	dependencies    the kind "jsr" entries of the dependencies endpoint
//	downloads       the daily buckets of the downloads endpoint, summed over the
//	                seven days before now. They reach a caller through Downloads
//	                and never through VersionInfo, which JSR gives no per-version
//	                figure for
//
// Not carried, and therefore never guessed:
//
//   - No install scripts, because JSR has no install-time script mechanism at all.
//     A JSR package is source modules plus a config file; nothing in the registry
//     or the runtime runs a lifecycle hook when a package is added. VersionInfo.Scripts
//     is left empty as a fact, not marked unknown, so the install-script checks
//     can pass rather than skip.
//   - No yank message. The management API's yank operation takes a single boolean
//     (UpdatePackageVersionRequest is {yanked: bool}), so a yanked version has no
//     text to report and VersionInfo.Deprecated stays empty.
//   - No per-version maintainer set. Scope members are current state only, like
//     crates.io owners and PyPI roles, which is what leaves TD003 without a
//     previous set to compare with.
//   - No package-level integrity. The version manifest has a sha256 per file, not
//     one digest for the version, so VersionInfo.Integrity stays empty.
//   - No per-version download count. The downloads endpoint reports the package
//     total per day, plus a few recent versions; VersionInfo.WeeklyDownloads is -1.
//   - No workflow identity in the provenance. The endpoints carry the Rekor log id
//     but not what the statement inside the log says, so model.Provenance.Identity
//     stays empty rather than repeating the package's linked GitHub repository,
//     which can be relinked without republishing anything.
//   - No stable public handle for a user. The public User record has a uuid, a
//     display name and a GitHub numeric id, but no login, so publishers and owners
//     are named by their mutable display name and a rename reads as a change.
//
// # Two live shapes the OpenAPI document does not describe
//
// Both observed 2026-09-09 and both handled here rather than trusted from the spec.
// The versions list is paginated and wrapped: it answers {"items": [...], "total": N}
// with at most 100 items, takes page and limit query parameters (limit above 100 is
// capped at 100), and orders items newest first; the spec declares a bare array with
// no parameters. And of the two fields the spec marks required on a version record,
// lifetimeDownloadCount was absent from every live response and newerVersionsCount
// is present on the single-version record and absent from the list, so nothing here
// depends on either.
//
// # Applicability of the checks to a jsr: ref
//
// TD003, TD008, TD009 and TD010 skip for reasons that belong to the ecosystem;
// TD002, TD004 and TD005 skip only because their own Ecosystems() lists do not name
// model.JSR yet, even though the data below would let two of them run.
//
//	id     runs   why not, and what a skip would say
//	TD001  yes    publish time: meta.json createdAt, else the versions list
//	TD002  no     data is there (versions[].user.name); the check lists npm and
//	              cargo only, so the runner skips it before it sees the subject
//	TD003  no     "baseline required (arrives in M4)": JSR records scope members as
//	              current state, never a maintainer set per version
//	TD004  no     data is there (rekorLogId); the check lists npm, pypi and cargo only
//	TD005  no     npm only, and JSR has no install-time scripts to introduce
//	TD006  yes    and always passes: JSR has no install-time script mechanism
//	TD007  yes    the kind "jsr" dependencies; the deps.dev escalation cannot fire
//	              (no JSR system), the young and low-usage ones can
//	TD008  no     "no popular list for jsr": the check says so itself for this milestone
//	TD009  no     "no source for jsr": OSV has no JSR ecosystem and deps.dev no JSR system
//	TD010  no     "no source for jsr": same, OSV is the only source this check has
//	TD011  yes    yanked from meta.json, archived from the package record
//	TD012  yes    the downloads endpoint, summed over the last seven days
//	TD013  yes    reads the lockfile entry only; skipped for a ref named on the command line
//	TD014  yes    the same, lockfile only
//	TD015  yes    the version list with publish times, ordered as semantic versions
//
// The two facts behind the TD009 and TD010 rows, both verified 2026-09-09 against
// the live services rather than assumed:
//
//   - OSV has no JSR ecosystem and no Deno one. POST https://api.osv.dev/v1/query
//     with {"package":{"name":"@std/fs","ecosystem":"JSR"},"version":"1.0.24"} answers
//     HTTP 400 {"code":3,"message":"invalid ecosystem"}, and the same request with
//     "Deno" answers the same; the identical request with ecosystem "npm" for
//     event-stream 3.3.6 answers with advisories, so the request form is right and
//     the ecosystem is what OSV rejects.
//   - deps.dev has neither a jsr nor a deno system. GET
//     https://api.deps.dev/v3/systems/jsr/packages/%40std%2Ffs and the same URL with
//     deno both answer HTTP 404 "package not found", while
//     https://api.deps.dev/v3/systems/npm/packages/express answers with versions. The
//     npm compatibility name does not help either: @jsr/std__fs is served by
//     npm.jsr.io, not by registry.npmjs.org, and deps.dev answers 404 for it too.
package jsr
