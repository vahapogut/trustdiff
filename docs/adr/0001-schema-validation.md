# ADR 0001: JSON Schema validation without a validator module

Date: 2026-09-09
Status: accepted

## Context

Three places in trustdiff validate a JSON document against a JSON Schema:

- `policy validate` (brief section 5) checks `.trustdiff.yaml` against the embedded
  `schema/policy.v1.json`, which is also published for editor autocompletion. The
  `checks` map has values that are either a level string (`warn`) or an object
  (`{ level: block, min_severity: high }`), so the schema needs `oneOf`.
- The report golden tests (brief section 10) validate `--format json` output against
  `schema/report.v1.json`, so the published schema cannot drift from what the binary
  writes.
- The SARIF golden tests (brief section 10, task 2.9) validate `--format sarif` output
  against the SARIF 2.1.0 schema vendored under `internal/report/testdata/`. That
  schema is draft-04, 110 KB, uses 233 local `$ref` edges, `type` arrays with `null`,
  `additionalProperties` in both the boolean and the schema form, `anyOf` and `oneOf`
  over `required` lists, `pattern`, `format`, `uniqueItems`, `minItems`, `minimum` and
  `maximum`, and recursive definitions (a `node` whose children are nodes).

The dependency policy (brief section 0.4 and section 15, plan section 1) allows six
direct modules, all already allocated, and admits nothing else without a written
justification. A JSON Schema validator module would be a seventh direct dependency
with its own transitive tree, for a tool whose reason to exist is that dependencies
are dangerous. Tests must also stay hermetic, so validation cannot be delegated to an
external process either.

## Decision

Write the validator in-house as `internal/jsonschema`, covering exactly the keyword
subset that the three schemas above use, and no more:

`$schema`, `$id` and `id` (accepted and ignored), `type` (string or array, including
`integer` and `null`), `enum`, `const`, `required`, `properties`,
`additionalProperties` (boolean or schema), `patternProperties`, `items` (single
schema), `minItems`, `maxItems`, `uniqueItems`, `minimum`, `maximum`,
`exclusiveMinimum` and `exclusiveMaximum` (both the draft-04 boolean form and the
draft-06 numeric form), `minLength`, `maxLength`, `pattern` (Go `regexp`, so RE2),
`format` (lenient: `date`, `date-time`, `uri` and `uri-reference` are checked loosely,
every other format is accepted), `oneOf`, `anyOf`, `allOf`, `not`, and `$ref` limited
to references inside the same document (`#`, `#/definitions/<name>`,
`#/$defs/<name>`). `title`, `description`, `default` and `examples` are annotations
and are ignored. Every other keyword is ignored as well, which is what the JSON Schema
specifications prescribe for unknown keywords.

Instances are decoded with `encoding/json` into `any`, so numbers are `float64` and
`integer` means "a number with no fractional part": `3.0` is an integer, `3.5` is not.
Validation reports every failure at once, each carrying the JSON pointer of the
failing instance location and the keyword that failed, joined with `errors.Join`.
`Compile` rejects a remote `$ref` and a `$ref` cycle that would recurse without
consuming input; a definition that references itself through `properties` or `items`
is ordinary recursion and works, because SARIF relies on it.

Alternatives considered:

- A third-party validator module. Complete and well tested, but it costs a direct
  dependency slot the project does not have, brings a transitive tree the security
  posture argues against, and implements far more than these three schemas need.
- Typed decoders only, with no schema validation. The typed policy decoder already
  rejects unknown keys and bad enums, but the published schemas would then be
  documentation that nothing checks, and `policy validate` promises a schema check.
- Validation by an external tool in CI only. Tests would no longer be hermetic, the
  check would not exist at runtime for `policy validate`, and contributors without
  that tool could not run the test suite.

## Consequences

- Schemas written for this project (`schema/policy.v1.json`, `schema/report.v1.json`,
  later `schema/doctor.v1.json` if ADR 0003 introduces it) must stay inside the
  subset above. The subset is listed in the package documentation of
  `internal/jsonschema`, which is the reference when a schema is written or extended.
- Unknown keywords are ignored as annotations. A schema that uses an unsupported
  validation keyword (`multipleOf`, `contains`, `propertyNames`, `dependencies`,
  `if`/`then`/`else`, `additionalItems`, `minProperties`, `maxProperties`) validates
  less strictly than a full validator would, silently. `(*Schema).UnsupportedKeywords`
  reports what a schema uses outside the subset, so a test can assert that the
  project schemas use nothing the validator does not enforce.
- A vendored third-party schema (SARIF today) is checked once, when it is vendored,
  against the subset. The SARIF 2.1.0 keyword usage was enumerated on 2026-09-09 and
  is fully covered. Vendoring a new schema means repeating that enumeration and
  extending the validator if needed.
- `pattern` values are compiled by Go's `regexp`, so ECMA 262 constructs that RE2 lacks
  (lookahead, backreferences) are compile errors. The four patterns in the SARIF
  schema are RE2-compatible; project schemas must keep to RE2 as plan section 1
  already requires.
- If the project ever needs a keyword outside the subset, the choice is to extend the
  validator or to revisit this ADR, in that order.
