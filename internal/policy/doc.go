// Package policy reads and applies the .trustdiff.yaml policy file: the cooldown and
// its exclusions, the level and options of every check, the reviewed exceptions with
// their expiry, what to do when a data source is unavailable, and per-ecosystem
// overrides. It owns the duration spellings the file accepts (12h, 3d, 1w, P3D), the
// package globs used by cooldown_exclude and allow, the commented default file that
// "policy init" writes, and the embedded copy of schema/policy.v1.json that
// "policy validate" checks against.
//
// Load and Parse return the file as written, after a strict decode (unknown keys are
// errors) and a schema check. Effective resolves the settings for one ecosystem by
// applying the precedence documented in internal/cli: the command line flag (applied
// by the caller), then the ecosystem override, then the policy value, then the
// built-in default.
package policy
