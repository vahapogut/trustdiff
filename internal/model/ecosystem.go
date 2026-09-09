// Package model holds the types shared by every other package: package references,
// version metadata as returned by registries, check levels and findings. It has no
// dependencies beyond the standard library so that checks, registry clients and
// report writers can all import it without importing each other.
package model

import (
	"fmt"
	"strings"
)

// Ecosystem identifies a package registry.
type Ecosystem string

// Supported ecosystems. Deno and JSR arrive in milestone M4.
const (
	NPM   Ecosystem = "npm"
	PyPI  Ecosystem = "pypi"
	Cargo Ecosystem = "cargo"
	Deno  Ecosystem = "deno"
	JSR   Ecosystem = "jsr"
)

var ecosystems = []Ecosystem{NPM, PyPI, Cargo, Deno, JSR}

// Ecosystems lists every ecosystem in a stable order.
func Ecosystems() []Ecosystem {
	out := make([]Ecosystem, len(ecosystems))
	copy(out, ecosystems)
	return out
}

// ParseEcosystem accepts the prefix used in refs and policy files, case-insensitively.
func ParseEcosystem(s string) (Ecosystem, error) {
	e := Ecosystem(strings.ToLower(strings.TrimSpace(s)))
	for _, known := range ecosystems {
		if e == known {
			return known, nil
		}
	}
	return "", fmt.Errorf("unknown ecosystem %q (want one of %s)", s, joinEcosystems())
}

func (e Ecosystem) String() string { return string(e) }

func joinEcosystems() string {
	names := make([]string, len(ecosystems))
	for i, e := range ecosystems {
		names[i] = string(e)
	}
	return strings.Join(names, ", ")
}
