package npm

import (
	"context"
	"errors"
	"testing"

	"github.com/vahapogut/trustdiff/internal/registry"
)

// A name npm's own grammar refuses cannot be on the registry, so the client
// answers not found for it and sends nothing. It used to put the name into the
// download counts URL unescaped: "foo?a=b" chose the query, "foo#frag" was
// answered as foo, and ".." was resolved away before the request arrived.
// Finding F25 of docs/review-2026-09-10.md.
func TestCanonicalNameRefusesWhatNpmCouldNeverHold(t *testing.T) {
	for _, name := range []string{"foo?a=b", "foo#frag", "..", ".hidden", "_leading", "node_modules", "a,b", "@scope/..", "%2e%2e"} {
		if _, err := canonicalName(name); !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("canonicalName(%q) error = %v, want registry.ErrNotFound", name, err)
		}
	}
	for _, name := range []string{"-", "JSONStream", "@types/node", "@Types/Node", "with~tilde!(star)*'"} {
		if got, err := canonicalName(name); err != nil || got != name {
			t.Errorf("canonicalName(%q) = %q, %v, want it kept as given", name, got, err)
		}
	}
}

func TestNoRequestCarriesANameNpmCouldNeverHold(t *testing.T) {
	fs := newFixtureServer(t)
	c := newClient(t, fs, t.TempDir(), false)
	ctx := context.Background()
	before := len(fs.seen())
	for _, name := range []string{"foo?a=b", "foo#frag", "..", "@scope/.."} {
		if _, err := c.Downloads(ctx, name); !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("Downloads(%q) error = %v, want registry.ErrNotFound", name, err)
		}
		if _, err := c.Versions(ctx, name); !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("Versions(%q) error = %v, want registry.ErrNotFound", name, err)
		}
	}
	if after := fs.seen(); len(after) != before {
		t.Errorf("the client requested %v for names that cannot exist", after[before:])
	}
}
