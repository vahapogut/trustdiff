package policy

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestAddAllowPreservesPolicyAndRestrictsException(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for _, source := range []string{
		"# keep\nversion: 1\nchecks:\n  low-usage: off # retain\n",
		"version: 1\nallow: [] # retain\nchecks:\n  low-usage: off\n",
		"version: 1\nallow:\n  - check: low-usage\n    package: npm:first\n    reason: reviewed\nchecks:\n  low-usage: off # retain\n",
		"version: 1\nallow:\n- check: low-usage\n  package: npm:first\n  reason: reviewed\n...\n",
	} {
		for _, nl := range []string{"\n", "\r\n"} {
			src := []byte(strings.ReplaceAll(source, "\n", nl))
			out, err := AddAllow(src, "exotic-source", "npm:vendored@1.2.3", "reviewed # repo: abc", "2026-10-10", now)
			if err != nil {
				t.Fatal(err)
			}
			p, err := Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			entry := p.Allow[len(p.Allow)-1]
			if entry.Reason != "reviewed # repo: abc" || entry.Package.String() != "npm:vendored@1.2.3" {
				t.Fatalf("bad entry: %+v", entry)
			}
			if strings.Contains(source, "# retain") && !bytes.Contains(out, []byte("# retain")) {
				t.Fatal("comment lost")
			}
			again, err := AddAllow(out, "exotic-source", "npm:vendored@1.2.3", "reviewed # repo: abc", "2026-10-10", now)
			if err != nil || !bytes.Equal(out, again) {
				t.Fatalf("non-idempotent: %v", err)
			}
		}
	}
}

func TestAddAllowRefusesBroadOrExpiredReview(t *testing.T) {
	for _, tc := range []struct{ ref, reason, expiry string }{
		{"npm:*", "reviewed", "2030-01-01"}, {"npm:foo", "", "2030-01-01"},
		{"npm:foo", "reviewed", "2020-01-01"}, {"foo", "reviewed", "2030-01-01"},
		{"npm:foo", "reviewed", ""},
	} {
		if _, err := AddAllow([]byte("version: 1\n"), "exotic-source", tc.ref, tc.reason, tc.expiry, time.Now()); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
