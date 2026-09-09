// Package osv queries OSV.dev for vulnerability and malicious-package advisories.
//
// Endpoints, verified 2026-09-09 against https://google.github.io/osv.dev/api/:
//
//	POST https://api.osv.dev/v1/querybatch  (up to 1000 queries; returns ids and modified)
//	GET  https://api.osv.dev/v1/vulns/<id>  (severity, affected ranges, references)
//
// Ecosystem names on the wire are npm, PyPI and crates.io. Advisory ids that start
// with MAL- come from ossf/malicious-packages and mark a malicious version.
package osv

import (
	"context"
	"errors"

	"github.com/vahapogut/trustdiff/internal/advisory"
	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
)

// Client is the OSV.dev client. All requests go through internal/httpcache.
type Client struct {
	http *httpcache.Client
	base string
}

// New returns a client using the shared HTTP cache.
func New(h *httpcache.Client) *Client {
	return &Client{http: h, base: "https://api.osv.dev/v1"}
}

// Advisories implements advisory.Source: one querybatch for all refs, then one
// details request per distinct advisory id.
func (c *Client) Advisories(_ context.Context, _ []model.PackageRef) (map[model.PackageRef][]advisory.Advisory, error) {
	return nil, errors.New("osv: Advisories not implemented yet (task 1.6)")
}

// Ecosystem maps an ecosystem to the OSV ecosystem name, or "" when OSV has none.
func Ecosystem(eco model.Ecosystem) string {
	switch eco {
	case model.NPM:
		return "npm"
	case model.PyPI:
		return "PyPI"
	case model.Cargo:
		return "crates.io"
	default:
		return ""
	}
}

var _ advisory.Source = (*Client)(nil)
