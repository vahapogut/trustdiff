// Package attestation binds npm provenance to a package and invokes an explicitly
// selected local Sigstore verifier. Cryptographic verification stays in Cosign.
package attestation

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/vahapogut/trustdiff/internal/httpcache"
	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/registry/npm"
)

const maxBundleBytes = 2 << 20

// NPM wraps npm metadata while preserving its optional bulk-download method.
type NPM struct {
	*npm.Client
	HTTP     *httpcache.Client
	Verifier *Verifier
}

// VersionInfo verifies advertised build provenance locally. A failed verification
// makes that facet unavailable; callers must not use deps.dev to erase the gap.
func (n *NPM) VersionInfo(ctx context.Context, ref model.PackageRef) (*model.VersionInfo, error) {
	info, err := n.Client.VersionInfo(ctx, ref)
	if err != nil || info.Provenance.Kind != model.ProvenanceAttestation {
		return info, err
	}
	endpoint := npm.DefaultRegistryURL + "/-/npm/v1/attestations/" + url.PathEscape(info.Ref.Name+"@"+info.Ref.Version)
	resp, err := n.HTTP.Get(ctx, endpoint, httpcache.Request{Accept: "application/json"})
	if err == nil && resp.StatusCode != 200 {
		err = fmt.Errorf("attestation endpoint returned HTTP %d", resp.StatusCode)
	}
	if err == nil {
		var claim *Claim
		claim, err = Parse(resp.Body, info.Ref, info.Integrity)
		if err == nil {
			err = n.Verifier.Verify(ctx, claim)
		}
		if err == nil {
			info.Provenance.Verified = true
			info.Provenance.VerifiedBy = "cosign"
			info.Provenance.Identity = claim.Identity
		}
	}
	if err != nil {
		info.SetUnknown(model.FacetProvenance, "local Sigstore verification unavailable: "+err.Error())
	}
	return info, nil
}

// Claim is a validated binding passed unchanged to the cryptographic verifier.
type Claim struct {
	Bundle                              json.RawMessage
	Identity, Issuer, Predicate, Digest string
}

type bundle struct {
	MediaType string                                `json:"mediaType"`
	Envelope  struct{ Payload, PayloadType string } `json:"dsseEnvelope"`
	Material  struct {
		Certificate struct{ RawBytes string }                          `json:"certificate"`
		Chain       struct{ Certificates []struct{ RawBytes string } } `json:"x509CertificateChain"`
	} `json:"verificationMaterial"`
}

// Parse requires an exact npm PURL and SHA512 registry checksum in the signed
// subject. The certificate is parsed only to select an explicit identity/issuer;
// Cosign subsequently authenticates it, its signature and transparency evidence.
func Parse(data []byte, ref model.PackageRef, integrity string) (*Claim, error) {
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("attestation response exceeds 2 MiB")
	}
	if ref.Ecosystem != model.NPM || ref.Version == "" || model.NPMNameProblem(ref.Name) != "" {
		return nil, fmt.Errorf("exact npm reference required")
	}
	var digest string
	for _, part := range strings.Fields(integrity) {
		if !strings.HasPrefix(part, "sha512-") {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(part, "sha512-"))
		if err != nil || len(decoded) != 64 {
			return nil, fmt.Errorf("invalid SHA512 registry integrity")
		}
		candidate := hex.EncodeToString(decoded)
		if digest != "" && digest != candidate {
			return nil, fmt.Errorf("ambiguous SHA512 registry integrity")
		}
		digest = candidate
	}
	if digest == "" {
		return nil, fmt.Errorf("SHA512 registry integrity is required")
	}
	var response struct {
		Attestations []struct {
			PredicateType string
			Bundle        json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("attestation JSON: %w", err)
	}
	var selected json.RawMessage
	var predicate string
	for _, a := range response.Attestations {
		if a.PredicateType != "https://slsa.dev/provenance/v1" && a.PredicateType != "https://slsa.dev/provenance/v0.2" {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("multiple build provenance bundles are ambiguous")
		}
		selected, predicate = a.Bundle, a.PredicateType
	}
	if selected == nil {
		return nil, fmt.Errorf("no supported SLSA build provenance bundle")
	}
	var b bundle
	if err := json.Unmarshal(selected, &b); err != nil {
		return nil, err
	}
	switch b.MediaType {
	case "application/vnd.dev.sigstore.bundle+json;version=0.1", "application/vnd.dev.sigstore.bundle+json;version=0.2", "application/vnd.dev.sigstore.bundle.v0.3+json":
	default:
		return nil, fmt.Errorf("unsupported Sigstore bundle media type %q", b.MediaType)
	}
	if b.Envelope.PayloadType != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("unexpected DSSE payload type")
	}
	payload, err := base64.StdEncoding.DecodeString(b.Envelope.Payload)
	if err != nil {
		return nil, err
	}
	var statement struct {
		Type          string `json:"_type"`
		PredicateType string
		Subject       []struct {
			Name   string
			Digest map[string]string
		}
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, err
	}
	if statement.Type != "https://in-toto.io/Statement/v1" && statement.Type != "https://in-toto.io/Statement/v0.1" {
		return nil, fmt.Errorf("unsupported in-toto statement")
	}
	if statement.PredicateType != predicate || len(statement.Subject) != 1 {
		return nil, fmt.Errorf("provenance must describe exactly one matching subject")
	}
	name, err := url.PathUnescape(statement.Subject[0].Name)
	if err != nil || name != "pkg:npm/"+ref.Name+"@"+ref.Version || statement.Subject[0].Digest["sha512"] != digest {
		return nil, fmt.Errorf("signed subject does not match npm package, version and registry checksum")
	}
	raw := b.Material.Certificate.RawBytes
	if raw == "" && len(b.Material.Chain.Certificates) == 1 {
		raw = b.Material.Chain.Certificates[0].RawBytes
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("bundle certificate: %w", err)
	}
	if len(cert.URIs) != 1 {
		return nil, fmt.Errorf("certificate must name exactly one URI identity")
	}
	identity := cert.URIs[0].String()
	issuer, err := certificateIssuer(cert)
	if err != nil {
		return nil, err
	}
	if (issuer != "https://token.actions.githubusercontent.com" || !strings.HasPrefix(identity, "https://github.com/")) && (issuer != "https://gitlab.com" || !strings.HasPrefix(identity, "https://gitlab.com/")) {
		return nil, fmt.Errorf("unsupported CI certificate issuer or identity")
	}
	return &Claim{Bundle: selected, Identity: identity, Issuer: issuer, Predicate: predicate, Digest: digest}, nil
}

func certificateIssuer(cert *x509.Certificate) (string, error) {
	issuer := ""
	for _, ext := range cert.Extensions {
		candidate := ""
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}) {
			candidate = string(ext.Value)
		}
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}) {
			if rest, err := asn1.Unmarshal(ext.Value, &candidate); err != nil || len(rest) != 0 {
				return "", fmt.Errorf("invalid certificate issuer extension")
			}
		}
		if candidate == "" {
			continue
		}
		if issuer != "" && issuer != candidate {
			return "", fmt.Errorf("conflicting certificate issuers")
		}
		issuer = candidate
	}
	return issuer, nil
}
