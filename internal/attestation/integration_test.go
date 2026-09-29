//go:build integration

package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// This test uses a real installed Cosign and its TUF trust roots. No package code
// is downloaded or executed. Set TRUSTDIFF_COSIGN_BIN for a non-PATH executable.
func TestIntegrationRealCosignAndTamperedSignature(t *testing.T) {
	if os.Getenv("TRUSTDIFF_INTEGRATION_OFFLINE") != "" {
		t.Skip("live integration disabled")
	}
	v, err := New(context.Background(), Options{Binary: os.Getenv("TRUSTDIFF_COSIGN_BIN"), TrustedRoot: os.Getenv("TRUSTDIFF_SIGSTORE_ROOT")})
	if err != nil {
		t.Fatal(err)
	}
	b, ref, integrity := fixture(t)
	c, err := Parse(b, ref, integrity)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(c.Bundle, &raw); err != nil {
		t.Fatal(err)
	}
	envelope := raw["dsseEnvelope"].(map[string]any)
	sig := envelope["signatures"].([]any)[0].(map[string]any)
	decoded, err := base64.StdEncoding.DecodeString(sig["sig"].(string))
	if err != nil {
		t.Fatal(err)
	}
	decoded[len(decoded)-1] ^= 1
	sig["sig"] = base64.StdEncoding.EncodeToString(decoded)
	c.Bundle, err = json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), c); err == nil {
		t.Fatal("Cosign accepted a tampered DSSE signature")
	}
}
