package attestation

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vahapogut/trustdiff/internal/model"
)

const fixtureDigest = "c1e7e3ca0b9d10d6f36d0324b35b79bb7e043f47c5a03d17bda10fec33943ffb172afa20cc4258170e44ea97a01b2a77a27196cd51182956b76cd656c93617f8"

func fixture(t *testing.T) ([]byte, model.PackageRef, string) {
	t.Helper()
	b, err := os.ReadFile("testdata/sigstore-bundle-5.0.0.json")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hex.DecodeString(fixtureDigest)
	if err != nil {
		t.Fatal(err)
	}
	return b, model.PackageRef{Ecosystem: model.NPM, Name: "@sigstore/bundle", Version: "5.0.0"}, "sha512-" + base64.StdEncoding.EncodeToString(hash)
}

func TestParseExactProvenanceBinding(t *testing.T) {
	b, ref, integrity := fixture(t)
	c, err := Parse(b, ref, integrity)
	if err != nil {
		t.Fatal(err)
	}
	if c.Digest != fixtureDigest || c.Issuer != "https://token.actions.githubusercontent.com" || !strings.Contains(c.Identity, "/sigstore/sigstore-js/") {
		t.Fatalf("wrong claim: %+v", c)
	}
	ref.Version = "4.0.0"
	if _, err := Parse(b, ref, integrity); err == nil {
		t.Fatal("cross-version replay accepted")
	}
	ref.Version = "5.0.0"
	ref.Name = "other"
	if _, err := Parse(b, ref, integrity); err == nil {
		t.Fatal("cross-package replay accepted")
	}
	_, ref, _ = fixture(t)
	if _, err := Parse(b, ref, "sha512-"+base64.StdEncoding.EncodeToString(make([]byte, 64))); err == nil {
		t.Fatal("wrong checksum accepted")
	}
	if _, err := Parse(b, ref, "sha1-aaaa"); err == nil {
		t.Fatal("weak checksum accepted")
	}
}

func TestParseRejectsAmbiguousAndWrongStatements(t *testing.T) {
	b, ref, integrity := fixture(t)
	var response map[string]any
	if err := json.Unmarshal(b, &response); err != nil {
		t.Fatal(err)
	}
	items := response["attestations"].([]any)
	response["attestations"] = append(items, items[1])
	duplicate, _ := json.Marshal(response)
	if _, err := Parse(duplicate, ref, integrity); err == nil {
		t.Fatal("ambiguous bundles accepted")
	}
	response["attestations"] = items
	bundle := items[1].(map[string]any)["bundle"].(map[string]any)
	bundle["dsseEnvelope"].(map[string]any)["payloadType"] = "text/plain"
	wrong, _ := json.Marshal(response)
	if _, err := Parse(wrong, ref, integrity); err == nil {
		t.Fatal("wrong payload type accepted")
	}
}

func TestConflictingIssuerExtensionsRejectedInEitherOrder(t *testing.T) {
	modern, err := asn1.Marshal("https://gitlab.com")
	if err != nil {
		t.Fatal(err)
	}
	a := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte("https://token.actions.githubusercontent.com")}
	b := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: modern}
	for _, extensions := range [][]pkix.Extension{{a, b}, {b, a}} {
		if _, err := certificateIssuer(&x509.Certificate{Extensions: extensions}); err == nil {
			t.Fatal("conflicting issuers accepted")
		}
	}
}

// The test executable acts as a verifier without a shell or a platform script.
func TestMain(m *testing.M) {
	if os.Getenv("TRUSTDIFF_FAKE_COSIGN") == "1" && len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "verify-blob-attestation") {
		if os.Args[1] == "version" {
			fmt.Println(`{"gitVersion":"v3.1.3"}`)
			os.Exit(0)
		}
		if os.Getenv("TRUSTDIFF_FAKE_COSIGN_WAIT") == "1" {
			time.Sleep(time.Minute)
		}
		joined := strings.Join(os.Args, " ")
		if !strings.Contains(joined, "--digestAlg sha512") || strings.Contains(joined, "insecure") || !strings.Contains(joined, "--digest "+fixtureDigest) {
			os.Exit(7)
		}
		fmt.Println("Verified OK")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestCosignFixedArgumentsAndCancellation(t *testing.T) {
	t.Setenv("TRUSTDIFF_FAKE_COSIGN", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(context.Background(), Options{Binary: exe})
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
	t.Setenv("TRUSTDIFF_FAKE_COSIGN_WAIT", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := v.Verify(ctx, c); err == nil {
		t.Fatal("cancellation ignored")
	}
	if _, err := New(context.Background(), Options{Binary: exe, Offline: true}); err == nil {
		t.Fatal("offline verification without local root accepted")
	}
}
