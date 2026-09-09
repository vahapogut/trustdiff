package model

import (
	"encoding/json"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		in      string
		want    Level
		wantErr bool
	}{
		{in: "off", want: LevelOff},
		{in: "info", want: LevelInfo},
		{in: "warn", want: LevelWarn},
		{in: "block", want: LevelBlock},
		{in: " Block ", want: LevelBlock},
		{in: "error", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseLevel(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseLevel(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseLevel(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestLevelOrderAndString(t *testing.T) {
	if LevelOff >= LevelInfo || LevelInfo >= LevelWarn || LevelWarn >= LevelBlock {
		t.Fatal("levels must be ordered off < info < warn < block")
	}
	if !LevelBlock.AtLeast(LevelWarn) || LevelWarn.AtLeast(LevelBlock) || !LevelWarn.AtLeast(LevelWarn) {
		t.Fatal("AtLeast is wrong")
	}
	for l, name := range map[Level]string{LevelOff: "off", LevelInfo: "info", LevelWarn: "warn", LevelBlock: "block"} {
		if l.String() != name {
			t.Errorf("%d.String() = %q, want %q", int(l), l.String(), name)
		}
	}
	if got := Level(42).String(); got != "level(42)" {
		t.Errorf("unknown level String() = %q", got)
	}
}

func TestLevelJSON(t *testing.T) {
	type doc struct {
		Level Level `json:"level"`
	}
	out, err := json.Marshal(doc{Level: LevelWarn})
	if err != nil || string(out) != `{"level":"warn"}` {
		t.Fatalf("Marshal = %s, %v", out, err)
	}
	var in doc
	if err := json.Unmarshal([]byte(`{"level":"block"}`), &in); err != nil || in.Level != LevelBlock {
		t.Fatalf("Unmarshal = %+v, %v", in, err)
	}
	if err := json.Unmarshal([]byte(`{"level":"loud"}`), &in); err == nil {
		t.Fatal("Unmarshal accepted an unknown level")
	}
	if _, err := json.Marshal(doc{Level: Level(9)}); err == nil {
		t.Fatal("Marshal accepted an unknown level")
	}
}

func TestProvenanceStrength(t *testing.T) {
	ordered := []Provenance{
		{Kind: ProvenanceNone},
		{Kind: ProvenanceSignature},
		{Kind: ProvenanceSignature, Verified: true},
		{Kind: ProvenanceAttestation},
		{Kind: ProvenanceAttestation, Verified: true},
		{Kind: ProvenanceTrustedPublisher},
		{Kind: ProvenanceTrustedPublisher, Verified: true},
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i].Strength() <= ordered[i-1].Strength() {
			t.Errorf("%+v (%d) should be stronger than %+v (%d)", ordered[i], ordered[i].Strength(), ordered[i-1], ordered[i-1].Strength())
		}
	}
	if (Provenance{}).Strength() != 0 || (Provenance{Kind: ProvenanceNone, Verified: true}).Strength() != 0 {
		t.Error("no provenance must have strength 0 whatever the verified flag says")
	}
}

func TestVersionInfoHasInstallScript(t *testing.T) {
	var empty VersionInfo
	if empty.HasInstallScript() {
		t.Fatal("empty scripts must not count as an install script")
	}
	v := &VersionInfo{Scripts: map[string]string{"postinstall": "node setup.js"}}
	if !v.HasInstallScript() {
		t.Fatal("postinstall must count as an install script")
	}
}
