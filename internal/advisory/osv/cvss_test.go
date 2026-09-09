package osv

import (
	"errors"
	"testing"
)

// TestCVSS3BaseScoreSpecificationExamples checks the calculator against every
// v3.1 example of https://www.first.org/cvss/v3.1/examples (read 2026-09-09),
// which cover both scopes, every attack vector and the Roundup edge cases.
func TestCVSS3BaseScoreSpecificationExamples(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{"CVE-2013-0375 MySQL stored SQL injection", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4},
		{"CVE-2014-3566 SSLv3 POODLE", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1},
		{"CVE-2012-1516 VMware guest to host escape", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9},
		{"CVE-2009-0783 Apache Tomcat XML parser", "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L", 4.2},
		{"CVE-2012-0384 Cisco IOS command execution", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2},
		{"CVE-2015-1098 Apple iWork denial of service", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8},
		{"CVE-2014-0160 OpenSSL Heartbleed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVE-2014-6271 Bash Shellshock", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVE-2008-1447 DNS Kaminsky bug", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N", 6.8},
		{"CVE-2014-2005 Sophos login screen bypass", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 6.8},
		{"CVE-2010-0467 Joomla directory traversal", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", 5.8},
		{"CVE-2012-1342 Cisco access control bypass", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N", 5.8},
		{"CVE-2013-6014 Juniper proxy ARP denial of service", "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H", 9.3},
		{"CVE-2019-7551 Cantemo Portal stored XSS", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0},
		{"CVE-2009-0658 Adobe Acrobat buffer overflow", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8},
		{"CVE-2011-1265 Windows Bluetooth remote code execution", "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8},
		{"CVE-2014-2019 Apple iOS security control bypass", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 4.6},
		{"CVE-2015-0970 SearchBlox CSRF", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8},
		{"CVE-2014-0224 SSL/TLS MITM", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4},
		{"CVE-2012-5376 Chrome sandbox bypass", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6},
		{"CVE-2016-1645 Chrome PDFium remote code execution", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8},
		{"CVE-2016-0128 Badlock", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8},
		{"CVE-2017-5942 WordPress mail plugin reflected XSS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVE-2018-18913 Opera DLL search order hijacking", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8},
		{"CVE-2016-5558 Oracle Outside In remote code execution", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", 8.6},
		{"CVE-2016-5729 Lenovo ThinkPwn", "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 8.2},
		{"CVE-2015-2890 failure to lock flash on resume", "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", 6.0},
		{"CVE-2018-3652 Intel DCI", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 7.6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := cvss3BaseScore(tt.vector)
			if err != nil {
				t.Fatalf("cvss3BaseScore(%q): %v", tt.vector, err)
			}
			if got != tt.want {
				t.Errorf("cvss3BaseScore(%q) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}

// TestCVSS3BaseScoreRules covers the rules around the examples: the zero-impact
// short cut, the v3.0 prefix, metric order and ignored optional metrics.
func TestCVSS3BaseScoreRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{"no impact scores zero whatever the exploitability", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
		{"no impact with changed scope", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N", 0},
		{"v3.0 prefix uses the same equations", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"metrics in another order (the specification's own example)", "CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N", 3.8},
		{"temporal metrics are ignored", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:F/RL:X/RC:C", 7.5},
		{"environmental metrics are ignored", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/CR:H/MAV:L", 7.5},
		{"changed scope uses the higher PR weights", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1},
		{"the score is capped at 10", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10},
		{"the express open redirect (GHSA-rv95-896h-c2vc)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"requests temp file reuse (PYSEC-2026-2275)", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", 5.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := cvss3BaseScore(tt.vector)
			if err != nil {
				t.Fatalf("cvss3BaseScore(%q): %v", tt.vector, err)
			}
			if got != tt.want {
				t.Errorf("cvss3BaseScore(%q) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}

func TestCVSS3BaseScoreInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		vector string
		want   error
	}{
		{"empty", "", errCVSSVersion},
		{"v2 vector", "AV:N/AC:L/Au:N/C:P/I:P/A:P", errCVSSVersion},
		{"v4 vector", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", errCVSSVersion},
		{"prefix only", "CVSS:3.1/", errCVSSSyntax},
		{"missing metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", errCVSSSyntax},
		{"duplicate metric", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", errCVSSSyntax},
		{"unknown metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/XX:Y", errCVSSSyntax},
		{"unknown value", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", errCVSSSyntax},
		{"missing colon", "CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", errCVSSSyntax},
		{"empty value", "CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", errCVSSSyntax},
		{"lowercase metric", "CVSS:3.1/av:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", errCVSSSyntax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := cvss3BaseScore(tt.vector)
			if !errors.Is(err, tt.want) {
				t.Fatalf("cvss3BaseScore(%q) error = %v, want %v", tt.vector, err, tt.want)
			}
			if got != 0 {
				t.Errorf("cvss3BaseScore(%q) = %v with an error, want 0", tt.vector, got)
			}
		})
	}
}

// TestCVSSRoundup checks the examples the specification gives for Roundup and
// the floating point cases Appendix A exists for.
func TestCVSSRoundup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   float64
		want float64
	}{
		{4.02, 4.1},
		{4.00, 4.0},
		{4.00001, 4.1},
		{4.000001, 4.0}, // below the 1e-5 resolution of Appendix A, so still 4.0
		{0, 0},
		{10, 10},
		{9.95, 10},
		{0.1 + 0.2, 0.3}, // 0.30000000000000004 in binary floating point
		{5.699999999999999, 5.7},
	}
	for _, tt := range tests {
		if got := cvssRoundup(tt.in); got != tt.want {
			t.Errorf("cvssRoundup(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
