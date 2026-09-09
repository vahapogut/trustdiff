package osv

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// CVSS v3 base score, computed in-house so that a record without a database
// label still gets a severity. The equations and constants below are section 7
// of the CVSS v3.1 specification, https://www.first.org/cvss/v3.1/specification-document,
// verified 2026-09-09:
//
//	ISS            = 1 - [(1 - C) x (1 - I) x (1 - A)]
//	Impact         = 6.42 x ISS                                    (Scope Unchanged)
//	               = 7.52 x (ISS - 0.029) - 3.25 x (ISS - 0.02)^15  (Scope Changed)
//	Exploitability = 8.22 x AV x AC x PR x UI
//	BaseScore      = 0 if Impact <= 0, else
//	                 Roundup(Minimum(Impact + Exploitability, 10))          (Unchanged)
//	                 Roundup(Minimum(1.08 x (Impact + Exploitability), 10))  (Changed)
//
// Roundup returns the smallest number, to one decimal place, that is equal to
// or higher than its input, implemented with the integer arithmetic of the
// specification's Appendix A. The base equations of v3.0 are the same (v3.1
// changed only the Roundup implementation advice and an environmental
// exponent), so a CVSS:3.0 vector is scored with the same code. The metric
// weights are Table 16 of the specification.

var (
	errCVSSVersion = errors.New("not a CVSS v3.0 or v3.1 vector")
	errCVSSSyntax  = errors.New("malformed CVSS vector")
)

// cvssMetricWeights maps every base metric to the weight of each of its values
// (Table 16). PR weights depend on Scope and are handled in cvss3BaseScore.
var cvssMetricWeights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"PR": {"N": 0.85, "L": 0.62, "H": 0.27},
	"UI": {"N": 0.85, "R": 0.62},
	"S":  {"U": 0, "C": 1},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// cvssPRChangedWeights are the PR weights when Scope is Changed.
var cvssPRChangedWeights = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}

// cvssOptionalMetrics are the temporal and environmental metrics a vector may
// carry after the base ones. They do not enter the base score and are only
// checked for being known, so a typo in a base metric name is still an error.
var cvssOptionalMetrics = map[string]struct{}{
	"E": {}, "RL": {}, "RC": {},
	"CR": {}, "IR": {}, "AR": {},
	"MAV": {}, "MAC": {}, "MPR": {}, "MUI": {}, "MS": {}, "MC": {}, "MI": {}, "MA": {},
}

// cvss3BaseScore computes the base score of a CVSS v3.0 or v3.1 vector string
// such as CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. The eight base metrics
// may appear in any order and must each appear once; temporal and environmental
// metrics are accepted and ignored.
func cvss3BaseScore(vector string) (float64, error) {
	rest, ok := strings.CutPrefix(vector, "CVSS:3.1/")
	if !ok {
		if rest, ok = strings.CutPrefix(vector, "CVSS:3.0/"); !ok {
			return 0, fmt.Errorf("%w: %q", errCVSSVersion, vector)
		}
	}
	metrics := make(map[string]string, len(cvssMetricWeights))
	for part := range strings.SplitSeq(rest, "/") {
		name, value, ok := strings.Cut(part, ":")
		if !ok || name == "" || value == "" {
			return 0, fmt.Errorf("%w: bad metric %q", errCVSSSyntax, part)
		}
		if _, dup := metrics[name]; dup {
			return 0, fmt.Errorf("%w: metric %s given twice", errCVSSSyntax, name)
		}
		if _, optional := cvssOptionalMetrics[name]; optional {
			metrics[name] = value
			continue
		}
		values, known := cvssMetricWeights[name]
		if !known {
			return 0, fmt.Errorf("%w: unknown metric %s", errCVSSSyntax, name)
		}
		if _, valid := values[value]; !valid {
			return 0, fmt.Errorf("%w: metric %s has no value %q", errCVSSSyntax, name, value)
		}
		metrics[name] = value
	}
	for name := range cvssMetricWeights {
		if _, present := metrics[name]; !present {
			return 0, fmt.Errorf("%w: metric %s missing", errCVSSSyntax, name)
		}
	}

	changed := metrics["S"] == "C"
	weight := func(name string) float64 { return cvssMetricWeights[name][metrics[name]] }
	pr := weight("PR")
	if changed {
		pr = cvssPRChangedWeights[metrics["PR"]]
	}

	iss := 1 - (1-weight("C"))*(1-weight("I"))*(1-weight("A"))
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * weight("AV") * weight("AC") * pr * weight("UI")
	if impact <= 0 {
		return 0, nil
	}
	if changed {
		return cvssRoundup(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return cvssRoundup(math.Min(impact+exploitability, 10)), nil
}

// cvssRoundup is the specification's Roundup with the integer arithmetic of
// Appendix A, so that inputs such as 4.02 and 4.00 round to 4.1 and 4.0
// whatever the floating point noise of the preceding multiplications.
func cvssRoundup(x float64) float64 {
	n := math.Round(x * 100000)
	if math.Mod(n, 10000) == 0 {
		return n / 100000
	}
	return (math.Floor(n/10000) + 1) / 10
}
