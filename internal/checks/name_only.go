package checks

import (
	"context"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/report"
)

// EvaluateNames diagnoses supplied names locally, without claiming that they are
// installable registry packages. Only TD008 runs; every other applicable check
// explicitly skips. Policy levels, allows, expired allows, timeouts and canceled
// contexts use the same runner machinery as a normal evaluation. Loader is never
// consulted, including for the deps.dev cross-check or popularity demotion.
func (r *Runner) EvaluateNames(ctx context.Context, inputs []Input) []Outcome {
	local := *r
	local.Loader = NewLoader(nil, nil, nil, nil)
	rn := local.prepare()
	out := make([]Outcome, len(inputs))
	for i, in := range inputs {
		s := &Subject{Ref: in.Ref, Location: in.Location, Direct: in.Direct, Now: rn.now,
			Settings: rn.policy.Effective(in.Ref.Ecosystem), Downloads: -1}
		out[i].Subject = report.Subject{Ref: in.Ref, Location: in.Location, Direct: in.Direct}
		out[i].Subject.Findings = append(out[i].Subject.Findings, rn.expiredAllows(s)...)
		for _, c := range rn.applicable(s) {
			if c.ID() == "TD008" {
				rn.runOne(ctx, &out[i], s, c, nil)
				continue
			}
			out[i].Subject.Skipped = append(out[i].Subject.Skipped, model.Skipped{
				Check: c.ID(), Reason: "name-only diagnostic: npm does not accept this Unicode name; no registry or advisory requests were made",
			})
		}
		finish(&out[i].Subject)
	}
	return out
}
