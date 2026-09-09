package report

import (
	"runtime"
	"slices"
	"testing"

	"github.com/vahapogut/trustdiff/internal/model"
	"github.com/vahapogut/trustdiff/internal/version"
)

var testRef = model.MustParseRef("npm:example-lib@4.19.3")

func testFinding(id string, level model.Level) model.Finding {
	return model.Finding{
		ID:          id,
		Name:        "check-" + id,
		Level:       level,
		Ref:         testRef,
		Title:       id + " title",
		Explanation: id + " explanation",
	}
}

func testTool() Tool {
	return Tool{Name: "trustdiff", Version: "v0.0.1", Commit: "abc1234", Date: "2026-09-09T00:00:00Z", GoVersion: "go1.26.8"}
}

func testPolicy() Policy {
	return Policy{Path: ".trustdiff.yaml", Cooldown: "3d", FailOn: "block"}
}

func TestBuildVerdict(t *testing.T) {
	tests := []struct {
		name    string
		subject Subject
		want    string
	}{
		{
			name: "block wins over warn and info",
			subject: Subject{
				Evaluated: []string{"TD001", "TD002", "TD012"},
				Findings:  []model.Finding{testFinding("TD012", model.LevelInfo), testFinding("TD001", model.LevelWarn), testFinding("TD002", model.LevelBlock)},
			},
			want: VerdictBlock,
		},
		{
			name: "warn wins over info",
			subject: Subject{
				Evaluated: []string{"TD001", "TD012"},
				Findings:  []model.Finding{testFinding("TD012", model.LevelInfo), testFinding("TD001", model.LevelWarn)},
			},
			want: VerdictWarn,
		},
		{
			name: "info only",
			subject: Subject{
				Evaluated: []string{"TD012"},
				Findings:  []model.Finding{testFinding("TD012", model.LevelInfo)},
			},
			want: VerdictInfo,
		},
		{
			name:    "clean",
			subject: Subject{Evaluated: []string{"TD001", "TD002"}},
			want:    VerdictOK,
		},
		{
			name:    "clean with one skipped check",
			subject: Subject{Evaluated: []string{"TD001"}, Skipped: []model.Skipped{{Check: "TD012", Reason: "offline"}}},
			want:    VerdictOK,
		},
		{
			name:    "nothing evaluated",
			subject: Subject{Skipped: []model.Skipped{{Check: "TD001", Reason: "offline"}}},
			want:    VerdictSkipped,
		},
		{
			name:    "nothing ran at all",
			subject: Subject{},
			want:    VerdictSkipped,
		},
		{
			name:    "findings without an evaluated list still decide the verdict",
			subject: Subject{Findings: []model.Finding{testFinding("TD001", model.LevelWarn)}},
			want:    VerdictWarn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Build([]Subject{tt.subject}, testTool(), testPolicy(), model.LevelBlock)
			if got := r.Subjects[0].Verdict; got != tt.want {
				t.Fatalf("verdict = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildOrdersFindingsSkippedAndEvaluated(t *testing.T) {
	in := Subject{
		Evaluated: []string{"TD012", "TD001", "TD009", "TD002", "TD010"},
		Skipped:   []model.Skipped{{Check: "TD006", Reason: "b"}, {Check: "TD003", Reason: "a"}},
		Findings: []model.Finding{
			testFinding("TD012", model.LevelInfo),
			testFinding("TD009", model.LevelBlock),
			testFinding("TD001", model.LevelWarn),
			{ID: "TD010", Name: "vulnerability", Level: model.LevelBlock, Ref: testRef, Title: "first"},
			testFinding("TD002", model.LevelBlock),
			{ID: "TD010", Name: "vulnerability", Level: model.LevelBlock, Ref: testRef, Title: "second"},
		},
	}
	r := Build([]Subject{in}, testTool(), testPolicy(), model.LevelBlock)
	got := r.Subjects[0]

	wantOrder := []string{"TD002", "TD009", "TD010", "TD010", "TD001", "TD012"}
	ids := make([]string, len(got.Findings))
	for i, f := range got.Findings {
		ids[i] = f.ID
	}
	if !slices.Equal(ids, wantOrder) {
		t.Errorf("finding order = %v, want %v", ids, wantOrder)
	}
	if got.Findings[2].Title != "first" || got.Findings[3].Title != "second" {
		t.Errorf("sort is not stable for equal level and id: %q, %q", got.Findings[2].Title, got.Findings[3].Title)
	}
	if want := []string{"TD001", "TD002", "TD009", "TD010", "TD012"}; !slices.Equal(got.Evaluated, want) {
		t.Errorf("evaluated = %v, want %v", got.Evaluated, want)
	}
	if got.Skipped[0].Check != "TD003" || got.Skipped[1].Check != "TD006" {
		t.Errorf("skipped order = %v, want TD003 then TD006", got.Skipped)
	}
}

func TestBuildDoesNotMutateInput(t *testing.T) {
	findings := []model.Finding{testFinding("TD012", model.LevelInfo), testFinding("TD002", model.LevelBlock)}
	evaluated := []string{"TD012", "TD002"}
	in := []Subject{{Evaluated: evaluated, Findings: findings}}

	Build(in, testTool(), testPolicy(), model.LevelBlock)

	if findings[0].ID != "TD012" || evaluated[0] != "TD012" {
		t.Fatalf("Build reordered the caller's slices: %v %v", findings, evaluated)
	}
	if in[0].Verdict != "" {
		t.Fatalf("Build wrote the verdict into the caller's subject: %q", in[0].Verdict)
	}
}

func TestBuildExitCode(t *testing.T) {
	tests := []struct {
		name   string
		levels []model.Level
		failOn model.Level
		want   int
	}{
		{name: "block fails on block", levels: []model.Level{model.LevelBlock, model.LevelWarn, model.LevelInfo}, failOn: model.LevelBlock, want: 1},
		{name: "warn does not fail on block", levels: []model.Level{model.LevelWarn, model.LevelInfo}, failOn: model.LevelBlock, want: 0},
		{name: "warn fails on warn", levels: []model.Level{model.LevelWarn, model.LevelInfo}, failOn: model.LevelWarn, want: 1},
		{name: "block fails on warn", levels: []model.Level{model.LevelBlock}, failOn: model.LevelWarn, want: 1},
		{name: "info does not fail on warn", levels: []model.Level{model.LevelInfo}, failOn: model.LevelWarn, want: 0},
		{name: "info fails on info", levels: []model.Level{model.LevelInfo}, failOn: model.LevelInfo, want: 1},
		{name: "never fails even on block", levels: []model.Level{model.LevelBlock}, failOn: model.LevelOff, want: 0},
		{name: "no findings", levels: nil, failOn: model.LevelInfo, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var findings []model.Finding
			for i, l := range tt.levels {
				findings = append(findings, testFinding("TD00"+string(rune('1'+i)), l))
			}
			// Spread the findings over two subjects so the exit code is proven to be global.
			subjects := []Subject{{Evaluated: []string{"TD001"}}, {Evaluated: []string{"TD001"}, Findings: findings}}
			r := Build(subjects, testTool(), testPolicy(), tt.failOn)
			if r.Summary.ExitCode != tt.want {
				t.Fatalf("exit code = %d, want %d", r.Summary.ExitCode, tt.want)
			}
			if r.Summary.ExitMeaning != ExitMeaning(tt.want) {
				t.Fatalf("exit meaning = %q, want %q", r.Summary.ExitMeaning, ExitMeaning(tt.want))
			}
		})
	}
}

func TestBuildEmpty(t *testing.T) {
	r := Build(nil, testTool(), testPolicy(), model.LevelBlock)
	if SchemaID != "trustdiff.report/1" {
		t.Errorf("SchemaID = %q, want trustdiff.report/1", SchemaID)
	}
	if r.Schema != SchemaID {
		t.Errorf("schema = %q, want %q", r.Schema, SchemaID)
	}
	if r.Subjects == nil || len(r.Subjects) != 0 {
		t.Errorf("subjects = %#v, want an empty non-nil slice", r.Subjects)
	}
	if r.Tool != testTool() || r.Policy != testPolicy() {
		t.Errorf("tool or policy not carried over: %+v %+v", r.Tool, r.Policy)
	}
	want := Summary{Subjects: 0, Findings: map[string]int{"block": 0, "warn": 0, "info": 0}, Skipped: 0, ExitCode: 0, ExitMeaning: "no blocking findings"}
	if r.Summary.Subjects != want.Subjects || r.Summary.Skipped != want.Skipped || r.Summary.ExitCode != want.ExitCode || r.Summary.ExitMeaning != want.ExitMeaning {
		t.Errorf("summary = %+v, want %+v", r.Summary, want)
	}
	if len(r.Summary.Findings) != 3 || r.Summary.Findings["block"] != 0 || r.Summary.Findings["warn"] != 0 || r.Summary.Findings["info"] != 0 {
		t.Errorf("summary findings = %v, want block, warn and info at zero", r.Summary.Findings)
	}
}

func TestBuildSummaryAndNormalization(t *testing.T) {
	r := fixtureReport()
	s := r.Summary
	if s.Subjects != 3 || s.Skipped != 1 || s.ExitCode != 1 || s.ExitMeaning != "blocking findings" {
		t.Errorf("summary = %+v", s)
	}
	if s.Findings["block"] != 1 || s.Findings["warn"] != 1 || s.Findings["info"] != 0 {
		t.Errorf("summary findings = %v, want block 1, warn 1, info 0", s.Findings)
	}
	wantVerdicts := []string{VerdictBlock, VerdictSkipped, VerdictOK}
	for i, sub := range r.Subjects {
		if sub.Verdict != wantVerdicts[i] {
			t.Errorf("subject %d verdict = %q, want %q", i, sub.Verdict, wantVerdicts[i])
		}
		if sub.Evaluated == nil || sub.Skipped == nil || sub.Findings == nil {
			t.Errorf("subject %d has a nil slice; JSON must render [] not null: %+v", i, sub)
		}
	}
}

func TestSetExitCode(t *testing.T) {
	r := Build(nil, testTool(), testPolicy(), model.LevelBlock)
	r.SetExitCode(3)
	if r.Summary.ExitCode != 3 || r.Summary.ExitMeaning != "a required data source was unavailable" {
		t.Fatalf("summary after SetExitCode(3) = %+v", r.Summary)
	}
}

func TestExitMeaning(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{0, "no blocking findings"},
		{1, "blocking findings"},
		{2, "usage or configuration error"},
		{3, "a required data source was unavailable"},
		{42, "unknown exit code"},
	}
	for _, tt := range tests {
		if got := ExitMeaning(tt.code); got != tt.want {
			t.Errorf("ExitMeaning(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in      string
		want    model.Level
		wantErr bool
	}{
		{in: "block", want: model.LevelBlock},
		{in: "warn", want: model.LevelWarn},
		{in: "never", want: model.LevelOff},
		{in: " Block ", want: model.LevelBlock},
		{in: "info", wantErr: true},
		{in: "off", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseFailOn(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseFailOn(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseFailOn(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestCurrentTool(t *testing.T) {
	got := CurrentTool()
	want := Tool{Name: "trustdiff", Version: version.Version, Commit: version.Commit, Date: version.Date, GoVersion: runtime.Version()}
	if got != want {
		t.Fatalf("CurrentTool() = %+v, want %+v", got, want)
	}
}
