package model

// Location points at the lockfile line an entry came from, when known.
type Location struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
}

// Finding is one result of one check for one package. The Evidence map is part of the
// stable JSON and SARIF output: keys are documented per check in docs/checks.md and
// never renamed within a schema version.
type Finding struct {
	// ID is the stable check identifier, for example TD002.
	ID string `json:"id"`
	// Name is the check's policy name, for example publisher-changed.
	Name string `json:"name"`
	// Level is the effective level after the policy was applied.
	Level Level `json:"level"`
	// Ref is the package version the finding is about.
	Ref PackageRef `json:"ref"`
	// Title is one line suitable for a terminal or an annotation.
	Title string `json:"title"`
	// Explanation is the human account of the evidence, for example
	// "previous 12 versions were published by alice; 4.19.3 was published by bob-ci".
	Explanation string `json:"explanation"`
	// Evidence holds the machine-readable facts behind the explanation.
	Evidence map[string]any `json:"evidence,omitempty"`
	// Location is set when the subject came from a lockfile.
	Location *Location `json:"location,omitempty"`
}

// Skipped records a check that could not run for a subject. It is reported, never
// hidden, so that an unavailable data source is not mistaken for a pass.
type Skipped struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// Subject is what a run evaluates: one package version, with its origin when it came
// from a lockfile. The check runner extends it with the data every check needs.
type Subject struct {
	Ref      PackageRef `json:"ref"`
	Location *Location  `json:"location,omitempty"`
	// Direct is true when the subject is a direct dependency of the project.
	Direct bool `json:"direct,omitempty"`
}
