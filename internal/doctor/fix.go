package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/vahapogut/trustdiff/internal/configfile"
	"github.com/vahapogut/trustdiff/internal/textdiff"
)

// newFileMode is what a configuration file this tool creates is given. It is the
// mode a person's own editor would have used, and an existing file keeps whatever
// mode it already has.
const newFileMode os.FileMode = 0o600

// applyFixes writes the settings the files do not state, one file at a time,
// and records what it changed on each result.
//
// Three things it will not do, all of them deliberate. It never touches a rule
// whose answer is a judgment rather than a value, which is what Fixable false
// means: which packages may run a build script is not a question a tool can
// answer. It never writes into a construct the codec refuses, and the reason ends
// up in the scorecard instead. And it never writes a file it did not first read,
// so a fix is always a change to something the run has seen.
func applyFixes(root string, card *Scorecard, opts *Options) {
	// One backup per file, not one per setting. Five npm rules write into the same
	// .npmrc, and a copy taken before each of them would be four copies of a file
	// this run has already changed, under names that collide inside the same
	// second. The first copy is the one worth keeping: it is the file as the person
	// left it.
	backups := map[string]string{}
	for i := range card.Results {
		res := &card.Results[i]
		if !fixable(res) {
			continue
		}
		changed, backup, err := fixOne(root, res, opts, backups)
		if err != nil {
			// One file that cannot be written must not stop the others: the run
			// says so on the result and carries on, because a monorepo where one
			// directory is read only should still get the other nine fixed. The run
			// is still incomplete, which the exit code follows.
			reason := slashed(err.Error())
			res.Detail = appendSentence(res.Detail, "could not be written: "+reason)
			card.Notes = append(card.Notes, res.File+": "+reason)
			if !contains(card.Failed, res.File) {
				card.Failed = append(card.Failed, res.File)
			}
			continue
		}
		if !changed {
			continue
		}
		if !contains(card.Changed, res.File) {
			card.Changed = append(card.Changed, res.File)
		}
		if backup != "" {
			card.Backups[res.File] = backup
		}
	}
}

// fixable reports whether a result is one --fix may write.
func fixable(res *Result) bool {
	if res.Manager != nil && res.Manager.UserScope() {
		// The machine's own configuration is reported, never written: a run inside
		// one repository must not change what every other project on the computer
		// installs with.
		return false
	}
	// Only a key the file does not have. A value that is already there was written
	// by somebody, and a tool that runs over a repository it does not own has no
	// business deciding they were wrong: it says what the value does and leaves the
	// line alone. That is what makes --fix safe to put in a script.
	return res.Rule != nil && res.Rule.Fixable &&
		res.Rule.Scan == nil &&
		res.Status == StatusMissing &&
		res.File != "" && res.target.Name != ""
}

// fixOne writes one setting. It returns false when there was nothing to write,
// which is what a second run of the fixer does to every file, and the backup it
// left beside the file when it wrote one.
func fixOne(root string, res *Result, opts *Options, backups map[string]string) (changed bool, backup string, err error) {
	_, full := targetPath(root, res.Manager, res.target)
	data, err := readConfig(full)
	created := false
	switch {
	case errors.Is(err, os.ErrNotExist):
		if !res.target.CreateIf {
			// Not an error: the rule says where the setting belongs and this file
			// is not one to conjure. pip reads its configuration from the machine,
			// and a pip.conf written into a repository would look like protection
			// and be none.
			res.Detail = appendSentence(res.Detail, res.File+" does not exist, and this setting is not written into a file the manager would not read")
			return false, "", nil
		}
		created, data = true, nil
	case err != nil:
		return false, "", err
	}

	doc := configfile.NewDoc(res.File, res.target.Format, data)
	edit, ok, err := configfile.Set(doc, res.target.Key, res.Rule.Desired.Want(&res.params))
	switch {
	case errors.Is(err, configfile.ErrNotEditable):
		res.Detail = appendSentence(res.Detail, err.Error()+", so it was left alone")
		return false, "", nil
	case err != nil:
		return false, "", err
	case !ok:
		// The file already says exactly this. Nothing is written and nothing is
		// reported as changed, which is what makes the second run a no-op.
		return false, "", nil
	}

	next, err := doc.Apply(edit)
	if err != nil {
		return false, "", err
	}
	res.Edit = string(textdiff.Unified(res.File, res.File, doc.Bytes(), next.Bytes()))

	mode := newFileMode
	if !created {
		info, statErr := os.Stat(full)
		if statErr != nil {
			return false, "", statErr
		}
		mode = info.Mode().Perm()
		switch existing, done := backups[full]; {
		case done:
			// Another rule of this run already copied the file.
			backup = existing
		case opts.Backup:
			copied, backupErr := textdiff.Backup(full, opts.Params.Now)
			if backupErr != nil {
				return false, "", backupErr
			}
			backup = filepath.ToSlash(mustRel(root, copied))
			backups[full] = backup
		}
	} else if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return false, "", err
	}
	if err := textdiff.Write(full, next.Bytes(), mode); err != nil {
		return false, "", err
	}
	// The judgment described the value that was there, and it is not there any
	// more. A line that says "set" over a sentence explaining what is wrong with it
	// is a line nobody can read.
	written := strings.TrimSpace(strings.Join(edit.Lines, " "))
	res.Detail = "written: " + written
	if backup != "" {
		res.Detail = appendSentence(res.Detail, "the previous file is kept as "+backup)
	}
	res.Current = written
	res.Fixed = true
	res.Status = StatusSet
	res.Line = edit.Start
	return true, backup, nil
}

// mustRel names a path relative to the root when it can, and as it is otherwise,
// because a backup beside the file is what the reader wants to see and an
// absolute path is still an answer.
func mustRel(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

// appendSentence joins two sentences of a detail line, either of which may be
// empty.
func appendSentence(existing, add string) string {
	switch {
	case existing == "":
		return add
	case add == "":
		return existing
	}
	return existing + "; " + add
}

// contains reports whether the list already names the file, so a file five rules
// wrote into is listed once.
func contains(list []string, want string) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}

// slashed writes the paths inside a message the way the rest of the report writes
// them. An error from the file system carries the platform's own separator, and a
// scorecard that says C:\Users in one line and C:/Users in the next is one nobody
// can grep.
func slashed(message string) string {
	return strings.ReplaceAll(message, "\\", "/")
}
