package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// External findings are escaped as JSON rather than rendered as terminal control
// codes or active Markdown. Full structured evidence remains available in JSON.
func writeAnalysis(b *strings.Builder, r *Report, markdown bool) {
	if !r.GuardDogRequested {
		return
	}
	if markdown {
		b.WriteString("\n### GuardDog source analysis\n\n")
	} else {
		b.WriteString("\nGuardDog source analysis (supplement)\n")
	}
	if len(r.GuardDog) == 0 {
		b.WriteString("No warn/block registry releases selected.\n")
		return
	}
	for i := range r.GuardDog {
		a := &r.GuardDog[i]
		data, _ := json.Marshal(a)
		if markdown {
			// JSON escapes source newlines, so data cannot close this fence on a
			// separate line and introduce active Markdown.
			b.WriteString("~~~~json\n")
			b.Write(data)
			b.WriteString("\n~~~~\n\n")
		} else {
			fmt.Fprintf(b, "%s\n", data)
		}
	}
}
