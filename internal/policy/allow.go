package policy

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/vahapogut/trustdiff/internal/model"
)

// AddAllow previews one exact package exception without rewriting other policy
// text. The caller resolves check IDs to policy names before calling this method.
func AddAllow(data []byte, check, packageRef, reason, expiry string, now time.Time) ([]byte, error) {
	p, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(packageRef, "*?[]\\") {
		return nil, fmt.Errorf("package must be an exact reference without wildcards")
	}
	ref, err := model.ParseRef(packageRef)
	if err != nil {
		return nil, err
	}
	pat, err := ParsePattern(ref.String())
	if err != nil {
		return nil, err
	}
	date, err := ParseDate(expiry)
	if err != nil {
		return nil, err
	}
	e := AllowEntry{Check: check, Package: pat, Reason: strings.TrimSpace(reason), Expires: date}
	if e.Reason == "" || strings.ContainsAny(e.Reason, "\r\n") {
		return nil, fmt.Errorf("reason must be a nonempty single line")
	}
	if e.Expired(now) {
		return nil, fmt.Errorf("expiry %s is already past", expiry)
	}
	for _, old := range p.Allow {
		if old.Check != check || old.Package.String() != pat.String() {
			continue
		}
		if old.Reason == e.Reason && old.Expires == e.Expires {
			return bytes.Clone(data), nil
		}
		return nil, fmt.Errorf("an exception for %s and %s already exists; review that entry before replacing it", check, pat)
	}
	p.Allow = append(p.Allow, e)
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var tree yaml.Node
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil, err
	}
	root := tree.Content[0]
	if root.Kind != yaml.MappingNode || root.Style&yaml.FlowStyle != 0 {
		return nil, fmt.Errorf("policy root must be a block mapping to edit safely")
	}
	newline := "\n"
	if bytes.Contains(data, []byte("\r\n")) {
		newline = "\r\n"
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	at := len(lines)
	for i, line := range lines {
		if strings.TrimSpace(line) == "..." {
			at = i
			break
		}
	}
	indent := 2
	found := false
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Value != "allow" {
			continue
		}
		found = true
		if value.Kind != yaml.SequenceNode || value.Anchor != "" {
			return nil, fmt.Errorf("allow must be an unanchored sequence to edit safely")
		}
		if len(value.Content) == 0 {
			line := lines[value.Line-1]
			prefix := value.Column - 1
			if value.Style&yaml.FlowStyle == 0 || prefix+2 > len(line) || line[prefix:prefix+2] != "[]" {
				return nil, fmt.Errorf("empty allow sequence cannot be edited safely")
			}
			lines[value.Line-1] = line[:prefix] + line[prefix+2:]
			at = value.Line
		} else {
			if value.Style&yaml.FlowStyle != 0 {
				return nil, fmt.Errorf("flow-style allow sequence cannot be edited safely")
			}
			indent = value.Content[0].Column - 3
			if indent < 0 {
				return nil, fmt.Errorf("invalid allow indentation")
			}
			last, err := editableEnd(value)
			if err != nil {
				return nil, err
			}
			at = last
		}
	}
	var encoded bytes.Buffer
	enc := yaml.NewEncoder(&encoded)
	enc.SetIndent(2)
	if err := enc.Encode([]AllowEntry{e}); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	added := strings.Split(strings.TrimSuffix(encoded.String(), "\n"), "\n")
	for i := range added {
		added[i] = strings.Repeat(" ", indent) + added[i]
	}
	if !found {
		added = append([]string{"allow:"}, added...)
	}
	out := append([]string{}, lines[:at]...)
	out = append(out, added...)
	out = append(out, lines[at:]...)
	result := []byte(strings.Join(out, newline) + newline)
	if _, err := Parse(result); err != nil {
		return nil, fmt.Errorf("refusing invalid edited policy: %w", err)
	}
	return result, nil
}

func editableEnd(n *yaml.Node) (int, error) {
	if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || strings.ContainsAny(n.Value, "\r\n") {
		return 0, fmt.Errorf("allow contains anchors or multiline values; edit it manually")
	}
	last := n.Line
	for _, child := range n.Content {
		end, err := editableEnd(child)
		if err != nil {
			return 0, err
		}
		last = max(last, end)
	}
	return last, nil
}
