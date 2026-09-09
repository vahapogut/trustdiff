package model

import (
	"fmt"
	"strings"
)

// Level is the severity assigned to a check or a finding. The order matters:
// a policy that fails on "warn" also fails on "block".
type Level int

// Levels from least to most severe. LevelOff disables a check entirely.
const (
	LevelOff Level = iota
	LevelInfo
	LevelWarn
	LevelBlock
)

var levelNames = map[Level]string{
	LevelOff:   "off",
	LevelInfo:  "info",
	LevelWarn:  "warn",
	LevelBlock: "block",
}

// ParseLevel accepts the spelling used in policy files and on the command line.
func ParseLevel(s string) (Level, error) {
	needle := strings.ToLower(strings.TrimSpace(s))
	for l, name := range levelNames {
		if name == needle {
			return l, nil
		}
	}
	return LevelOff, fmt.Errorf("unknown level %q (want off, info, warn or block)", s)
}

func (l Level) String() string {
	if name, ok := levelNames[l]; ok {
		return name
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// AtLeast reports whether l is as severe as other or more.
func (l Level) AtLeast(other Level) bool { return l >= other }

// MarshalText renders the level by name so it reads well in JSON and YAML.
func (l Level) MarshalText() ([]byte, error) {
	if _, ok := levelNames[l]; !ok {
		return nil, fmt.Errorf("cannot encode %s", l)
	}
	return []byte(l.String()), nil
}

// UnmarshalText parses the level by name.
func (l *Level) UnmarshalText(text []byte) error {
	parsed, err := ParseLevel(string(text))
	if err != nil {
		return err
	}
	*l = parsed
	return nil
}
