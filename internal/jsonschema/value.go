package jsonschema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

func decodeInstance(instance []byte) (any, error) {
	var v any
	if err := json.Unmarshal(instance, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// escapePointer encodes one reference token as RFC 6901 requires: "~" becomes "~0"
// and "/" becomes "~1", in that order.
func escapePointer(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

func unescapePointer(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
}

// resolvePointer walks a decoded document along an RFC 6901 pointer. The empty
// pointer names the document itself.
func resolvePointer(doc any, pointer string) (any, bool) {
	if pointer == "" {
		return doc, true
	}
	current := doc
	for _, token := range strings.Split(pointer[1:], "/") {
		token = unescapePointer(token)
		switch container := current.(type) {
		case map[string]any:
			next, ok := container[token]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(container) {
				return nil, false
			}
			current = container[index]
		default:
			return nil, false
		}
	}
	return current, true
}

// jsonType names the JSON type of a decoded value. The second result is false for
// Go values that encoding/json would never produce when decoding into any.
func jsonType(v any) (string, bool) {
	switch v.(type) {
	case nil:
		return "null", true
	case bool:
		return "boolean", true
	case string:
		return "string", true
	case map[string]any:
		return "object", true
	case []any:
		return "array", true
	}
	if _, ok := asNumber(v); ok {
		return "number", true
	}
	return "", false
}

// asNumber converts the numeric representations a decoded document can carry:
// float64 from encoding/json, json.Number when the decoder used UseNumber, and Go
// integer and float types as a convenience for hand-built values.
func asNumber(v any) (float64, bool) {
	if num, ok := v.(json.Number); ok {
		f, err := num.Float64()
		return f, err == nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	default:
		return 0, false
	}
}

// equalJSON compares two decoded values as JSON values: objects by key set and
// member values, arrays element by element, numbers by value.
func equalJSON(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, present := y[k]
			if !present || !equalJSON(xv, yv) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equalJSON(x[i], y[i]) {
				return false
			}
		}
		return true
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	}
	xf, xok := asNumber(a)
	yf, yok := asNumber(b)
	return xok && yok && xf == yf
}

func containsJSON(list []any, v any) bool {
	for _, item := range list {
		if equalJSON(item, v) {
			return true
		}
	}
	return false
}

// formatValue renders a value as compact JSON for error messages, shortened so a
// large object does not swamp the message.
func formatValue(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprintf("%v", v)
	}
	s := strings.TrimSuffix(buf.String(), "\n")
	const limit = 80
	if utf8.RuneCountInString(s) > limit {
		runes := []rune(s)
		s = string(runes[:limit-3]) + "..."
	}
	return s
}

func formatNumber(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func plural(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(count) + " " + noun + "s"
}

// orList renders ["a"] as "a", ["a","b"] as "a or b" and ["a","b","c"] as "a, b or c".
func orList(items []string) string {
	return joinList(items, "or")
}

// andList renders indices the same way with "and".
func andList(indices []int) string {
	items := make([]string, 0, len(indices))
	for _, i := range indices {
		items = append(items, strconv.Itoa(i))
	}
	return joinList(items, "and")
}

func joinList(items []string, conjunction string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " " + conjunction + " " + items[len(items)-1]
	}
}
