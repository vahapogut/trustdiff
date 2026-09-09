package jsonschema

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func addError(errs *[]error, pointer, keyword, message string) {
	*errs = append(*errs, &ValidationError{Pointer: pointer, Keyword: keyword, Message: message})
}

// validate applies every keyword of n to v, appending one error per failed keyword.
// Keywords are independent: a keyword that does not apply to the instance's type is
// skipped rather than failed, as the specification requires.
func (n *node) validate(v any, pointer string, errs *[]error) {
	if n.isBool {
		if !n.boolValue {
			addError(errs, pointer, "false", "no value is allowed here")
		}
		return
	}
	kind, ok := jsonType(v)
	if !ok {
		addError(errs, pointer, "type",
			fmt.Sprintf("unsupported Go value of type %T (decode the instance with encoding/json into any)", v))
		return
	}
	if n.ref != nil {
		n.ref.validate(v, pointer, errs)
	}
	if n.types != nil && !matchesAnyType(n.types, kind, v) {
		addError(errs, pointer, "type", fmt.Sprintf("want %s, got %s", orList(n.types), kind))
	}
	if n.hasEnum && !containsJSON(n.enum, v) {
		addError(errs, pointer, "enum", fmt.Sprintf("value %s is not one of %s", formatValue(v), formatValue(n.enum)))
	}
	if n.hasConst && !equalJSON(n.constant, v) {
		addError(errs, pointer, "const", fmt.Sprintf("value %s is not %s", formatValue(v), formatValue(n.constant)))
	}
	switch x := v.(type) {
	case map[string]any:
		n.validateObject(x, pointer, errs)
	case []any:
		n.validateArray(x, pointer, errs)
	case string:
		n.validateString(x, pointer, errs)
	default:
		if f, isNumber := asNumber(v); isNumber {
			n.validateNumber(f, pointer, errs)
		}
	}
	n.validateCombinators(v, pointer, errs)
}

func matchesAnyType(want []string, kind string, v any) bool {
	for _, name := range want {
		if name == kind {
			return true
		}
		if name == "integer" && kind == "number" {
			f, _ := asNumber(v)
			if f == math.Trunc(f) && !math.IsInf(f, 0) {
				return true
			}
		}
	}
	return false
}

func (n *node) validateObject(obj map[string]any, pointer string, errs *[]error) {
	for _, name := range n.required {
		if _, present := obj[name]; !present {
			addError(errs, pointer, "required", fmt.Sprintf("missing property %q", name))
		}
	}
	if len(n.properties) == 0 && len(n.patternProperties) == 0 && n.additionalAllowed && n.additional == nil {
		return
	}
	for _, key := range sortedKeys(obj) {
		child := pointer + "/" + escapePointer(key)
		value := obj[key]
		matched := false
		if sub, ok := n.properties[key]; ok {
			sub.validate(value, child, errs)
			matched = true
		}
		for _, pp := range n.patternProperties {
			if pp.re.MatchString(key) {
				pp.schema.validate(value, child, errs)
				matched = true
			}
		}
		if matched {
			continue
		}
		if !n.additionalAllowed {
			addError(errs, child, "additionalProperties", fmt.Sprintf("property %q is not allowed", key))
			continue
		}
		if n.additional != nil {
			n.additional.validate(value, child, errs)
		}
	}
}

func (n *node) validateArray(arr []any, pointer string, errs *[]error) {
	if n.items != nil {
		for i, item := range arr {
			n.items.validate(item, pointer+"/"+strconv.Itoa(i), errs)
		}
	}
	if n.minItems >= 0 && len(arr) < n.minItems {
		addError(errs, pointer, "minItems", fmt.Sprintf("array has %s, want at least %d", plural(len(arr), "item"), n.minItems))
	}
	if n.maxItems >= 0 && len(arr) > n.maxItems {
		addError(errs, pointer, "maxItems", fmt.Sprintf("array has %s, want at most %d", plural(len(arr), "item"), n.maxItems))
	}
	if n.uniqueItems {
		if i, j, dup := firstDuplicate(arr); dup {
			addError(errs, pointer, "uniqueItems", fmt.Sprintf("items %d and %d are equal", i, j))
		}
	}
}

// firstDuplicate returns the first pair of equal items, earliest first index and
// then earliest second index, so the message is stable. Items are compared through
// a canonical encoding (encoding/json sorts object keys; numbers are normalized
// first) looked up in a map, so a large array costs one encoding per item rather
// than one deep comparison per pair.
func firstDuplicate(arr []any) (i, j int, found bool) {
	first := make(map[string]int, len(arr))
	for k, item := range arr {
		if _, ok := jsonType(item); !ok {
			// Not a JSON value: validate reports it as a type error, and equalJSON
			// never equates such a value with anything.
			continue
		}
		key, err := json.Marshal(normalizeNumbers(item))
		if err != nil {
			// Unreachable for values produced by encoding/json.
			continue
		}
		earlier, dup := first[string(key)]
		if !dup {
			first[string(key)] = k
			continue
		}
		// The first duplicate of a key pairs its earliest two occurrences. A later key
		// may still have an earlier first occurrence, so keep the smallest first index.
		if !found || earlier < i {
			i, j, found = earlier, k, true
		}
	}
	return i, j, found
}

// normalizeNumbers returns a copy of v with every number as a float64 and negative
// zero as zero, so that equal JSON values encode to the same bytes: 1, 1.0 and
// json.Number("1") all become 1.
func normalizeNumbers(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalizeNumbers(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalizeNumbers(e)
		}
		return out
	}
	if f, ok := asNumber(v); ok {
		if f == 0 {
			// -0 equals 0 but would encode as "-0".
			f = 0
		}
		return f
	}
	return v
}

func (n *node) validateString(s, pointer string, errs *[]error) {
	count := utf8.RuneCountInString(s)
	if n.minLength >= 0 && count < n.minLength {
		addError(errs, pointer, "minLength", fmt.Sprintf("string has %s, want at least %d", plural(count, "character"), n.minLength))
	}
	if n.maxLength >= 0 && count > n.maxLength {
		addError(errs, pointer, "maxLength", fmt.Sprintf("string has %s, want at most %d", plural(count, "character"), n.maxLength))
	}
	if n.pattern != nil && !n.pattern.MatchString(s) {
		addError(errs, pointer, "pattern", fmt.Sprintf("%q does not match %s", s, n.patternSource))
	}
	if n.format != "" && !matchesFormat(n.format, s) {
		addError(errs, pointer, "format", fmt.Sprintf("%q is not a valid %s", s, n.format))
	}
}

// matchesFormat checks the few formats the project schemas rely on and accepts every
// other format name, which is what the specification allows for format.
func matchesFormat(format, s string) bool {
	switch format {
	case "date":
		_, err := time.Parse("2006-01-02", s)
		return err == nil
	case "date-time":
		// RFC 3339 allows a lowercase "t" separator and "z" designator; Go's layout
		// does not, so retry upper-cased. The string has no other letters.
		if _, err := time.Parse(time.RFC3339, s); err == nil {
			return true
		}
		_, err := time.Parse(time.RFC3339, strings.ToUpper(s))
		return err == nil
	case "uri":
		u, err := url.Parse(s)
		return err == nil && u.Scheme != ""
	case "uri-reference":
		_, err := url.Parse(s)
		return err == nil
	default:
		return true
	}
}

func (n *node) validateNumber(f float64, pointer string, errs *[]error) {
	if n.minimum != nil {
		switch {
		case n.minimumExclusive && f <= *n.minimum:
			addError(errs, pointer, "minimum", fmt.Sprintf("%s is not greater than %s", formatNumber(f), formatNumber(*n.minimum)))
		case !n.minimumExclusive && f < *n.minimum:
			addError(errs, pointer, "minimum", fmt.Sprintf("%s is less than %s", formatNumber(f), formatNumber(*n.minimum)))
		}
	}
	if n.maximum != nil {
		switch {
		case n.maximumExclusive && f >= *n.maximum:
			addError(errs, pointer, "maximum", fmt.Sprintf("%s is not less than %s", formatNumber(f), formatNumber(*n.maximum)))
		case !n.maximumExclusive && f > *n.maximum:
			addError(errs, pointer, "maximum", fmt.Sprintf("%s is greater than %s", formatNumber(f), formatNumber(*n.maximum)))
		}
	}
	if n.exclusiveMinimum != nil && f <= *n.exclusiveMinimum {
		addError(errs, pointer, "exclusiveMinimum", fmt.Sprintf("%s is not greater than %s", formatNumber(f), formatNumber(*n.exclusiveMinimum)))
	}
	if n.exclusiveMaximum != nil && f >= *n.exclusiveMaximum {
		addError(errs, pointer, "exclusiveMaximum", fmt.Sprintf("%s is not less than %s", formatNumber(f), formatNumber(*n.exclusiveMaximum)))
	}
}

func (n *node) validateCombinators(v any, pointer string, errs *[]error) {
	for _, sub := range n.allOf {
		sub.validate(v, pointer, errs)
	}
	if len(n.anyOf) > 0 {
		matched, failures := tryAlternatives(n.anyOf, v, pointer)
		if len(matched) == 0 {
			addError(errs, pointer, "anyOf", fmt.Sprintf("value matches none of %d alternatives: %s", len(n.anyOf), strings.Join(failures, "; ")))
		}
	}
	if len(n.oneOf) > 0 {
		matched, failures := tryAlternatives(n.oneOf, v, pointer)
		switch {
		case len(matched) == 0:
			addError(errs, pointer, "oneOf", fmt.Sprintf("value matches none of %d alternatives: %s", len(n.oneOf), strings.Join(failures, "; ")))
		case len(matched) > 1:
			addError(errs, pointer, "oneOf", fmt.Sprintf("value matches %d alternatives (%s), want exactly one", len(matched), andList(matched)))
		}
	}
	if n.not != nil {
		var sub []error
		n.not.validate(v, pointer, &sub)
		if len(sub) == 0 {
			addError(errs, pointer, "not", "value matches the schema it must not match")
		}
	}
}

// tryAlternatives validates v against each alternative and returns the indices that
// matched plus a one-line summary of why each other alternative failed.
func tryAlternatives(alternatives []*node, v any, pointer string) (matched []int, failures []string) {
	for i, sub := range alternatives {
		var subErrs []error
		sub.validate(v, pointer, &subErrs)
		if len(subErrs) == 0 {
			matched = append(matched, i)
			continue
		}
		messages := make([]string, 0, len(subErrs))
		for _, err := range subErrs {
			messages = append(messages, err.Error())
		}
		failures = append(failures, fmt.Sprintf("[%d] %s", i, strings.Join(messages, "; ")))
	}
	return matched, failures
}
