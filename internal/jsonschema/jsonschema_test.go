package jsonschema

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// keywordCase is one schema and one instance. want lists substrings that must each
// appear in the joined error text; an empty want means the instance must be valid.
type keywordCase struct {
	name     string
	schema   string
	instance string
	want     []string
}

func runCases(t *testing.T, cases []keywordCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Compile([]byte(tc.schema))
			if err != nil {
				t.Fatalf("Compile(%s): %v", tc.schema, err)
			}
			assertErrors(t, s.Validate([]byte(tc.instance)), tc.want)
		})
	}
}

func assertErrors(t *testing.T, err error, want []string) {
	t.Helper()
	if len(want) == 0 {
		if err != nil {
			t.Fatalf("unexpected validation error:\n%v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("want errors containing %q, got none", want)
	}
	got := err.Error()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("error text does not contain %q:\n%s", w, got)
		}
	}
}

// flatten unwraps an errors.Join result into its ValidationError leaves.
func flatten(err error) []*ValidationError {
	var out []*ValidationError
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				walk(child)
			}
			return
		}
		var ve *ValidationError
		if errors.As(e, &ve) {
			out = append(out, ve)
		}
	}
	walk(err)
	return out
}

// lookupError returns the leaf error at pointer for keyword, or nil.
func lookupError(err error, pointer, keyword string) *ValidationError {
	for _, ve := range flatten(err) {
		if ve.Pointer == pointer && ve.Keyword == keyword {
			return ve
		}
	}
	return nil
}

func requireError(t *testing.T, err error, pointer, keyword string) {
	t.Helper()
	if lookupError(err, pointer, keyword) == nil {
		t.Fatalf("no error at pointer %q for keyword %q in:\n%v", pointer, keyword, err)
	}
}

// requireOnlyError asserts that err carries exactly one leaf, at pointer for keyword.
func requireOnlyError(t *testing.T, err error, pointer, keyword string) {
	t.Helper()
	requireError(t, err, pointer, keyword)
	if leaves := flatten(err); len(leaves) != 1 {
		t.Fatalf("got %d errors, want only %s at %q:\n%v", len(leaves), keyword, pointer, err)
	}
}

// replaceOnce edits a fixture and fails the test when old is absent, so a test can
// never end up validating the unedited fixture.
func replaceOnce(t *testing.T, s, old, replacement string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("fixture does not contain %s", old)
	}
	return strings.Replace(s, old, replacement, 1)
}

func TestType(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "string ok", schema: `{"type":"string"}`, instance: `"hi"`},
		{name: "string wrong", schema: `{"type":"string"}`, instance: `1`, want: []string{"#: type: want string, got number"}},
		{name: "number ok", schema: `{"type":"number"}`, instance: `1.5`},
		{name: "integer accepts whole float", schema: `{"type":"integer"}`, instance: `3.0`},
		{name: "integer accepts plain int", schema: `{"type":"integer"}`, instance: `3`},
		{name: "integer accepts negative", schema: `{"type":"integer"}`, instance: `-7`},
		{name: "integer rejects fraction", schema: `{"type":"integer"}`, instance: `3.5`, want: []string{"type: want integer, got number"}},
		{name: "integer rejects string", schema: `{"type":"integer"}`, instance: `"3"`, want: []string{"type: want integer, got string"}},
		{name: "boolean ok", schema: `{"type":"boolean"}`, instance: `true`},
		{name: "boolean wrong", schema: `{"type":"boolean"}`, instance: `"true"`, want: []string{"want boolean, got string"}},
		{name: "null ok", schema: `{"type":"null"}`, instance: `null`},
		{name: "null wrong", schema: `{"type":"null"}`, instance: `0`, want: []string{"want null, got number"}},
		{name: "object ok", schema: `{"type":"object"}`, instance: `{}`},
		{name: "object wrong", schema: `{"type":"object"}`, instance: `[]`, want: []string{"want object, got array"}},
		{name: "array ok", schema: `{"type":"array"}`, instance: `[1]`},
		{name: "array wrong", schema: `{"type":"array"}`, instance: `{}`, want: []string{"want array, got object"}},
		{name: "type list ok null", schema: `{"type":["array","null"]}`, instance: `null`},
		{name: "type list ok array", schema: `{"type":["array","null"]}`, instance: `[]`},
		{name: "type list wrong", schema: `{"type":["array","null"]}`, instance: `{}`, want: []string{"type: want array or null, got object"}},
		{name: "type list three", schema: `{"type":["string","integer","null"]}`, instance: `1.5`, want: []string{"want string, integer or null, got number"}},
		{name: "no type accepts anything", schema: `{}`, instance: `{"a":[1,"x",null]}`},
	})
}

func TestEnumAndConst(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "enum string ok", schema: `{"enum":["none","note","warning","error"]}`, instance: `"note"`},
		{name: "enum string wrong", schema: `{"enum":["none","note","warning","error"]}`, instance: `"fatal"`,
			want: []string{`#: enum: value "fatal" is not one of ["none","note","warning","error"]`}},
		{name: "enum mixed types", schema: `{"enum":[1,"1",null,true,[1,2],{"a":1}]}`, instance: `{"a":1}`},
		{name: "enum mixed types array", schema: `{"enum":[1,"1",null,[1,2]]}`, instance: `[1,2]`},
		{name: "enum number vs string", schema: `{"enum":[1]}`, instance: `"1"`, want: []string{"enum:"}},
		{name: "enum null", schema: `{"enum":[null]}`, instance: `null`},
		{name: "enum object key order", schema: `{"enum":[{"a":1,"b":2}]}`, instance: `{"b":2,"a":1}`},
		{name: "enum object extra key", schema: `{"enum":[{"a":1}]}`, instance: `{"a":1,"b":2}`, want: []string{"enum:"}},
		{name: "const ok", schema: `{"const":"trustdiff.report/1"}`, instance: `"trustdiff.report/1"`},
		{name: "const wrong", schema: `{"const":"trustdiff.report/1"}`, instance: `"trustdiff.report/2"`,
			want: []string{`const: value "trustdiff.report/2" is not "trustdiff.report/1"`}},
		{name: "const number equal float", schema: `{"const":2}`, instance: `2.0`},
		{name: "const object", schema: `{"const":{"a":[1,2]}}`, instance: `{"a":[1,2]}`},
		{name: "const object wrong", schema: `{"const":{"a":[1,2]}}`, instance: `{"a":[2,1]}`, want: []string{"const:"}},
	})
}

func TestRequiredAndProperties(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "required ok", schema: `{"required":["a","b"]}`, instance: `{"a":1,"b":null}`},
		{name: "required missing", schema: `{"required":["a","b"]}`, instance: `{"a":1}`, want: []string{`#: required: missing property "b"`}},
		{name: "required not object", schema: `{"required":["a"]}`, instance: `[]`},
		{name: "required all missing reported", schema: `{"required":["a","b"]}`, instance: `{}`,
			want: []string{`missing property "a"`, `missing property "b"`}},
		{name: "properties ok", schema: `{"properties":{"n":{"type":"integer"}}}`, instance: `{"n":1,"other":"free"}`},
		{name: "properties wrong", schema: `{"properties":{"n":{"type":"integer"}}}`, instance: `{"n":"x"}`, want: []string{"#/n: type: want integer, got string"}},
		{name: "properties nested pointer", schema: `{"properties":{"a":{"properties":{"b":{"type":"string"}}}}}`, instance: `{"a":{"b":1}}`,
			want: []string{"#/a/b: type: want string, got number"}},
		{name: "properties not object", schema: `{"properties":{"n":{"type":"integer"}}}`, instance: `"scalar"`},
	})
}

func TestAdditionalAndPatternProperties(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "additional false ok", schema: `{"properties":{"a":{}},"additionalProperties":false}`, instance: `{"a":1}`},
		{name: "additional false wrong", schema: `{"properties":{"a":{}},"additionalProperties":false}`, instance: `{"a":1,"zzz":2}`,
			want: []string{`#/zzz: additionalProperties: property "zzz" is not allowed`}},
		{name: "additional true", schema: `{"properties":{"a":{}},"additionalProperties":true}`, instance: `{"a":1,"b":2}`},
		{name: "additional schema ok", schema: `{"additionalProperties":{"type":"string"}}`, instance: `{"a":"x","b":"y"}`},
		{name: "additional schema wrong", schema: `{"properties":{"n":{"type":"integer"}},"additionalProperties":{"type":"string"}}`,
			instance: `{"n":1,"b":2}`, want: []string{"#/b: type: want string, got number"}},
		{name: "pattern properties ok", schema: `{"patternProperties":{"^x-":{"type":"string"}},"additionalProperties":false}`, instance: `{"x-a":"1","x-b":"2"}`},
		{name: "pattern properties wrong", schema: `{"patternProperties":{"^x-":{"type":"string"}}}`, instance: `{"x-a":1}`,
			want: []string{"#/x-a: type: want string, got number"}},
		{name: "pattern properties unmatched is additional", schema: `{"patternProperties":{"^x-":{}},"additionalProperties":false}`, instance: `{"y":1}`,
			want: []string{`#/y: additionalProperties: property "y" is not allowed`}},
		{name: "properties win over additional", schema: `{"properties":{"a":{"type":"integer"}},"patternProperties":{"^a":{"type":"integer"}},"additionalProperties":false}`,
			instance: `{"a":1,"ab":2}`},
	})
}

func TestArrays(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "items ok", schema: `{"items":{"type":"integer"}}`, instance: `[1,2,3]`},
		{name: "items wrong pointer", schema: `{"items":{"type":"integer"}}`, instance: `[1,"two",3.5]`,
			want: []string{"#/1: type: want integer, got string", "#/2: type: want integer, got number"}},
		{name: "items not array", schema: `{"items":{"type":"integer"}}`, instance: `{"0":"x"}`},
		{name: "items boolean false rejects any", schema: `{"items":false}`, instance: `[1]`, want: []string{"#/0: false: no value is allowed here"}},
		{name: "items boolean false empty ok", schema: `{"items":false}`, instance: `[]`},
		{name: "minItems ok", schema: `{"minItems":2}`, instance: `[1,2]`},
		{name: "minItems wrong", schema: `{"minItems":2}`, instance: `[1]`, want: []string{"#: minItems: array has 1 item, want at least 2"}},
		{name: "minItems zero", schema: `{"minItems":0}`, instance: `[]`},
		{name: "maxItems ok", schema: `{"maxItems":2}`, instance: `[1,2]`},
		{name: "maxItems wrong", schema: `{"maxItems":2}`, instance: `[1,2,3]`, want: []string{"maxItems: array has 3 items, want at most 2"}},
		{name: "uniqueItems ok", schema: `{"uniqueItems":true}`, instance: `[1,"1",[1],{"a":1},{"a":2},null]`},
		{name: "uniqueItems wrong scalars", schema: `{"uniqueItems":true}`, instance: `[1,2,1.0]`, want: []string{"#: uniqueItems: items 0 and 2 are equal"}},
		{name: "uniqueItems wrong objects", schema: `{"uniqueItems":true}`, instance: `[{"a":1,"b":[1]},{"b":[1],"a":1}]`, want: []string{"items 0 and 1 are equal"}},
		{name: "uniqueItems nested numbers", schema: `{"uniqueItems":true}`, instance: `[{"a":[1,2.5]},{"a":[1.0,2.5]}]`, want: []string{"items 0 and 1 are equal"}},
		{name: "uniqueItems negative zero", schema: `{"uniqueItems":true}`, instance: `[0,-0]`, want: []string{"items 0 and 1 are equal"}},
		{name: "uniqueItems reports the earliest first index", schema: `{"uniqueItems":true}`, instance: `[1,2,2,1]`, want: []string{"items 0 and 3 are equal"}},
		{name: "uniqueItems reports the earliest second index", schema: `{"uniqueItems":true}`, instance: `[1,1,1]`, want: []string{"items 0 and 1 are equal"}},
		{name: "uniqueItems false", schema: `{"uniqueItems":false}`, instance: `[1,1]`},
	})
}

func TestNumericBounds(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "minimum ok equal", schema: `{"minimum":1}`, instance: `1`},
		{name: "minimum wrong", schema: `{"minimum":1}`, instance: `0.5`, want: []string{"#: minimum: 0.5 is less than 1"}},
		{name: "maximum ok equal", schema: `{"maximum":3}`, instance: `3`},
		{name: "maximum wrong", schema: `{"maximum":3}`, instance: `3.25`, want: []string{"maximum: 3.25 is greater than 3"}},
		{name: "draft04 exclusive minimum ok", schema: `{"minimum":1,"exclusiveMinimum":true}`, instance: `1.001`},
		{name: "draft04 exclusive minimum wrong", schema: `{"minimum":1,"exclusiveMinimum":true}`, instance: `1`, want: []string{"minimum: 1 is not greater than 1"}},
		{name: "draft04 exclusive minimum false", schema: `{"minimum":1,"exclusiveMinimum":false}`, instance: `1`},
		{name: "draft04 exclusive maximum wrong", schema: `{"maximum":3,"exclusiveMaximum":true}`, instance: `3`, want: []string{"maximum: 3 is not less than 3"}},
		{name: "draft04 exclusive maximum ok", schema: `{"maximum":3,"exclusiveMaximum":true}`, instance: `2.999`},
		{name: "draft06 exclusive minimum ok", schema: `{"exclusiveMinimum":0}`, instance: `0.1`},
		{name: "draft06 exclusive minimum wrong", schema: `{"exclusiveMinimum":0}`, instance: `0`, want: []string{"exclusiveMinimum: 0 is not greater than 0"}},
		{name: "draft06 exclusive maximum ok", schema: `{"exclusiveMaximum":10}`, instance: `9`},
		{name: "draft06 exclusive maximum wrong", schema: `{"exclusiveMaximum":10}`, instance: `10`, want: []string{"exclusiveMaximum: 10 is not less than 10"}},
		{name: "bounds ignore strings", schema: `{"minimum":1,"maximum":2}`, instance: `"5"`},
		{name: "negative and large", schema: `{"minimum":-1e21}`, instance: `-2e21`, want: []string{"minimum: -2e+21 is less than -1e+21"}},
	})
}

func TestStrings(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "minLength ok", schema: `{"minLength":3}`, instance: `"abc"`},
		{name: "minLength wrong", schema: `{"minLength":3}`, instance: `"ab"`, want: []string{"#: minLength: string has 2 characters, want at least 3"}},
		{name: "minLength counts code points", schema: `{"minLength":3}`, instance: `"\u00e9\u00e9\u00e9"`},
		{name: "maxLength ok", schema: `{"maxLength":2}`, instance: `"\u00e9\u00e9"`},
		{name: "maxLength wrong", schema: `{"maxLength":2}`, instance: `"abc"`, want: []string{"maxLength: string has 3 characters, want at most 2"}},
		{name: "length ignores numbers", schema: `{"minLength":10}`, instance: `1`},
		{name: "pattern ok", schema: `{"pattern":"^[0-9]+(\\.[0-9]+){2}$"}`, instance: `"1.2.3"`},
		{name: "pattern unanchored", schema: `{"pattern":"[0-9]+"}`, instance: `"v1"`},
		{name: "pattern wrong", schema: `{"pattern":"^[0-9]+$"}`, instance: `"abc"`, want: []string{`#: pattern: "abc" does not match ^[0-9]+$`}},
		{name: "pattern ignores non strings", schema: `{"pattern":"^[0-9]+$"}`, instance: `true`},
	})
}

func TestFormat(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "date ok", schema: `{"format":"date"}`, instance: `"2026-09-09"`},
		{name: "date wrong shape", schema: `{"format":"date"}`, instance: `"2026-9-9"`, want: []string{`#: format: "2026-9-9" is not a valid date`}},
		{name: "date wrong month", schema: `{"format":"date"}`, instance: `"2026-13-01"`, want: []string{"is not a valid date"}},
		{name: "date-time ok utc", schema: `{"format":"date-time"}`, instance: `"2026-09-09T10:00:00Z"`},
		{name: "date-time ok fraction offset", schema: `{"format":"date-time"}`, instance: `"2026-09-09T10:00:00.123+02:00"`},
		{name: "date-time ok lowercase", schema: `{"format":"date-time"}`, instance: `"2026-09-09t10:00:00z"`},
		{name: "date-time wrong space", schema: `{"format":"date-time"}`, instance: `"2026-09-09 10:00:00"`, want: []string{"is not a valid date-time"}},
		{name: "date-time wrong text", schema: `{"format":"date-time"}`, instance: `"yesterday"`, want: []string{"is not a valid date-time"}},
		{name: "uri ok https", schema: `{"format":"uri"}`, instance: `"https://example.com/x?y=1#z"`},
		{name: "uri ok urn", schema: `{"format":"uri"}`, instance: `"urn:isbn:0451450523"`},
		{name: "uri wrong relative", schema: `{"format":"uri"}`, instance: `"/relative/path"`, want: []string{`"/relative/path" is not a valid uri`}},
		{name: "uri wrong text", schema: `{"format":"uri"}`, instance: `"not a uri"`, want: []string{"is not a valid uri"}},
		{name: "uri-reference ok relative", schema: `{"format":"uri-reference"}`, instance: `"/relative/path"`},
		{name: "uri-reference ok fragment", schema: `{"format":"uri-reference"}`, instance: `"#fragment"`},
		{name: "uri-reference ok empty", schema: `{"format":"uri-reference"}`, instance: `""`},
		{name: "uri-reference wrong host", schema: `{"format":"uri-reference"}`, instance: `"http://[bad"`, want: []string{"is not a valid uri-reference"}},
		{name: "uri-reference wrong escape", schema: `{"format":"uri-reference"}`, instance: `"%zz"`, want: []string{"is not a valid uri-reference"}},
		{name: "unknown format accepted", schema: `{"format":"email"}`, instance: `"not-an-email"`},
		{name: "format ignores non strings", schema: `{"format":"date"}`, instance: `20260909`},
	})
}

func TestCombinators(t *testing.T) {
	policy := `{
		"type": "object",
		"properties": {
			"checks": {
				"type": "object",
				"additionalProperties": {
					"oneOf": [
						{"type": "string", "enum": ["off", "info", "warn", "block"]},
						{
							"type": "object",
							"required": ["level"],
							"properties": {
								"level": {"enum": ["off", "info", "warn", "block"]},
								"min_severity": {"type": "string"}
							},
							"additionalProperties": false
						}
					]
				}
			}
		}
	}`
	runCases(t, []keywordCase{
		{name: "policy oneOf string", schema: policy, instance: `{"checks":{"young-version":"warn"}}`},
		{name: "policy oneOf object", schema: policy, instance: `{"checks":{"vulnerability":{"level":"block","min_severity":"high"}}}`},
		{name: "policy oneOf bad string", schema: policy, instance: `{"checks":{"young-version":"loud"}}`,
			want: []string{"#/checks/young-version: oneOf: value matches none of 2 alternatives", "[0] #/checks/young-version: enum:", "[1] #/checks/young-version: type: want object, got string"}},
		{name: "policy oneOf bad object", schema: policy, instance: `{"checks":{"vulnerability":{"level":"blocc"}}}`,
			want: []string{"#/checks/vulnerability: oneOf: value matches none of 2 alternatives", "[1] #/checks/vulnerability/level: enum:"}},
		{name: "oneOf ambiguous", schema: `{"oneOf":[{"type":"number"},{"minimum":0}]}`, instance: `5`,
			want: []string{"#: oneOf: value matches 2 alternatives (0 and 1), want exactly one"}},
		{name: "oneOf exactly one", schema: `{"oneOf":[{"type":"number"},{"minimum":0}]}`, instance: `"text"`},
		{name: "anyOf ok first", schema: `{"anyOf":[{"required":["startLine"]},{"required":["charOffset"]}]}`, instance: `{"startLine":1}`},
		{name: "anyOf ok both", schema: `{"anyOf":[{"required":["startLine"]},{"required":["charOffset"]}]}`, instance: `{"startLine":1,"charOffset":2}`},
		{name: "anyOf none", schema: `{"anyOf":[{"required":["startLine"]},{"required":["charOffset"]}]}`, instance: `{}`,
			want: []string{"#: anyOf: value matches none of 2 alternatives", `[0] #: required: missing property "startLine"`, `[1] #: required: missing property "charOffset"`}},
		{name: "allOf ok", schema: `{"allOf":[{"type":"string"},{"minLength":2}]}`, instance: `"ab"`},
		{name: "allOf reports every branch", schema: `{"allOf":[{"type":"string"},{"minLength":2}]}`, instance: `"a"`,
			want: []string{"#: minLength: string has 1 character, want at least 2"}},
		{name: "allOf propagates pointer", schema: `{"allOf":[{"properties":{"a":{"type":"string"}}},{"required":["b"]}]}`, instance: `{"a":1}`,
			want: []string{"#/a: type: want string, got number", `#: required: missing property "b"`}},
		{name: "not ok", schema: `{"not":{"type":"string"}}`, instance: `1`},
		{name: "not wrong", schema: `{"not":{"type":"string"}}`, instance: `"x"`, want: []string{"#: not: value matches the schema it must not match"}},
		{name: "boolean true schema", schema: `{"properties":{"a":true}}`, instance: `{"a":[1]}`},
		{name: "boolean false schema", schema: `{"properties":{"a":false}}`, instance: `{"a":1}`, want: []string{"#/a: false: no value is allowed here"}},
	})
}

func TestRef(t *testing.T) {
	runCases(t, []keywordCase{
		{name: "definitions ok", schema: `{"definitions":{"lvl":{"enum":["a","b"]}},"properties":{"x":{"$ref":"#/definitions/lvl"}}}`, instance: `{"x":"a"}`},
		{name: "definitions wrong", schema: `{"definitions":{"lvl":{"enum":["a","b"]}},"properties":{"x":{"$ref":"#/definitions/lvl"}}}`, instance: `{"x":"c"}`,
			want: []string{`#/x: enum: value "c" is not one of ["a","b"]`}},
		{name: "defs ok", schema: `{"$defs":{"lvl":{"enum":["a","b"]}},"properties":{"x":{"$ref":"#/$defs/lvl"}}}`, instance: `{"x":"b"}`},
		{name: "defs wrong", schema: `{"$defs":{"lvl":{"enum":["a","b"]}},"properties":{"x":{"$ref":"#/$defs/lvl"}}}`, instance: `{"x":1}`, want: []string{"#/x: enum:"}},
		{name: "root recursion ok", schema: `{"type":"object","properties":{"child":{"$ref":"#"}},"additionalProperties":false}`, instance: `{"child":{"child":{"child":{}}}}`},
		{name: "root recursion wrong deep", schema: `{"type":"object","properties":{"child":{"$ref":"#"}},"additionalProperties":false}`, instance: `{"child":{"child":{"leaf":1}}}`,
			want: []string{`#/child/child/leaf: additionalProperties: property "leaf" is not allowed`}},
		{name: "definition self recursion via items", schema: `{"definitions":{"node":{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"children":{"type":"array","items":{"$ref":"#/definitions/node"}}},"additionalProperties":false}},"$ref":"#/definitions/node"}`,
			instance: `{"id":"a","children":[{"id":"b","children":[{"id":"c"}]}]}`},
		{name: "definition self recursion wrong", schema: `{"definitions":{"node":{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"children":{"type":"array","items":{"$ref":"#/definitions/node"}}},"additionalProperties":false}},"$ref":"#/definitions/node"}`,
			instance: `{"id":"a","children":[{"id":"b","children":[{}]}]}`, want: []string{`#/children/0/children/0: required: missing property "id"`}},
		{name: "ref chain through definitions", schema: `{"definitions":{"a":{"$ref":"#/definitions/b"},"b":{"type":"integer"}},"$ref":"#/definitions/a"}`, instance: `1.5`,
			want: []string{"#: type: want integer, got number"}},
		{name: "ref siblings apply", schema: `{"definitions":{"s":{"type":"string"}},"$ref":"#/definitions/s","minLength":2}`, instance: `"a"`,
			want: []string{"minLength: string has 1 character, want at least 2"}},
		{name: "escaped pointer segments", schema: `{"definitions":{"a/b":{"type":"string"},"c~d":{"type":"integer"}},"properties":{"x":{"$ref":"#/definitions/a~1b"},"y":{"$ref":"#/definitions/c~0d"}}}`,
			instance: `{"x":1,"y":"s"}`, want: []string{"#/x: type: want string, got number", "#/y: type: want integer, got string"}},
		{name: "percent encoded pointer", schema: `{"definitions":{"a b":{"type":"string"}},"properties":{"x":{"$ref":"#/definitions/a%20b"}}}`, instance: `{"x":1}`,
			want: []string{"#/x: type: want string, got number"}},
	})
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		want   string
	}{
		{name: "invalid json", schema: `{"type":`, want: "decode schema"},
		{name: "root array", schema: `[]`, want: "schema must be a JSON object"},
		{name: "root string", schema: `"string"`, want: "schema must be a JSON object"},
		{name: "remote ref http", schema: `{"$ref":"https://example.com/schema.json#/definitions/x"}`, want: `#: $ref "https://example.com/schema.json#/definitions/x": only references into the same document are supported`},
		{name: "remote ref file", schema: `{"properties":{"a":{"$ref":"other.json"}}}`, want: `#/properties/a: $ref "other.json": only references`},
		{name: "unresolvable ref", schema: `{"$ref":"#/definitions/missing"}`, want: `$ref "#/definitions/missing": no such location in the schema`},
		{name: "unresolvable ref in unreferenced definition", schema: `{"definitions":{"a":{"$ref":"#/definitions/missing"}}}`, want: `#/definitions/a: $ref "#/definitions/missing": no such location`},
		{name: "ref not string", schema: `{"$ref":5}`, want: "$ref must be a string"},
		{name: "cycle root", schema: `{"$ref":"#"}`, want: `cyclic $ref "#"`},
		{name: "cycle through allOf", schema: `{"allOf":[{"$ref":"#"}]}`, want: "cyclic $ref"},
		{name: "cycle through definitions", schema: `{"definitions":{"a":{"$ref":"#/definitions/b"},"b":{"anyOf":[{"$ref":"#/definitions/a"}]}},"$ref":"#/definitions/a"}`, want: "cyclic $ref"},
		{name: "cycle through not", schema: `{"definitions":{"a":{"not":{"$ref":"#/definitions/a"}}}}`, want: "cyclic $ref"},
		// Keys compile in sorted order, so "items" reaches definitions/c first and caches it
		// with a fresh chain; the "not" that closes the loop then finds the cached node.
		{name: "cycle hidden by cache via items", schema: `{"items":{"$ref":"#/definitions/c"},"not":{"$ref":"#/definitions/c"},"definitions":{"c":{"not":{"$ref":"#"}}}}`, want: "cyclic $ref"},
		{name: "cycle hidden by cache via definitions", schema: `{"definitions":{"b":{"items":{"$ref":"#/definitions/c"},"oneOf":[{"$ref":"#/definitions/c"}]},"c":{"oneOf":[{"$ref":"#/definitions/b"}]}},"properties":{"x":{"$ref":"#/definitions/b"}}}`, want: "cyclic $ref"},
		{name: "cycle hidden by cache via additionalProperties", schema: `{"additionalProperties":{"$ref":"#/definitions/c"},"anyOf":[{"$ref":"#/definitions/c"}],"definitions":{"c":{"allOf":[{"$ref":"#"}]}}}`, want: "cyclic $ref"},
		{name: "type unknown name", schema: `{"type":"strin"}`, want: `#: type: unknown type "strin"`},
		{name: "type number", schema: `{"type":5}`, want: "type must be a string or an array of strings"},
		{name: "type list unknown", schema: `{"type":["string","thing"]}`, want: `unknown type "thing"`},
		{name: "enum not array", schema: `{"enum":"x"}`, want: "enum must be a non-empty array"},
		{name: "enum empty", schema: `{"enum":[]}`, want: "enum must be a non-empty array"},
		{name: "required not array", schema: `{"required":"a"}`, want: "required must be an array of strings"},
		{name: "required not strings", schema: `{"required":[1]}`, want: "required must be an array of strings"},
		{name: "properties not object", schema: `{"properties":[]}`, want: "properties must be an object"},
		{name: "nested bad keyword", schema: `{"properties":{"a":{"minItems":"x"}}}`, want: `#/properties/a: minItems must be a non-negative integer`},
		{name: "minItems negative", schema: `{"minItems":-1}`, want: "minItems must be a non-negative integer"},
		{name: "minItems fraction", schema: `{"minItems":1.5}`, want: "minItems must be a non-negative integer"},
		{name: "maxLength string", schema: `{"maxLength":"3"}`, want: "maxLength must be a non-negative integer"},
		{name: "minimum string", schema: `{"minimum":"1"}`, want: "minimum must be a number"},
		{name: "exclusiveMinimum string", schema: `{"exclusiveMinimum":"1"}`, want: "exclusiveMinimum must be a boolean or a number"},
		{name: "uniqueItems string", schema: `{"uniqueItems":"yes"}`, want: "uniqueItems must be a boolean"},
		{name: "pattern invalid regexp", schema: `{"pattern":"("}`, want: `#: pattern "(": `},
		{name: "pattern lookahead unsupported", schema: `{"pattern":"^(?=a)"}`, want: "pattern"},
		{name: "pattern not string", schema: `{"pattern":1}`, want: "pattern must be a string"},
		{name: "patternProperties bad regexp", schema: `{"patternProperties":{"(":{}}}`, want: `patternProperties "(": `},
		{name: "patternProperties not object", schema: `{"patternProperties":[]}`, want: "patternProperties must be an object"},
		{name: "items array form", schema: `{"items":[{"type":"string"}]}`, want: "items must be a single schema"},
		{name: "additionalProperties string", schema: `{"additionalProperties":"no"}`, want: "additionalProperties must be a boolean or a schema"},
		{name: "oneOf not array", schema: `{"oneOf":{}}`, want: "oneOf must be a non-empty array of schemas"},
		{name: "anyOf empty", schema: `{"anyOf":[]}`, want: "anyOf must be a non-empty array of schemas"},
		{name: "allOf element not schema", schema: `{"allOf":[1]}`, want: "#/allOf/0: schema must be an object or a boolean"},
		{name: "not not schema", schema: `{"not":"x"}`, want: "#/not: schema must be an object or a boolean"},
		{name: "format not string", schema: `{"format":1}`, want: "format must be a string"},
		{name: "const missing is fine but null is a value", schema: `{"const":null,"minItems":"x"}`, want: "minItems"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Compile([]byte(tt.schema))
			if err == nil {
				t.Fatalf("Compile(%s) succeeded (%v), want error containing %q", tt.schema, s, tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Compile(%s) error = %q, want it to contain %q", tt.schema, err, tt.want)
			}
		})
	}
}

func TestUnknownKeywordsIgnored(t *testing.T) {
	schema := `{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"$id": "https://example.com/x.json",
		"id": "legacy",
		"title": "t", "description": "d", "default": 5, "examples": [1], "$comment": "c",
		"type": "string",
		"multipleOf": "junk",
		"x-custom": {"anything": true},
		"dependencies": {"a": ["b"]},
		"properties": {"multipleOf": {"type": "integer", "propertyNames": 1}}
	}`
	s, err := Compile([]byte(schema))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := s.Validate([]byte(`"hi"`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := s.UnsupportedKeywords()
	want := []string{"dependencies", "multipleOf", "propertyNames", "x-custom"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("UnsupportedKeywords() = %q, want %q", got, want)
	}
	clean, err := Compile([]byte(`{"type":"object","properties":{"multipleOf":{"const":1}},"definitions":{"x":{"enum":[1]}}}`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := clean.UnsupportedKeywords(); len(got) != 0 {
		t.Fatalf("UnsupportedKeywords() = %q, want none", got)
	}
}

func TestValidateReportsEveryError(t *testing.T) {
	s, err := Compile([]byte(`{
		"type": "object",
		"required": ["schema", "subjects"],
		"properties": {
			"schema": {"const": "trustdiff.report/1"},
			"subjects": {"type": "array", "items": {"type": "object", "required": ["ref"]}},
			"a/b": {"type": "string"},
			"c~d": {"type": "string"}
		},
		"additionalProperties": false
	}`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	err = s.Validate([]byte(`{"schema":"trustdiff.report/2","subjects":[{"ref":"x"},{}],"extra":1,"a/b":1,"c~d":2}`))
	if err == nil {
		t.Fatal("want errors, got nil")
	}
	leaves := flatten(err)
	if len(leaves) != 5 {
		t.Fatalf("got %d errors, want 5:\n%v", len(leaves), err)
	}
	requireError(t, err, "/schema", "const")
	requireError(t, err, "/subjects/1", "required")
	requireError(t, err, "/extra", "additionalProperties")
	requireError(t, err, "/a~1b", "type")
	requireError(t, err, "/c~0d", "type")

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("errors.As failed to find a *ValidationError in %T", err)
	}
	if !strings.Contains(err.Error(), "#/a~1b: type: want string, got number") {
		t.Fatalf("escaped pointer missing from:\n%v", err)
	}
}

func TestValidateInputs(t *testing.T) {
	s, err := Compile([]byte(`{"type":"object","properties":{"n":{"type":"integer"}}}`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := s.Validate([]byte(`{"n":`)); err == nil || !strings.Contains(err.Error(), "decode instance") {
		t.Fatalf("Validate(invalid json) = %v, want decode error", err)
	}
	if err := s.ValidateValue(map[string]any{"n": 3.0}); err != nil {
		t.Fatalf("ValidateValue(float64 3.0): %v", err)
	}
	if err := s.ValidateValue(map[string]any{"n": 3}); err != nil {
		t.Fatalf("ValidateValue(int 3): %v", err)
	}
	if err := s.ValidateValue(map[string]any{"n": json.Number("3")}); err != nil {
		t.Fatalf("ValidateValue(json.Number 3): %v", err)
	}
	if err := s.ValidateValue(map[string]any{"n": json.Number("3.5")}); err == nil {
		t.Fatal("ValidateValue(json.Number 3.5) = nil, want type error")
	}
	if err := s.ValidateValue(map[string]any{"n": 3.5}); err == nil {
		t.Fatal("ValidateValue(float64 3.5) = nil, want type error")
	}
	err = s.ValidateValue(map[string]any{"n": struct{}{}})
	if err == nil || !strings.Contains(err.Error(), "#/n: type: unsupported Go value of type struct {}") {
		t.Fatalf("ValidateValue(struct) = %v, want unsupported type error", err)
	}
	var decoded any
	dec := json.NewDecoder(strings.NewReader(`{"n": 12345678901234567890}`))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateValue(decoded); err != nil {
		t.Fatalf("ValidateValue(UseNumber): %v", err)
	}
}

// uniqueItems compares items through a canonical encoding, so every numeric
// representation a decoded document can carry must collapse to the same key.
func TestUniqueItemsNormalizesNumbers(t *testing.T) {
	s, err := Compile([]byte(`{"uniqueItems":true}`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tests := []struct {
		name string
		arr  []any
		want string
	}{
		{name: "json.Number vs float", arr: []any{json.Number("1"), 1.0}, want: "items 0 and 1 are equal"},
		{name: "json.Number vs int", arr: []any{map[string]any{"n": json.Number("2")}, map[string]any{"n": 2}}, want: "items 0 and 1 are equal"},
		{name: "json.Number float vs float", arr: []any{[]any{json.Number("2.50")}, []any{2.5}}, want: "items 0 and 1 are equal"},
		{name: "json.Number distinct", arr: []any{json.Number("1"), json.Number("2")}},
		{name: "number vs string", arr: []any{json.Number("1"), "1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var want []string
			if tt.want != "" {
				want = []string{tt.want}
			}
			assertErrors(t, s.ValidateValue(tt.arr), want)
		})
	}
}

// A uniqueItems array of many distinct objects, the shape of a SARIF rule list.
func BenchmarkUniqueItemsObjects(b *testing.B) {
	s, err := Compile([]byte(`{"uniqueItems":true,"items":{"type":"object","required":["id"]}}`))
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}
	arr := make([]any, 20000)
	for i := range arr {
		arr[i] = map[string]any{"id": strconv.Itoa(i), "guid": strings.Repeat("x", 36)}
	}
	for b.Loop() {
		if err := s.ValidateValue(arr); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSARIFSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "report", "testdata", "sarif-schema-2.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Compile(raw)
	if err != nil {
		t.Fatalf("Compile(sarif): %v", err)
	}
	if got := s.UnsupportedKeywords(); len(got) != 0 {
		t.Fatalf("SARIF schema uses keywords outside the subset: %q", got)
	}

	const minimal = `{
		"version": "2.1.0",
		"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		"runs": [{"tool": {"driver": {"name": "trustdiff"}}, "results": []}]
	}`
	if err := s.Validate([]byte(minimal)); err != nil {
		t.Fatalf("minimal SARIF log rejected:\n%v", err)
	}

	const withResult = `{
		"version": "2.1.0",
		"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		"runs": [{
			"tool": {"driver": {"name": "trustdiff", "version": "0.0.1", "informationUri": "https://github.com/vahapogut/trustdiff",
				"rules": [{"id": "TD001", "shortDescription": {"text": "young version"}, "helpUri": "https://github.com/vahapogut/trustdiff/blob/main/docs/checks.md#td001"}]}},
			"results": [{
				"ruleId": "TD001", "ruleIndex": 0, "level": "warning",
				"message": {"text": "express@4.19.2 was published 2 days ago"},
				"locations": [{"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}, "region": {"startLine": 42}}}]
			}]
		}]
	}`
	if err := s.Validate([]byte(withResult)); err != nil {
		t.Fatalf("SARIF log with one result rejected:\n%v", err)
	}

	badLevel := replaceOnce(t, withResult, `"level": "warning"`, `"level": "fatal"`)
	err = s.Validate([]byte(badLevel))
	requireOnlyError(t, err, "/runs/0/results/0/level", "enum")
	ve := lookupError(err, "/runs/0/results/0/level", "enum")
	if !strings.Contains(ve.Message, `"fatal"`) {
		t.Fatalf("enum message = %q, want it to name the value", ve.Message)
	}

	noRuns := `{"version": "2.1.0"}`
	err = s.Validate([]byte(noRuns))
	if err == nil {
		t.Fatal("log without runs accepted")
	}
	requireError(t, err, "", "required")
	ve = lookupError(err, "", "required")
	if ve.Message != `missing property "runs"` {
		t.Fatalf("required message = %q", ve.Message)
	}

	unknownRunProperty := replaceOnce(t, minimal, `"results": []`, `"results": [], "verdict": "ok"`)
	err = s.Validate([]byte(unknownRunProperty))
	requireError(t, err, "/runs/0/verdict", "additionalProperties")

	missingMessage := replaceOnce(t, withResult, `"message": {"text": "express@4.19.2 was published 2 days ago"},`, "")
	err = s.Validate([]byte(missingMessage))
	requireError(t, err, "/runs/0/results/0", "required")

	badRegion := replaceOnce(t, withResult, `"region": {"startLine": 42}`, `"region": {"startLine": 0}`)
	err = s.Validate([]byte(badRegion))
	requireError(t, err, "/runs/0/results/0/locations/0/physicalLocation/region/startLine", "minimum")

	// The structures trustdiff emits lean on these SARIF keywords, so each one is
	// driven through the compiled schema: anyOf over required lists for region,
	// physicalLocation and message, maximum for rank, pattern for guid, format uri
	// for informationUri and uniqueItems for the rule list.
	noAnchor := replaceOnce(t, withResult, `"region": {"startLine": 42}`, `"region": {"endLine": 42}`)
	requireOnlyError(t, s.Validate([]byte(noAnchor)), "/runs/0/results/0/locations/0/physicalLocation/region", "anyOf")

	noArtifact := replaceOnce(t, withResult, `"artifactLocation": {"uri": "package-lock.json"}, `, "")
	requireOnlyError(t, s.Validate([]byte(noArtifact)), "/runs/0/results/0/locations/0/physicalLocation", "anyOf")

	emptyMessage := replaceOnce(t, withResult, `"message": {"text": "express@4.19.2 was published 2 days ago"}`, `"message": {}`)
	requireOnlyError(t, s.Validate([]byte(emptyMessage)), "/runs/0/results/0/message", "anyOf")

	badRank := replaceOnce(t, withResult, `"level": "warning",`, `"level": "warning", "rank": 101,`)
	requireOnlyError(t, s.Validate([]byte(badRank)), "/runs/0/results/0/rank", "maximum")

	badGUID := replaceOnce(t, minimal, `"driver": {"name": "trustdiff"}`, `"driver": {"name": "trustdiff", "guid": "nope"}`)
	requireOnlyError(t, s.Validate([]byte(badGUID)), "/runs/0/tool/driver/guid", "pattern")

	badURI := replaceOnce(t, minimal, `"driver": {"name": "trustdiff"}`, `"driver": {"name": "trustdiff", "informationUri": "not a uri"}`)
	requireOnlyError(t, s.Validate([]byte(badURI)), "/runs/0/tool/driver/informationUri", "format")

	duplicateRules := replaceOnce(t, minimal, `"driver": {"name": "trustdiff"}`, `"driver": {"name": "trustdiff", "rules": [{"id": "TD001"}, {"id": "TD001"}]}`)
	requireOnlyError(t, s.Validate([]byte(duplicateRules)), "/runs/0/tool/driver/rules", "uniqueItems")
}
