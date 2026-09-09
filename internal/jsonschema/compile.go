package jsonschema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// node is one compiled schema. Zero values mean "keyword absent"; the int limits use
// -1 for absent because 0 is a valid limit.
type node struct {
	// Boolean schemas ("true" and "false") have no keywords.
	isBool    bool
	boolValue bool

	ref *node

	types    []string
	enum     []any
	hasEnum  bool
	constant any
	hasConst bool

	required          []string
	properties        map[string]*node
	patternProperties []patternProperty
	additionalAllowed bool
	additional        *node

	items       *node
	minItems    int
	maxItems    int
	uniqueItems bool

	minimum          *float64
	maximum          *float64
	minimumExclusive bool // draft-04 form: exclusiveMinimum: true
	maximumExclusive bool // draft-04 form: exclusiveMaximum: true
	exclusiveMinimum *float64
	exclusiveMaximum *float64

	minLength     int
	maxLength     int
	pattern       *regexp.Regexp
	patternSource string
	format        string

	oneOf []*node
	anyOf []*node
	allOf []*node
	not   *node
}

type patternProperty struct {
	source string
	re     *regexp.Regexp
	schema *node
}

func newNode() *node {
	return &node{additionalAllowed: true, minItems: -1, maxItems: -1, minLength: -1, maxLength: -1}
}

// Keywords that carry no validation semantics. Everything else that is not compiled
// below is reported by UnsupportedKeywords.
var annotationKeywords = map[string]bool{
	"$schema":     true,
	"$id":         true,
	"id":          true,
	"$comment":    true,
	"title":       true,
	"description": true,
	"default":     true,
	"examples":    true,
	"definitions": true,
	"$defs":       true,
}

var typeNames = map[string]bool{
	"string":  true,
	"number":  true,
	"integer": true,
	"boolean": true,
	"object":  true,
	"array":   true,
	"null":    true,
}

// compiler turns the decoded schema document into nodes. Nodes are cached by their
// JSON pointer inside the document so that every $ref to the same location shares
// one node, which is what makes recursive definitions work.
type compiler struct {
	doc         map[string]any
	nodes       map[string]*node
	unsupported map[string]bool
}

func newCompiler(schema []byte) (*compiler, error) {
	var raw any
	if err := json.Unmarshal(schema, &raw); err != nil {
		return nil, fmt.Errorf("decode schema: %w", err)
	}
	doc, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("schema must be a JSON object")
	}
	return &compiler{doc: doc, nodes: map[string]*node{}, unsupported: map[string]bool{}}, nil
}

// compileRoot compiles the document root and then every definition, so that a broken
// or cyclic definition is reported even when nothing references it.
func (c *compiler) compileRoot() (*node, error) {
	root, err := c.compile(c.doc, "", []string{""})
	if err != nil {
		return nil, err
	}
	for _, container := range []string{"definitions", "$defs"} {
		raw, present := c.doc[container]
		if !present {
			continue
		}
		defs, ok := raw.(map[string]any)
		if !ok {
			return nil, &schemaError{pointer: "", err: fmt.Errorf("%s must be an object", container)}
		}
		for _, name := range sortedKeys(defs) {
			pointer := "/" + container + "/" + escapePointer(name)
			if _, err := c.compile(defs[name], pointer, []string{pointer}); err != nil {
				return nil, err
			}
		}
	}
	if err := c.checkCycles(); err != nil {
		return nil, err
	}
	return root, nil
}

// checkCycles walks the compiled graph along the edges that do not consume input
// ($ref, allOf, anyOf, oneOf, not) and reports a loop among them. The chain check in
// compileRef misses a back edge whenever its target was already cached, which
// happens when a consuming keyword (items, additionalProperties) sorts before the
// combinator that closes the loop: the target is first compiled with a fresh chain,
// and the later $ref returns the cached node without a check. Such a loop would
// recurse forever on any instance, so it is a compile error whichever path found it.
func (c *compiler) checkCycles() error {
	pointerOf := make(map[*node]string, len(c.nodes))
	for pointer, n := range c.nodes {
		pointerOf[n] = pointer
	}
	// The zero value of state is "not visited yet".
	const (
		visiting = iota + 1
		done
	)
	state := make(map[*node]int, len(c.nodes))
	var visit func(n *node) error
	visit = func(n *node) error {
		switch state[n] {
		case visiting:
			return &schemaError{pointer: pointerOf[n], err: errors.New("cyclic $ref: the reference loops back without consuming input")}
		case done:
			return nil
		}
		state[n] = visiting
		next := make([]*node, 0, 2+len(n.allOf)+len(n.anyOf)+len(n.oneOf))
		if n.ref != nil {
			next = append(next, n.ref)
		}
		next = append(next, n.allOf...)
		next = append(next, n.anyOf...)
		next = append(next, n.oneOf...)
		if n.not != nil {
			next = append(next, n.not)
		}
		for _, m := range next {
			if err := visit(m); err != nil {
				return err
			}
		}
		state[n] = done
		return nil
	}
	for _, pointer := range sortedKeys(c.nodes) {
		if err := visit(c.nodes[pointer]); err != nil {
			return err
		}
	}
	return nil
}

func (c *compiler) unsupportedKeywords() []string {
	return sortedKeys(c.unsupported)
}

// compile returns the node for the schema at pointer, compiling it on first use.
//
// active lists the pointers of the schemas on the current chain of keywords that do
// not consume input ($ref, allOf, anyOf, oneOf, not). A $ref back into that chain
// would recurse forever on any instance, so it is rejected. Keywords that descend
// into the instance (properties, patternProperties, additionalProperties, items)
// start a fresh chain. The chain only sees the first path that reached a node;
// checkCycles catches a loop closed through a node that was already cached.
func (c *compiler) compile(raw any, pointer string, active []string) (*node, error) {
	if n, ok := c.nodes[pointer]; ok {
		return n, nil
	}
	n := newNode()
	c.nodes[pointer] = n
	switch s := raw.(type) {
	case bool:
		n.isBool = true
		n.boolValue = s
		return n, nil
	case map[string]any:
		if err := c.fill(n, s, pointer, active); err != nil {
			return nil, err
		}
		return n, nil
	default:
		return nil, &schemaError{pointer: pointer, err: errors.New("schema must be an object or a boolean")}
	}
}

// fill compiles the keywords of one schema object into n. Keys are visited in sorted
// order so that the first error reported for a bad schema is deterministic.
func (c *compiler) fill(n *node, obj map[string]any, pointer string, active []string) error {
	for _, key := range sortedKeys(obj) {
		raw := obj[key]
		var err error
		switch key {
		case "$ref":
			err = c.compileRef(n, raw, active)
		case "type":
			err = compileType(n, raw)
		case "enum":
			values, ok := raw.([]any)
			if !ok || len(values) == 0 {
				err = errors.New("enum must be a non-empty array")
				break
			}
			n.enum, n.hasEnum = values, true
		case "const":
			n.constant, n.hasConst = raw, true
		case "required":
			n.required, err = stringList(raw)
			if err != nil {
				err = errors.New("required must be an array of strings")
			}
		case "properties":
			err = c.compileProperties(n, raw, pointer)
		case "patternProperties":
			err = c.compilePatternProperties(n, raw, pointer)
		case "additionalProperties":
			err = c.compileAdditionalProperties(n, raw, pointer)
		case "items":
			if _, isList := raw.([]any); isList {
				err = errors.New("items must be a single schema")
				break
			}
			n.items, err = c.compileChild(raw, pointer+"/items", nil)
		case "minItems":
			n.minItems, err = nonNegativeInt(key, raw)
		case "maxItems":
			n.maxItems, err = nonNegativeInt(key, raw)
		case "uniqueItems":
			unique, ok := raw.(bool)
			if !ok {
				err = errors.New("uniqueItems must be a boolean")
				break
			}
			n.uniqueItems = unique
		case "minimum":
			n.minimum, err = number(key, raw)
		case "maximum":
			n.maximum, err = number(key, raw)
		case "exclusiveMinimum":
			n.minimumExclusive, n.exclusiveMinimum, err = exclusiveBound(key, raw)
		case "exclusiveMaximum":
			n.maximumExclusive, n.exclusiveMaximum, err = exclusiveBound(key, raw)
		case "minLength":
			n.minLength, err = nonNegativeInt(key, raw)
		case "maxLength":
			n.maxLength, err = nonNegativeInt(key, raw)
		case "pattern":
			source, ok := raw.(string)
			if !ok {
				err = errors.New("pattern must be a string")
				break
			}
			n.pattern, err = regexp.Compile(source)
			if err != nil {
				err = fmt.Errorf("pattern %q: %w", source, err)
				break
			}
			n.patternSource = source
		case "format":
			format, ok := raw.(string)
			if !ok {
				err = errors.New("format must be a string")
				break
			}
			n.format = format
		case "oneOf":
			n.oneOf, err = c.compileList(key, raw, pointer, active)
		case "anyOf":
			n.anyOf, err = c.compileList(key, raw, pointer, active)
		case "allOf":
			n.allOf, err = c.compileList(key, raw, pointer, active)
		case "not":
			n.not, err = c.compileChild(raw, pointer+"/not", active)
		default:
			if !annotationKeywords[key] {
				c.unsupported[key] = true
			}
		}
		if err != nil {
			return locate(pointer, err)
		}
	}
	return nil
}

// compileChild compiles a sub-schema at childPointer, extending the non-consuming
// chain with the child's own location so that a $ref back to it is caught.
func (c *compiler) compileChild(raw any, childPointer string, active []string) (*node, error) {
	return c.compile(raw, childPointer, append(slices.Clone(active), childPointer))
}

// schemaError is a compile error that names the schema location it was found at.
// Every error that leaves compile carries one, so fill wraps an error exactly once.
type schemaError struct {
	pointer string
	err     error
}

func (e *schemaError) Error() string { return "#" + e.pointer + ": " + e.err.Error() }
func (e *schemaError) Unwrap() error { return e.err }

func locate(pointer string, err error) error {
	var located *schemaError
	if errors.As(err, &located) {
		return err
	}
	return &schemaError{pointer: pointer, err: err}
}

func (c *compiler) compileRef(n *node, raw any, active []string) error {
	ref, ok := raw.(string)
	if !ok {
		return errors.New("$ref must be a string")
	}
	target, err := refTarget(ref)
	if err != nil {
		return err
	}
	if slices.Contains(active, target) {
		return fmt.Errorf("cyclic $ref %q: the reference loops back without consuming input", ref)
	}
	rawTarget, found := resolvePointer(c.doc, target)
	if !found {
		return fmt.Errorf("$ref %q: no such location in the schema", ref)
	}
	n.ref, err = c.compileChild(rawTarget, target, active)
	return err
}

// refTarget turns a $ref value into a JSON pointer inside the current document.
func refTarget(ref string) (string, error) {
	if !strings.HasPrefix(ref, "#") {
		return "", fmt.Errorf("$ref %q: only references into the same document are supported", ref)
	}
	fragment, err := url.PathUnescape(ref[1:])
	if err != nil {
		return "", fmt.Errorf("$ref %q: %w", ref, err)
	}
	if fragment != "" && !strings.HasPrefix(fragment, "/") {
		return "", fmt.Errorf("$ref %q: the fragment must be a JSON pointer", ref)
	}
	return fragment, nil
}

// compileProperties, compilePatternProperties and compileAdditionalProperties pass a
// nil chain to compileChild: these keywords descend into the instance, so a $ref from
// inside them back to an ancestor is ordinary recursion, not a loop.
func (c *compiler) compileProperties(n *node, raw any, pointer string) error {
	props, ok := raw.(map[string]any)
	if !ok {
		return errors.New("properties must be an object")
	}
	n.properties = make(map[string]*node, len(props))
	for _, name := range sortedKeys(props) {
		child, err := c.compileChild(props[name], pointer+"/properties/"+escapePointer(name), nil)
		if err != nil {
			return err
		}
		n.properties[name] = child
	}
	return nil
}

func (c *compiler) compilePatternProperties(n *node, raw any, pointer string) error {
	props, ok := raw.(map[string]any)
	if !ok {
		return errors.New("patternProperties must be an object")
	}
	n.patternProperties = make([]patternProperty, 0, len(props))
	for _, source := range sortedKeys(props) {
		re, err := regexp.Compile(source)
		if err != nil {
			return fmt.Errorf("patternProperties %q: %w", source, err)
		}
		child, err := c.compileChild(props[source], pointer+"/patternProperties/"+escapePointer(source), nil)
		if err != nil {
			return err
		}
		n.patternProperties = append(n.patternProperties, patternProperty{source: source, re: re, schema: child})
	}
	return nil
}

func (c *compiler) compileAdditionalProperties(n *node, raw any, pointer string) error {
	switch v := raw.(type) {
	case bool:
		n.additionalAllowed = v
		return nil
	case map[string]any:
		child, err := c.compileChild(v, pointer+"/additionalProperties", nil)
		if err != nil {
			return err
		}
		n.additional = child
		return nil
	default:
		return errors.New("additionalProperties must be a boolean or a schema")
	}
}

func (c *compiler) compileList(keyword string, raw any, pointer string, active []string) ([]*node, error) {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty array of schemas", keyword)
	}
	out := make([]*node, 0, len(items))
	for i, item := range items {
		child, err := c.compileChild(item, fmt.Sprintf("%s/%s/%d", pointer, keyword, i), active)
		if err != nil {
			return nil, err
		}
		out = append(out, child)
	}
	return out, nil
}

func compileType(n *node, raw any) error {
	var names []string
	switch v := raw.(type) {
	case string:
		names = []string{v}
	case []any:
		var err error
		names, err = stringList(v)
		if err != nil {
			return errors.New("type must be a string or an array of strings")
		}
	default:
		return errors.New("type must be a string or an array of strings")
	}
	for _, name := range names {
		if !typeNames[name] {
			return fmt.Errorf("type: unknown type %q", name)
		}
	}
	n.types = names
	return nil
}

func stringList(raw any) ([]string, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, errors.New("not an array")
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("not an array of strings")
		}
		out = append(out, s)
	}
	return out, nil
}

func nonNegativeInt(keyword string, raw any) (int, error) {
	f, ok := raw.(float64)
	if !ok || f < 0 || f != math.Trunc(f) || f > math.MaxInt32 {
		return 0, fmt.Errorf("%s must be a non-negative integer", keyword)
	}
	return int(f), nil
}

func number(keyword string, raw any) (*float64, error) {
	f, ok := raw.(float64)
	if !ok {
		return nil, fmt.Errorf("%s must be a number", keyword)
	}
	return &f, nil
}

// exclusiveBound reads exclusiveMinimum or exclusiveMaximum in either form: a boolean
// (draft-04, modifies minimum or maximum) or a number (draft-06 and later).
func exclusiveBound(keyword string, raw any) (flag bool, bound *float64, err error) {
	switch v := raw.(type) {
	case bool:
		return v, nil, nil
	case float64:
		return false, &v, nil
	default:
		return false, nil, fmt.Errorf("%s must be a boolean or a number", keyword)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
