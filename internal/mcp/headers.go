package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Streamable HTTP mirrors parts of the JSON-RPC body into headers so that
// intermediaries can route without parsing JSON. The rules below are the
// transport spec's, and they are MUSTs for a client: a call that omits a
// header the server expects is rejected with HeaderMismatch, and a tool whose
// annotations are malformed must not be offered at all.

const (
	headerProtocolVersion = "MCP-Protocol-Version"
	headerMethod          = "Mcp-Method"
	headerName            = "Mcp-Name"
	headerParamPrefix     = "Mcp-Param-"
	headerSessionID       = "Mcp-Session-Id"

	base64Prefix = "=?base64?"
	base64Suffix = "?="
)

// headerPath is where in the arguments an annotated parameter lives: the chain
// of property names from the root.
type headerPath []string

// headerAnnotations reads every x-mcp-header annotation out of a tool's input
// schema and validates them against the transport spec. It returns the header
// name (without the Mcp-Param- prefix) mapped to the property path, or an
// error naming the first violation -- in which case the whole tool is invalid.
func headerAnnotations(schema json.RawMessage) (map[string]headerPath, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	var root any
	if err := json.Unmarshal(schema, &root); err != nil {
		return nil, fmt.Errorf("inputSchema is not valid JSON: %w", err)
	}
	found := map[string]headerPath{}
	seen := map[string]string{} // lowercased name -> original, for uniqueness
	if err := walkSchema(root, nil, true, found, seen); err != nil {
		return nil, err
	}
	return found, nil
}

// Keywords whose subschemas are not statically reachable: an annotation under
// any of them invalidates the tool, because a router cannot know from the
// arguments alone which branch applies.
var unreachableKeywords = []string{
	"items", "prefixItems", "additionalProperties", "patternProperties",
	"oneOf", "anyOf", "allOf", "not", "if", "then", "else",
	"$defs", "definitions", "dependentSchemas", "$ref",
}

func walkSchema(node any, path headerPath, reachable bool, found map[string]headerPath, seen map[string]string) error {
	obj, ok := node.(map[string]any)
	if !ok {
		return nil
	}

	if raw, has := obj["x-mcp-header"]; has && len(path) > 0 {
		if !reachable {
			return fmt.Errorf("x-mcp-header on %q is not statically reachable (under an array, composition or $ref)", strings.Join(path, "."))
		}
		name, ok := raw.(string)
		if !ok || name == "" {
			return fmt.Errorf("x-mcp-header on %q must be a non-empty string", strings.Join(path, "."))
		}
		if !isToken(name) {
			return fmt.Errorf("x-mcp-header %q on %q is not a valid header token", name, strings.Join(path, "."))
		}
		typ, _ := obj["type"].(string)
		switch typ {
		case "integer", "string", "boolean":
		default:
			return fmt.Errorf("x-mcp-header %q on %q needs type integer, string or boolean (got %q)", name, strings.Join(path, "."), typ)
		}
		lower := strings.ToLower(name)
		if prev, dup := seen[lower]; dup {
			return fmt.Errorf("x-mcp-header %q duplicates %q (names are case-insensitive)", name, prev)
		}
		seen[lower] = name
		found[name] = append(headerPath(nil), path...)
	}

	if props, ok := obj["properties"].(map[string]any); ok {
		for prop, sub := range props {
			if err := walkSchema(sub, append(append(headerPath(nil), path...), prop), reachable, found, seen); err != nil {
				return err
			}
		}
	}
	for _, kw := range unreachableKeywords {
		sub, ok := obj[kw]
		if !ok {
			continue
		}
		switch v := sub.(type) {
		case []any:
			for _, item := range v {
				if err := walkSchema(item, path, false, found, seen); err != nil {
					return err
				}
			}
		case map[string]any:
			// Both a single subschema (items, not, if) and a map of named
			// subschemas ($defs, patternProperties) end up here; walking the
			// values of the latter is harmless because reachable is false.
			if _, isSchema := v["type"]; isSchema || v["properties"] != nil || v["x-mcp-header"] != nil {
				if err := walkSchema(v, path, false, found, seen); err != nil {
					return err
				}
			} else {
				for _, item := range v {
					if err := walkSchema(item, path, false, found, seen); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// mirrorHeaders produces the Mcp-Param-* headers for one call from its tool's
// schema and the arguments actually sent. A parameter that is absent or null
// yields no header, exactly as the spec says the server must expect.
func mirrorHeaders(schema, arguments json.RawMessage) map[string]string {
	annotated, err := headerAnnotations(schema)
	if err != nil || len(annotated) == 0 || len(arguments) == 0 {
		return nil
	}
	var args map[string]any
	if err := json.Unmarshal(arguments, &args); err != nil {
		return nil
	}
	out := map[string]string{}
	for name, path := range annotated {
		v, ok := lookup(args, path)
		if !ok || v == nil {
			continue
		}
		s, ok := headerString(v)
		if !ok {
			continue
		}
		out[headerParamPrefix+name] = encodeHeaderValue(s)
	}
	return out
}

func lookup(args map[string]any, path headerPath) (any, bool) {
	var cur any = args
	for _, seg := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// headerString renders a primitive the way the spec wants it on the wire.
func headerString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		if t != math.Trunc(t) || math.Abs(t) > (1<<53)-1 {
			return "", false
		}
		return strconv.FormatInt(int64(t), 10), true
	}
	return "", false
}

// encodeHeaderValue applies the spec's Base64 sentinel to anything that is not
// plain, trimmed, visible ASCII -- and to a plain value that merely looks like
// the sentinel, so a server never has to guess.
func encodeHeaderValue(s string) string {
	if needsEncoding(s) {
		return base64Prefix + base64.StdEncoding.EncodeToString([]byte(s)) + base64Suffix
	}
	return s
}

func needsEncoding(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == ' ' || s[0] == '\t' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t' {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || (c >= 0x20 && c <= 0x7E) {
			continue
		}
		return true
	}
	return strings.HasPrefix(s, base64Prefix) && strings.HasSuffix(s, base64Suffix)
}

// isToken is RFC 9110's tchar: the characters allowed in a header field name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// mcpName is the value for Mcp-Name: params.name for tools and prompts,
// params.uri for resources. Empty when the method carries neither.
func mcpName(method string, params json.RawMessage) string {
	switch method {
	case MethodToolsCall, MethodPromptsGet:
		return nameIn(params)
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return ""
		}
		return p.URI
	}
	return ""
}
