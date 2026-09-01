package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/YusufDrymz/toolwall/internal/mcp"
)

// Fingerprint hashes everything about a tool that the model can read: name,
// title, description, both schemas and the annotations. Field order coming
// off the wire is not stable, so the value is canonicalised first -- without
// that, an unchanged tool would look like a rug pull half the time.
func Fingerprint(t mcp.Tool) string {
	parts := []any{
		t.Name,
		t.Title,
		t.Description,
		canonicalRaw(t.InputSchema),
		canonicalRaw(t.OutputSchema),
		canonicalRaw(t.Annotations),
	}
	sum := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(sum, "%q\x00", p)
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

// FingerprintPrompt does the same for a prompt definition.
func FingerprintPrompt(p mcp.Prompt) string {
	sum := sha256.New()
	fmt.Fprintf(sum, "%q\x00%q\x00%q\x00%q", p.Name, p.Title, p.Description, canonicalRaw(p.Arguments))
	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

func canonicalRaw(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw) // not JSON we understand; hash it verbatim
	}
	return canonical(v)
}

// canonical renders a decoded JSON value with object keys in sorted order.
func canonical(v any) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := "{"
		for i, k := range keys {
			if i > 0 {
				out += ","
			}
			out += strconv.Quote(k) + ":" + canonical(t[k])
		}
		return out + "}"
	case []any:
		out := "["
		for i, e := range t {
			if i > 0 {
				out += ","
			}
			out += canonical(e)
		}
		return out + "]"
	case string:
		return strconv.Quote(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", t)
	}
}
