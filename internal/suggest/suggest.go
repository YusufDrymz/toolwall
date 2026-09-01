// Package suggest guesses labels for a tool so that toolwall init produces a
// draft worth editing instead of an empty file.
//
// These are suggestions and nothing more. Every one of them is written into
// the policy with the reason attached, because the person reviewing the file
// is the only one who knows whether a tool called "search" reads the company
// wiki or the open internet.
package suggest

import (
	"encoding/json"
	"strings"

	"github.com/YusufDrymz/toolwall/internal/mcp"
	"github.com/YusufDrymz/toolwall/internal/policy"
)

type Suggestion struct {
	Labels []string
	Why    string
}

// Keyword tables. Deliberately short: a long list looks thorough and quietly
// mislabels things, and a wrong sensitive label is worse than no label because
// it teaches the operator to ignore the file.
var (
	sinkWords = []string{
		"send", "email", "mail", "post", "publish", "upload", "push", "webhook",
		"tweet", "message", "notify", "request", "http", "curl", "exec", "shell",
	}
	untrustedWords = []string{
		"fetch", "browse", "crawl", "scrape", "search", "web", "url", "issue",
		"comment", "review", "inbox", "feed", "rss",
	}
	sensitiveWords = []string{
		"secret", "credential", "password", "token", "key", "private", "notes",
		"contact", "calendar", "customer", "salary", "payroll", "invoice",
		"database", "query", "read_file", "readfile",
	}
)

type annotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint"`
	DestructiveHint *bool `json:"destructiveHint"`
	OpenWorldHint   *bool `json:"openWorldHint"`
}

func For(t mcp.Tool) Suggestion {
	haystack := strings.ToLower(t.Name + " " + t.Title + " " + t.Description)

	var labels []string
	var why []string

	if word, ok := match(haystack, sinkWords); ok {
		labels = append(labels, policy.LabelSink)
		why = append(why, "name or description mentions "+word)
	}
	if word, ok := match(haystack, untrustedWords); ok {
		labels = append(labels, policy.LabelUntrusted)
		why = append(why, "returns content from elsewhere ("+word+")")
	}
	if word, ok := match(haystack, sensitiveWords); ok {
		labels = append(labels, policy.LabelSensitive)
		why = append(why, "looks like it reads private data ("+word+")")
	}

	var ann annotations
	if len(t.Annotations) > 0 {
		_ = json.Unmarshal(t.Annotations, &ann)
	}
	// Annotations are self-reported by the server and the spec says to treat
	// them as untrusted. They are good enough to shape a draft and never good
	// enough to clear a label on their own.
	if ann.OpenWorldHint != nil && *ann.OpenWorldHint && !has(labels, policy.LabelUntrusted) {
		labels = append(labels, policy.LabelUntrusted)
		why = append(why, "openWorldHint is set")
	}
	if ann.DestructiveHint != nil && *ann.DestructiveHint && !has(labels, policy.LabelSink) {
		labels = append(labels, policy.LabelSink)
		why = append(why, "destructiveHint is set")
	}
	if ann.ReadOnlyHint != nil && *ann.ReadOnlyHint && has(labels, policy.LabelSink) {
		labels = remove(labels, policy.LabelSink)
		why = append(why, "readOnlyHint says it cannot write, so the sink guess was dropped")
	}

	if len(labels) == 0 {
		return Suggestion{Why: "no guess; label it yourself if it reads private data, returns outside content, or can send anything out"}
	}
	return Suggestion{Labels: labels, Why: "suggested: " + strings.Join(why, "; ")}
}

func match(haystack string, words []string) (string, bool) {
	for _, w := range words {
		if strings.Contains(haystack, w) {
			return w, true
		}
	}
	return "", false
}

func has(list []string, want string) bool {
	for _, l := range list {
		if l == want {
			return true
		}
	}
	return false
}

func remove(list []string, drop string) []string {
	out := list[:0]
	for _, l := range list {
		if l != drop {
			out = append(out, l)
		}
	}
	return out
}
