// Package audit writes the decision trail.
//
// One JSON object per line, append-only, safe to tail and easy to grep. The
// log is the product as much as the enforcement is: after an incident the
// question is always "what did the agent actually touch, and in what order",
// and that answer has to survive the session it happened in.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/YusufDrymz/toolwall/internal/flow"
)

type Kind string

const (
	KindCall    Kind = "call"
	KindResult  Kind = "result"
	KindDenied  Kind = "denied"
	KindPin     Kind = "pin_mismatch"
	KindSession Kind = "session"
)

type Event struct {
	Time   time.Time `json:"time"`
	Kind   Kind      `json:"kind"`
	Server string    `json:"server,omitempty"`
	Scope  string    `json:"scope,omitempty"`
	Tool   string    `json:"tool,omitempty"`
	// Args maps argument name to a sha256 prefix of its value, or to the value
	// itself when the operator opted in. Arguments to a sensitive tool are
	// exactly the material you do not want lying around in a log file.
	Args     map[string]string `json:"args,omitempty"`
	Labels   []string          `json:"labels,omitempty"`
	Decision *flow.Decision    `json:"decision,omitempty"`
	Detail   string            `json:"detail,omitempty"`
	IsError  bool              `json:"isError,omitempty"`
}

type Log struct {
	mu     sync.Mutex
	w      io.WriteCloser
	server string
}

// Open appends to path, creating it with owner-only permissions. An empty path
// disables logging.
func Open(path, server string) (*Log, error) {
	if path == "" {
		return &Log{server: server}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return &Log{w: f, server: server}, nil
}

// To writes to an already-open stream; used by tests and by --audit -.
func To(w io.WriteCloser, server string) *Log { return &Log{w: w, server: server} }

func (l *Log) Write(e Event) {
	if l == nil || l.w == nil {
		return
	}
	e.Time = time.Now().UTC()
	e.Server = l.server

	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(raw, '\n'))
}

func (l *Log) Close() error {
	if l == nil || l.w == nil {
		return nil
	}
	return l.w.Close()
}

// Summarize reduces call arguments to something safe to keep. Values are
// replaced by a short digest unless the operator asked for the real thing;
// either way the argument names survive, and names alone are often enough to
// reconstruct what happened.
func Summarize(arguments json.RawMessage, keepValues bool) map[string]string {
	if len(arguments) == 0 {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(arguments, &decoded); err != nil {
		return map[string]string{"_": digest(string(arguments))}
	}
	out := make(map[string]string, len(decoded))
	for k, v := range decoded {
		rendered := render(v)
		if keepValues {
			out[k] = truncate(rendered, 512)
			continue
		}
		out[k] = digest(rendered)
	}
	return out
}

func render(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(raw)
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// SortedLabels keeps log lines stable, which matters when they are diffed.
func SortedLabels(labels []string) []string {
	out := append([]string{}, labels...)
	sort.Strings(out)
	return out
}
