// Package flow tracks what a scope has read and refuses the calls that would
// send it somewhere.
//
// The model is deliberately small. Tools are labelled in the policy file;
// calling a labelled tool stains the scope with its labels; calling a sink is
// denied once the scope carries the labels a rule forbids. No inference, no
// classifier, no network -- the same sequence of calls always produces the
// same verdict, and every verdict can name the call that caused it.
package flow

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/YusufDrymz/toolwall/internal/mcp"
	"github.com/YusufDrymz/toolwall/internal/policy"
)

// Evidence is the call that first brought a label into the scope. Without it a
// denial is unactionable: the user needs to know which earlier step is the
// reason their tool call just failed.
type Evidence struct {
	Label string `json:"label"`
	Tool  string `json:"tool"`
	Call  int    `json:"call"`
}

type Decision struct {
	Deny bool `json:"deny"`
	// Enforced is false in observe mode: the call was allowed through even
	// though it violates the policy.
	Enforced bool       `json:"enforced"`
	Rule     string     `json:"rule,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	Because  []Evidence `json:"because,omitempty"`
}

func (d Decision) Blocked() bool { return d.Deny && d.Enforced }

// Engine holds the flow state. One engine fronts one server, but scopes are
// keyed by string so a future multi-server gateway can share it.
type Engine struct {
	cfg    *policy.Config
	server string

	mu         sync.Mutex
	scopes     map[string]*scope
	mismatched map[string]string // tool -> why its pin failed
}

type scope struct {
	calls int
	seen  map[string]Evidence
}

func New(cfg *policy.Config, server string) *Engine {
	return &Engine{
		cfg:        cfg,
		server:     server,
		scopes:     map[string]*scope{},
		mismatched: map[string]string{},
	}
}

// CheckPin compares a tool definition against the digest it was pinned with.
// A server is free to add new tools; it is not free to change one that was
// already reviewed.
func (e *Engine) CheckPin(t mcp.Tool) (policy.Action, string) {
	tp, ok := e.cfg.Lookup(e.server, t.Name)
	if !ok || tp.Digest == "" {
		return policy.ActionAllow, ""
	}
	got := policy.Fingerprint(t)
	if got == tp.Digest {
		return policy.ActionAllow, ""
	}
	reason := fmt.Sprintf("definition changed since it was pinned (want %s, got %s)", short(tp.Digest), short(got))

	e.mu.Lock()
	e.mismatched[t.Name] = reason
	e.mu.Unlock()

	return e.cfg.Flow.PinMismatch, reason
}

// Decide is called before a tool call reaches the server.
func (e *Engine) Decide(scopeID, tool string, arguments json.RawMessage) Decision {
	enforced := e.cfg.Mode == policy.ModeEnforce

	tp, known := e.cfg.Lookup(e.server, tool)
	if !known && e.cfg.Flow.UnknownTools == policy.ActionDeny {
		return Decision{Deny: true, Enforced: enforced, Rule: "unknown-tool",
			Reason: "tool is not described in the policy and unknown_tools is deny"}
	}
	if tp.Deny {
		return Decision{Deny: true, Enforced: enforced, Rule: "blocked-tool",
			Reason: "tool is blocked by policy"}
	}

	e.mu.Lock()
	pinReason, pinFailed := e.mismatched[tool]
	e.mu.Unlock()
	if pinFailed && e.cfg.Flow.PinMismatch == policy.ActionDeny {
		return Decision{Deny: true, Enforced: enforced, Rule: "pin-mismatch", Reason: pinReason}
	}

	if err := tp.CheckArgs(arguments); err != nil {
		return Decision{Deny: true, Enforced: enforced, Rule: "argument", Reason: err.Error()}
	}

	st := e.scope(scopeID)
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range e.cfg.Flow.Deny {
		if !hasAny(tp.Labels, rule.Sink) {
			continue
		}
		because, ok := matchAll(st, rule.After)
		if !ok {
			continue
		}
		reason := rule.Reason
		if reason == "" {
			reason = fmt.Sprintf("rule %q forbids this flow", rule.Name)
		}
		return Decision{Deny: true, Enforced: enforced, Rule: rule.Name, Reason: reason, Because: because}
	}
	return Decision{Enforced: enforced}
}

// Record stains the scope with the labels of a tool whose result just came
// back. Errored results count too: the text of a failure is still content the
// model reads, and an attacker who controls a web page controls its errors.
func (e *Engine) Record(scopeID, tool string) []string {
	tp, ok := e.cfg.Lookup(e.server, tool)
	if !ok || len(tp.Labels) == 0 {
		e.bump(scopeID)
		return nil
	}

	st := e.scope(scopeID)
	e.mu.Lock()
	defer e.mu.Unlock()

	st.calls++
	var added []string
	for _, l := range tp.Labels {
		if l == policy.LabelSink {
			continue // a sink sends data out; it does not bring any in
		}
		if _, seen := st.seen[l]; seen {
			continue
		}
		st.seen[l] = Evidence{Label: l, Tool: tool, Call: st.calls}
		added = append(added, l)
	}
	return added
}

// Labels reports what the scope currently carries, for status output.
func (e *Engine) Labels(scopeID string) []Evidence {
	st := e.scope(scopeID)
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]Evidence, 0, len(st.seen))
	for _, ev := range st.seen {
		out = append(out, ev)
	}
	return out
}

func (e *Engine) bump(scopeID string) {
	st := e.scope(scopeID)
	e.mu.Lock()
	st.calls++
	e.mu.Unlock()
}

func (e *Engine) scope(id string) *scope {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.scopes[id]
	if !ok {
		st = &scope{seen: map[string]Evidence{}}
		e.scopes[id] = st
	}
	return st
}

func hasAny(labels, want []string) bool {
	for _, l := range labels {
		for _, w := range want {
			if l == w {
				return true
			}
		}
	}
	return false
}

// matchAll requires every label in want to be present; a rule names the
// combination that is dangerous, not a list of alternatives.
func matchAll(st *scope, want []string) ([]Evidence, bool) {
	out := make([]Evidence, 0, len(want))
	for _, w := range want {
		ev, ok := st.seen[w]
		if !ok {
			return nil, false
		}
		out = append(out, ev)
	}
	return out, true
}

func short(digest string) string {
	if len(digest) > 14 {
		return digest[:14]
	}
	return digest
}
