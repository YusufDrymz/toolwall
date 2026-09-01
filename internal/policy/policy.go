// Package policy is toolwall's configuration: which servers to front, what
// each tool is trusted with, and which flows are forbidden.
//
// The file is meant to be committed and reviewed like code. Everything in it
// is declarative and offline -- no model, no service call, no heuristics at
// enforcement time -- so the same policy always produces the same verdict.
package policy

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/YusufDrymz/toolwall/internal/mcp"
)

// Built-in labels. They are the vocabulary the default rules are written in.
//
//	sensitive -- the tool returns data that must not leave the machine
//	untrusted -- the tool returns content controlled by someone else
//	sink      -- calling the tool can send data outwards
const (
	LabelSensitive = "sensitive"
	LabelUntrusted = "untrusted"
	LabelSink      = "sink"
)

type Mode string

const (
	// ModeEnforce denies violating calls. ModeObserve lets everything through
	// and records what would have been denied, which is how you find out
	// whether a policy is right before it starts breaking people's work.
	ModeEnforce Mode = "enforce"
	ModeObserve Mode = "observe"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionWarn  Action = "warn"
)

type Config struct {
	Version int                       `yaml:"version"`
	Mode    Mode                      `yaml:"mode,omitempty"`
	Servers map[string]mcp.ServerSpec `yaml:"servers,omitempty"`
	Tools   map[string]ToolPolicy     `yaml:"tools,omitempty"`
	Flow    Flow                      `yaml:"flow,omitempty"`
	Audit   Audit                     `yaml:"audit,omitempty"`
}

type ToolPolicy struct {
	Labels []string `yaml:"labels,omitempty"`
	// Digest pins the tool definition as it was reviewed. A server that
	// changes a pinned description or schema is doing a rug pull.
	Digest string             `yaml:"digest,omitempty"`
	Deny   bool               `yaml:"deny,omitempty"`
	Args   map[string]ArgRule `yaml:"args,omitempty"`
	Note   string             `yaml:"note,omitempty"`
}

// ArgRule constrains one argument. Paths are dotted: "options.path".
type ArgRule struct {
	Allow  []string `yaml:"allow,omitempty"`
	Deny   []string `yaml:"deny,omitempty"`
	MaxLen int      `yaml:"max_len,omitempty"`

	allow []*regexp.Regexp
	deny  []*regexp.Regexp
}

type Flow struct {
	// UnknownTools decides what happens to a tool with no policy entry.
	// Default allow: unlabelled tools carry no taint and are not sinks, so
	// they are harmless under the flow rules. Set deny for a closed setup.
	UnknownTools Action `yaml:"unknown_tools,omitempty"`
	// PinMismatch decides what happens when a pinned definition changed.
	PinMismatch Action `yaml:"pin_mismatch,omitempty"`
	Deny        []Rule `yaml:"deny,omitempty"`
}

// Rule forbids calling a tool labelled Sink once the scope has already seen
// every label in After. Labels within After are ANDed; that is what makes a
// rule express "these two things together are the problem".
type Rule struct {
	Name   string   `yaml:"name"`
	Sink   []string `yaml:"sink"`
	After  []string `yaml:"after"`
	Reason string   `yaml:"reason,omitempty"`
}

type Audit struct {
	File string `yaml:"file,omitempty"`
	// LogArguments writes argument values into the audit log. Off by default:
	// the arguments of a sensitive tool call are exactly the material you do
	// not want sitting in a log file. Names and value digests are always kept.
	LogArguments bool `yaml:"log_arguments,omitempty"`
}

// DefaultRules are the two flows that motivate the whole tool. Private data
// reaching a sink is exfiltration; untrusted content reaching a sink is how a
// prompt injection gets its output out.
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:   "exfiltration",
			Sink:   []string{LabelSink},
			After:  []string{LabelSensitive},
			Reason: "sensitive data was read earlier in this scope",
		},
		{
			Name:   "injection-exfiltration",
			Sink:   []string{LabelSink},
			After:  []string{LabelUntrusted},
			Reason: "untrusted content entered this scope earlier and may be steering the call",
		},
	}
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a misspelled key is a silent hole, not a nicety
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if err := c.normalize(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) normalize() error {
	if c.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d (want 1)", c.Version)
	}
	if c.Mode == "" {
		c.Mode = ModeEnforce
	}
	if c.Mode != ModeEnforce && c.Mode != ModeObserve {
		return fmt.Errorf("policy: unknown mode %q", c.Mode)
	}
	if c.Flow.UnknownTools == "" {
		c.Flow.UnknownTools = ActionAllow
	}
	if c.Flow.PinMismatch == "" {
		c.Flow.PinMismatch = ActionDeny
	}
	for _, a := range []Action{c.Flow.UnknownTools, c.Flow.PinMismatch} {
		if a != ActionAllow && a != ActionDeny && a != ActionWarn {
			return fmt.Errorf("policy: unknown action %q", a)
		}
	}
	if len(c.Flow.Deny) == 0 {
		c.Flow.Deny = DefaultRules()
	}

	for i, r := range c.Flow.Deny {
		if r.Name == "" {
			return fmt.Errorf("policy: flow.deny[%d] has no name", i)
		}
		if len(r.Sink) == 0 || len(r.After) == 0 {
			return fmt.Errorf("policy: rule %q needs both sink and after labels", r.Name)
		}
	}

	if err := c.compileArgs(); err != nil {
		return err
	}
	return c.checkLabels()
}

func (c *Config) compileArgs() error {
	for tool, tp := range c.Tools {
		for arg, rule := range tp.Args {
			var err error
			if rule.allow, err = compile(rule.Allow); err != nil {
				return fmt.Errorf("policy: %s.%s allow: %w", tool, arg, err)
			}
			if rule.deny, err = compile(rule.Deny); err != nil {
				return fmt.Errorf("policy: %s.%s deny: %w", tool, arg, err)
			}
			tp.Args[arg] = rule
		}
	}
	return nil
}

// checkLabels rejects labels no rule can ever act on. A typo in a label is
// invisible at runtime -- the tool simply stops being a sink -- so it is
// caught at load time instead.
func (c *Config) checkLabels() error {
	used := map[string]bool{LabelSensitive: true, LabelUntrusted: true, LabelSink: true}
	for _, r := range c.Flow.Deny {
		for _, l := range append(append([]string{}, r.Sink...), r.After...) {
			used[l] = true
		}
	}
	var unknown []string
	for tool, tp := range c.Tools {
		for _, l := range tp.Labels {
			if !used[l] {
				unknown = append(unknown, fmt.Sprintf("%s: %q", tool, l))
			}
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("policy: label(s) not referenced by any rule (typo?): %s", strings.Join(unknown, ", "))
	}
	return nil
}

func compile(patterns []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

// Lookup resolves a tool for the given server, preferring the qualified name.
// The proxy fronts one server at a time but a policy file is shared across
// them, so both spellings have to work.
func (c *Config) Lookup(server, tool string) (ToolPolicy, bool) {
	if server != "" {
		if tp, ok := c.Tools[server+"."+tool]; ok {
			return tp, true
		}
	}
	tp, ok := c.Tools[tool]
	return tp, ok
}

func (t ToolPolicy) Has(label string) bool {
	for _, l := range t.Labels {
		if l == label {
			return true
		}
	}
	return false
}

// Marshal writes the config back out. Used by init, which generates a draft
// for a human to read and correct.
func (c *Config) Marshal() ([]byte, error) { return yaml.Marshal(c) }
