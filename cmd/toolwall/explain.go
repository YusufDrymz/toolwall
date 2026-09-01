package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/YusufDrymz/toolwall/internal/flow"
	"github.com/YusufDrymz/toolwall/internal/policy"
)

// runExplain simulates a policy against a sequence of tool calls without
// touching any server. It answers the question you have before you deploy:
// "given these rules, which of these calls goes through, and why not the rest?"
//
// Because it is offline it cannot check pins against a live definition, so a
// pinned tool is judged on its flow and argument rules alone; the run reminds
// you of that once.
func runExplain(args []string) (int, error) {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	configPath := fs.String("config", "toolwall.yaml", "policy file")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	steps, err := parseSteps(fs.Args())
	if err != nil {
		return 2, err
	}
	if len(steps) == 0 {
		return 2, fmt.Errorf("explain: give a sequence of calls, e.g. hr.read_record mail.send='{\"to\":\"x\"}'")
	}

	cfg, err := policy.Load(*configPath)
	if err != nil {
		return 2, err
	}

	results := simulate(cfg, steps)
	denied := renderExplain(*configPath, cfg, steps, results)
	if denied {
		return 1, nil
	}
	return 0, nil
}

// step is one hypothetical call. server may be empty, matching the bare-tool
// form the policy also accepts.
type step struct {
	server string
	tool   string
	args   json.RawMessage
}

// parseSteps reads positional tokens of the form server.tool or
// server.tool={json-args}. The first "." splits server from tool; the first
// "=" splits the call from its arguments.
func parseSteps(tokens []string) ([]step, error) {
	var steps []step
	for _, tok := range tokens {
		name, args, hasArgs := strings.Cut(tok, "=")
		s := step{}
		if i := strings.Index(name, "."); i >= 0 {
			s.server, s.tool = name[:i], name[i+1:]
		} else {
			s.tool = name
		}
		if s.tool == "" {
			return nil, fmt.Errorf("explain: %q has no tool name", tok)
		}
		if hasArgs {
			if !json.Valid([]byte(args)) {
				return nil, fmt.Errorf("explain: arguments for %q are not valid JSON", name)
			}
			s.args = json.RawMessage(args)
		}
		steps = append(steps, s)
	}
	return steps, nil
}

type stepResult struct {
	decision flow.Decision
	labels   []string // labels this call brought into the scope
}

// simulate runs the steps through an offline engine in order and returns one
// result per step. The scope is shared across every step, exactly as it would
// be in a live session, so cross-server flows show up here too.
func simulate(cfg *policy.Config, steps []step) []stepResult {
	eng := flow.New(cfg).Offline()
	const scope = "explain"

	out := make([]stepResult, len(steps))
	for i, s := range steps {
		d := eng.Decide(scope, s.server, s.tool, s.args)
		out[i] = stepResult{decision: d}
		// Mirror the runtime: a blocked call never reaches the server, so it
		// never stains the scope. Everything else -- allowed, or would-deny in
		// observe mode -- does.
		if !d.Blocked() {
			out[i].labels = eng.Record(scope, s.server, s.tool)
		}
	}
	return out
}

func renderExplain(path string, cfg *policy.Config, steps []step, results []stepResult) bool {
	fmt.Printf("policy %s, mode %s -- offline simulation, pins not checked\n\n", path, cfg.Mode)
	anyDenied := false
	for i, s := range steps {
		r := results[i]
		name := s.tool
		if s.server != "" {
			name = s.server + "." + s.tool
		}
		switch {
		case r.decision.Blocked():
			anyDenied = true
			fmt.Printf("%2d. DENIED     %s\n", i+1, name)
			fmt.Printf("        rule %s: %s\n", r.decision.Rule, r.decision.Reason)
			for _, ev := range r.decision.Because {
				fmt.Printf("        because call %d (%s) brought %s data in\n", ev.Call, ev.Tool, ev.Label)
			}
		case r.decision.Deny:
			anyDenied = true
			fmt.Printf("%2d. WOULD DENY %s (observe mode lets it through)\n", i+1, name)
			fmt.Printf("        rule %s: %s\n", r.decision.Rule, r.decision.Reason)
		default:
			suffix := ""
			if len(r.labels) > 0 {
				suffix = "  +" + strings.Join(r.labels, ",")
			}
			fmt.Printf("%2d. allow      %s%s\n", i+1, name, suffix)
		}
	}
	return anyDenied
}
