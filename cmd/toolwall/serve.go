package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/YusufDrymz/toolwall/internal/audit"
	"github.com/YusufDrymz/toolwall/internal/gateway"
	"github.com/YusufDrymz/toolwall/internal/policy"
)

// runServe fronts every server in the policy behind one gateway with a single
// shared flow scope. This is the multi-server sibling of run: put toolwall in
// your client config once, and it aggregates all your MCP servers while
// watching data cross between them.
func runServe(args []string) (int, error) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "toolwall.yaml", "policy file")
	auditPath := fs.String("audit", "", "append the decision trail here (overrides the policy)")
	scopeKey := fs.String("scope-key", "", "_meta key identifying the conversation, if the client sets one")
	observe := fs.Bool("observe", false, "report violations without blocking, whatever the policy says")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}

	cfg, err := policy.Load(*configPath)
	if err != nil {
		return 2, err
	}
	if len(cfg.Servers) == 0 {
		return 2, fmt.Errorf("serve: no servers in %s; run toolwall init first", *configPath)
	}
	if *observe {
		cfg.Mode = policy.ModeObserve
	}

	logPath := cfg.Audit.File
	if *auditPath != "" {
		logPath = *auditPath
	}
	log, err := audit.Open(logPath, "")
	if err != nil {
		return 2, err
	}
	defer func() { _ = log.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, err := gateway.Dial(ctx, gateway.Options{
		Config:   cfg,
		Log:      log,
		Notices:  os.Stderr,
		ScopeKey: *scopeKey,
	})
	if err != nil {
		return 2, err
	}
	defer func() { _ = g.Close() }()

	fmt.Fprintf(os.Stderr, "toolwall: fronting %s in %s mode\n", serverList(cfg), cfg.Mode)

	if err := g.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		return 2, err
	}
	return 0, nil
}

func serverList(cfg *policy.Config) string {
	names := make([]string, 0, len(cfg.Servers))
	for name := range cfg.Servers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
