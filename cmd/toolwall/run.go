package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/YusufDrymz/toolwall/internal/audit"
	"github.com/YusufDrymz/toolwall/internal/policy"
	"github.com/YusufDrymz/toolwall/internal/proxy"
)

// runGateway is what an MCP client actually launches. It speaks MCP on stdio
// in both directions, so notices go to stderr and nothing else may.
func runGateway(args []string) (int, error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "toolwall.yaml", "policy file")
	server := fs.String("server", "", "which server in the policy this gateway fronts")
	auditPath := fs.String("audit", "", "append the decision trail here (overrides the policy)")
	scopeKey := fs.String("scope-key", "", "_meta key identifying the conversation, if the client sets one")
	observe := fs.Bool("observe", false, "report violations without blocking, whatever the policy says")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *server == "" {
		return 2, fmt.Errorf("run: --server is required")
	}

	cfg, err := policy.Load(*configPath)
	if err != nil {
		return 2, err
	}
	if *observe {
		cfg.Mode = policy.ModeObserve
	}

	spec, err := resolveSpec(cfg, *server, fs.Args(), httpFlags{})
	if err != nil {
		return 2, err
	}
	if spec.IsHTTP() {
		// run is a byte proxy over a spawned child; it cannot front a remote
		// endpoint. serve speaks to HTTP upstreams as a real MCP client.
		return 2, fmt.Errorf("run fronts a stdio server; %q is an http server, use toolwall serve", *server)
	}

	logPath := cfg.Audit.File
	if *auditPath != "" {
		logPath = *auditPath
	}
	log, err := audit.Open(logPath, *server)
	if err != nil {
		return 2, err
	}
	defer func() { _ = log.Close() }()

	// The client owns stdin and stdout; a stray Println here corrupts the
	// stream, so every human-facing byte goes to stderr.
	fmt.Fprintf(os.Stderr, "toolwall: fronting %q in %s mode\n", *server, cfg.Mode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := proxy.New(proxy.Options{
		Server:   *server,
		Spec:     spec,
		Config:   cfg,
		Log:      log,
		Notices:  os.Stderr,
		ScopeKey: *scopeKey,
	})
	if err := p.Run(ctx, os.Stdin, os.Stdout); err != nil {
		return 2, err
	}
	return 0, nil
}
