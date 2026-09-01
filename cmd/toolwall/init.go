package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/YusufDrymz/toolwall/internal/mcp"
	"github.com/YusufDrymz/toolwall/internal/policy"
	"github.com/YusufDrymz/toolwall/internal/suggest"
)

func runInit(args []string) (int, error) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "toolwall.yaml", "policy file to create or extend")
	server := fs.String("server", "", "name for this server in the policy")
	dryRun := fs.Bool("dry-run", false, "print the policy instead of writing it")
	repin := fs.Bool("repin", false, "update digests of tools whose definition changed")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *server == "" {
		return 2, fmt.Errorf("init: --server is required")
	}

	cfg, err := loadOrCreate(*configPath)
	if err != nil {
		return 2, err
	}

	spec, err := resolveSpec(cfg, *server, fs.Args())
	if err != nil {
		return 2, err
	}

	inv, err := take(spec)
	if err != nil {
		return 2, err
	}

	if cfg.Servers == nil {
		cfg.Servers = map[string]mcp.ServerSpec{}
	}
	cfg.Servers[*server] = spec
	if cfg.Tools == nil {
		cfg.Tools = map[string]policy.ToolPolicy{}
	}

	var added, repinned, unchanged []string
	for _, t := range inv.tools {
		key := *server + "." + t.Name
		digest := policy.Fingerprint(t)

		existing, ok := cfg.Tools[key]
		if !ok {
			s := suggest.For(t)
			cfg.Tools[key] = policy.ToolPolicy{Labels: s.Labels, Digest: digest, Note: s.Why}
			added = append(added, t.Name)
			continue
		}
		// Never silently re-pin: a changed definition is the exact event the
		// digest exists to catch, so it takes a deliberate --repin to accept.
		if existing.Digest != digest {
			if !*repin {
				unchanged = append(unchanged, t.Name+" (definition changed, run with --repin to accept)")
				continue
			}
			existing.Digest = digest
			cfg.Tools[key] = existing
			repinned = append(repinned, t.Name)
			continue
		}
		unchanged = append(unchanged, t.Name)
	}

	out, err := cfg.Marshal()
	if err != nil {
		return 2, err
	}
	if *dryRun {
		fmt.Print(string(out))
		return 0, nil
	}
	if err := os.WriteFile(*configPath, out, 0o644); err != nil {
		return 2, err
	}

	fmt.Printf("%s: %s server %q, protocol %s, %d tool(s)\n",
		*configPath, inv.era, nameOr(inv.info.Name, *server), inv.version, len(inv.tools))
	report("added", added)
	report("repinned", repinned)
	report("kept", unchanged)
	if len(added) > 0 {
		fmt.Println("\nreview the labels before trusting them: sensitive means the tool returns private")
		fmt.Println("data, untrusted means it returns someone else's content, sink means it can send data out.")
	}
	return 0, nil
}

func loadOrCreate(path string) (*policy.Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &policy.Config{Version: 1, Mode: policy.ModeObserve}, nil
	}
	return policy.Load(path)
}

// resolveSpec prefers an explicit command line and falls back to the server
// already described in the policy.
func resolveSpec(cfg *policy.Config, server string, argv []string) (mcp.ServerSpec, error) {
	if len(argv) > 0 {
		return mcp.ServerSpec{Command: argv[0], Args: argv[1:]}, nil
	}
	if spec, ok := cfg.Servers[server]; ok {
		return spec, nil
	}
	return mcp.ServerSpec{}, fmt.Errorf("no command given and %q is not in the policy; pass it after --", server)
}

func report(label string, names []string) {
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	fmt.Printf("  %s: %d\n", label, len(names))
	for _, n := range names {
		fmt.Println("    -", n)
	}
}

func nameOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
