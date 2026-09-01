package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/YusufDrymz/toolwall/internal/mcp"
	"github.com/YusufDrymz/toolwall/internal/policy"
	"github.com/YusufDrymz/toolwall/internal/suggest"
)

func runInit(args []string) (int, error) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "toolwall.yaml", "policy file to create or extend")
	server := fs.String("server", "", "name for this server in the policy")
	url := fs.String("url", "", "Streamable HTTP endpoint (instead of a command after --)")
	var headers headerFlags
	fs.Var(&headers, "header", "extra HTTP header, NAME:VALUE (repeatable); values may use ${ENV}")
	insecure := fs.Bool("insecure", false, "allow plain http to a non-loopback host")
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

	spec, err := resolveSpec(cfg, *server, fs.Args(), httpFlags{url: *url, headers: headers, insecure: *insecure})
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

// httpFlags carries the url-server flags from a command so resolveSpec can
// build a Streamable HTTP spec without every caller re-parsing them.
type httpFlags struct {
	url      string
	headers  headerFlags
	insecure bool
}

// resolveSpec builds a server spec from, in order: an explicit --url, a command
// after --, or the entry already in the policy.
func resolveSpec(cfg *policy.Config, server string, argv []string, http httpFlags) (mcp.ServerSpec, error) {
	if http.url != "" {
		if len(argv) > 0 {
			return mcp.ServerSpec{}, fmt.Errorf("give either --url or a command after --, not both")
		}
		hdrs, err := http.headers.toMap()
		if err != nil {
			return mcp.ServerSpec{}, err
		}
		return mcp.ServerSpec{URL: http.url, Headers: hdrs, Insecure: http.insecure}, nil
	}
	if len(argv) > 0 {
		return mcp.ServerSpec{Command: argv[0], Args: argv[1:]}, nil
	}
	if spec, ok := cfg.Servers[server]; ok {
		return spec, nil
	}
	return mcp.ServerSpec{}, fmt.Errorf("no command or --url given, and %q is not in the policy; pass a command after -- or use --url", server)
}

// headerFlags collects repeated --header NAME:VALUE flags.
type headerFlags []string

func (h *headerFlags) String() string { return fmt.Sprint([]string(*h)) }
func (h *headerFlags) Set(v string) error {
	if !strings.Contains(v, ":") {
		return fmt.Errorf("header %q must be NAME:VALUE", v)
	}
	*h = append(*h, v)
	return nil
}

func (h headerFlags) toMap() (map[string]string, error) {
	if len(h) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(h))
	for _, entry := range h {
		name, value, _ := strings.Cut(entry, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("header %q has an empty name", entry)
		}
		out[name] = value
	}
	return out, nil
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
