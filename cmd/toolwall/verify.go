package main

import (
	"flag"
	"fmt"
	"sort"

	"github.com/YusufDrymz/toolwall/internal/policy"
)

// runVerify is the CI half of the tool: reconnect to every server and prove
// that nothing the operator reviewed has changed underneath them.
func runVerify(args []string) (int, error) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	configPath := fs.String("config", "toolwall.yaml", "policy file")
	only := fs.String("server", "", "verify a single server")
	strict := fs.Bool("strict", false, "also fail when a server exposes a tool the policy has never seen")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}

	cfg, err := policy.Load(*configPath)
	if err != nil {
		return 2, err
	}
	if len(cfg.Servers) == 0 {
		return 2, fmt.Errorf("no servers in %s; run toolwall init first", *configPath)
	}

	names := make([]string, 0, len(cfg.Servers))
	for name := range cfg.Servers {
		if *only != "" && name != *only {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return 2, fmt.Errorf("server %q is not in %s", *only, *configPath)
	}
	sort.Strings(names)

	violations := 0
	for _, name := range names {
		inv, err := take(cfg.Servers[name])
		if err != nil {
			return 2, fmt.Errorf("%s: %w", name, err)
		}

		seen := map[string]bool{}
		for _, t := range inv.tools {
			seen[t.Name] = true
			tp, known := cfg.Tools[name+"."+t.Name]
			switch {
			case !known:
				line := fmt.Sprintf("[new ] %s.%s not in the policy", name, t.Name)
				if *strict {
					violations++
					fmt.Println(line)
					continue
				}
				fmt.Println(line + " (run toolwall init to add it)")
			case tp.Digest == "":
				fmt.Printf("[open] %s.%s is not pinned\n", name, t.Name)
			case tp.Digest != policy.Fingerprint(t):
				violations++
				fmt.Printf("[DRIFT] %s.%s definition changed since it was reviewed\n", name, t.Name)
				fmt.Printf("        pinned %s\n        actual %s\n", tp.Digest, policy.Fingerprint(t))
			}
		}

		for key := range cfg.Tools {
			prefix := name + "."
			if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
				continue
			}
			if !seen[key[len(prefix):]] {
				fmt.Printf("[gone] %s no longer exposed by the server\n", key)
			}
		}
		fmt.Printf("%s: %s, %d tool(s) checked\n", name, inv.era, len(inv.tools))
	}

	if violations > 0 {
		fmt.Printf("\n%d violation(s)\n", violations)
		return 1, nil
	}
	fmt.Println("\nno drift")
	return 0, nil
}
