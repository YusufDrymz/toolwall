package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/YusufDrymz/toolwall/internal/audit"
)

// runAudit reads the trail back as a timeline. After something goes wrong the
// question is what the agent touched and in what order, and a wall of JSON is
// a poor answer to it.
func runAudit(args []string) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	path := fs.String("file", "toolwall-audit.jsonl", "audit log to read")
	scope := fs.String("scope", "", "only show this scope")
	deniedOnly := fs.Bool("denied", false, "only show denials")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}

	f, err := os.Open(*path)
	if err != nil {
		return 2, err
	}
	defer func() { _ = f.Close() }()

	counts := map[audit.Kind]int{}
	byTool := map[string]int{}
	denials := 0

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if *scope != "" && e.Scope != *scope {
			continue
		}
		if *deniedOnly && e.Kind != audit.KindDenied {
			continue
		}
		counts[e.Kind]++
		if e.Tool != "" {
			byTool[e.Tool]++
		}
		if e.Kind == audit.KindDenied {
			denials++
		}
		printEvent(e)
	}
	if err := sc.Err(); err != nil {
		return 2, err
	}

	fmt.Println()
	for _, k := range []audit.Kind{audit.KindCall, audit.KindResult, audit.KindDenied, audit.KindPin} {
		if counts[k] > 0 {
			fmt.Printf("%-12s %d\n", string(k), counts[k])
		}
	}
	if len(byTool) > 0 {
		fmt.Println("\nmost used:")
		for _, t := range topTools(byTool, 5) {
			fmt.Printf("  %-24s %d\n", t.name, t.n)
		}
	}
	if denials > 0 {
		return 1, nil
	}
	return 0, nil
}

func printEvent(e audit.Event) {
	stamp := e.Time.Format("15:04:05")
	switch e.Kind {
	case audit.KindDenied:
		verdict := "DENIED"
		if e.Decision != nil && !e.Decision.Enforced {
			verdict = "WOULD DENY"
		}
		fmt.Printf("%s %-10s %s\n", stamp, verdict, e.Tool)
		if e.Decision != nil {
			fmt.Printf("           rule %s: %s\n", e.Decision.Rule, e.Decision.Reason)
			for _, ev := range e.Decision.Because {
				fmt.Printf("           because call %d (%s) brought %s data in\n", ev.Call, ev.Tool, ev.Label)
			}
		}
	case audit.KindResult:
		suffix := ""
		if len(e.Labels) > 0 {
			suffix = "  +" + strings.Join(e.Labels, ",")
		}
		if e.IsError {
			suffix += "  (tool reported an error)"
		}
		fmt.Printf("%s %-10s %s%s\n", stamp, "result", e.Tool, suffix)
	case audit.KindCall:
		fmt.Printf("%s %-10s %s(%s)\n", stamp, "call", e.Tool, strings.Join(argNames(e.Args), ", "))
	default:
		fmt.Printf("%s %-10s %s %s\n", stamp, string(e.Kind), e.Tool, e.Detail)
	}
}

func argNames(args map[string]string) []string {
	names := make([]string, 0, len(args))
	for k := range args {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

type toolCount struct {
	name string
	n    int
}

func topTools(counts map[string]int, limit int) []toolCount {
	out := make([]toolCount, 0, len(counts))
	for name, n := range counts {
		out = append(out, toolCount{name, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].name < out[j].name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
