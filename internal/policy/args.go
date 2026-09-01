package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CheckArgs walks the declared argument rules against a call's arguments.
// It returns the first violation, or nil.
//
// Only string values are matched. Rules on a missing argument do not fire:
// an absent value cannot violate an allowlist, and forcing tools to always
// send every argument would be a different feature.
func (t ToolPolicy) CheckArgs(arguments json.RawMessage) error {
	if len(t.Args) == 0 || len(arguments) == 0 {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(arguments, &decoded); err != nil {
		return nil // not an object; nothing addressable to check
	}
	for path, rule := range t.Args {
		v, ok := lookupPath(decoded, path)
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if rule.MaxLen > 0 && len(s) > rule.MaxLen {
			return fmt.Errorf("argument %q is %d bytes, limit is %d", path, len(s), rule.MaxLen)
		}
		for _, re := range rule.deny {
			if re.MatchString(s) {
				return fmt.Errorf("argument %q matches a denied pattern (%s)", path, re.String())
			}
		}
		if len(rule.allow) > 0 {
			matched := false
			for _, re := range rule.allow {
				if re.MatchString(s) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("argument %q is not allowed by any pattern for this tool", path)
			}
		}
	}
	return nil
}

func lookupPath(m map[string]any, path string) (any, bool) {
	cur := any(m)
	for _, seg := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
