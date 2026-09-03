package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/YusufDrymz/toolwall/internal/policy"
)

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := policy.Parse([]byte("version: 1\n"))
	require.NoError(t, err)

	assert.Equal(t, policy.ModeEnforce, cfg.Mode)
	assert.Equal(t, policy.ActionAllow, cfg.Flow.UnknownTools)
	assert.Equal(t, policy.ActionDeny, cfg.Flow.PinMismatch)
	assert.Len(t, cfg.Flow.Deny, 2, "the two default rules should be in place")
}

// A key that does not exist is almost always a rule the author believes is
// active. Failing the load is the only safe reading.
func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := policy.Parse([]byte("version: 1\ntols:\n  a: {}\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tols")
}

func TestParseRejectsLabelNoRuleUses(t *testing.T) {
	_, err := policy.Parse([]byte("version: 1\ntools:\n  reader:\n    labels: [sensitiv]\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not referenced by any rule")
}

func TestParseAcceptsCustomLabelUsedByARule(t *testing.T) {
	cfg, err := policy.Parse([]byte(`
version: 1
tools:
  payroll:
    labels: [hr]
  slack_post:
    labels: [broadcast]
flow:
  deny:
    - name: hr-stays-in-hr
      sink: [broadcast]
      after: [hr]
`))
	require.NoError(t, err)
	assert.Len(t, cfg.Flow.Deny, 1)
}

func TestParseRejectsBadVersionAndMode(t *testing.T) {
	_, err := policy.Parse([]byte("version: 2\n"))
	assert.ErrorContains(t, err, "unsupported version")

	_, err = policy.Parse([]byte("version: 1\nmode: audit\n"))
	assert.ErrorContains(t, err, "unknown mode")
}

func TestParseRejectsIncompleteRule(t *testing.T) {
	_, err := policy.Parse([]byte("version: 1\nflow:\n  deny:\n    - name: half\n      sink: [sink]\n"))
	assert.ErrorContains(t, err, "needs both sink and after")
}

func TestLookupPrefersQualifiedName(t *testing.T) {
	cfg, err := policy.Parse([]byte(`
version: 1
tools:
  search:
    labels: [untrusted]
  web.search:
    labels: [sink]
`))
	require.NoError(t, err)

	qualified, ok := cfg.Lookup("web", "search")
	require.True(t, ok)
	assert.True(t, qualified.Has(policy.LabelSink))

	bare, ok := cfg.Lookup("files", "search")
	require.True(t, ok)
	assert.True(t, bare.Has(policy.LabelUntrusted))
}

func TestResourceLabelsUnionEveryMatchingRule(t *testing.T) {
	cfg, err := policy.Parse([]byte(`
version: 1
resources:
  - match: '^file:///hr/'
    labels: [sensitive]
  - match: '\.csv$'
    labels: [untrusted]
`))
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"sensitive"}, cfg.ResourceLabels("file:///hr/notes.txt"))
	assert.ElementsMatch(t, []string{"untrusted"}, cfg.ResourceLabels("file:///public/a.csv"))
	assert.ElementsMatch(t, []string{"sensitive", "untrusted"},
		cfg.ResourceLabels("file:///hr/salaries.csv"), "overlapping rules are additive")
	assert.Empty(t, cfg.ResourceLabels("file:///other/x.txt"))
}

func TestResourceRuleValidation(t *testing.T) {
	_, err := policy.Parse([]byte("version: 1\nresources:\n  - labels: [sensitive]\n"))
	assert.ErrorContains(t, err, "no match pattern")

	_, err = policy.Parse([]byte("version: 1\nresources:\n  - match: '[unclosed'\n"))
	assert.ErrorContains(t, err, "match")

	_, err = policy.Parse([]byte("version: 1\nresources:\n  - match: '^file:'\n    labels: [sensitiv]\n"))
	assert.ErrorContains(t, err, "not referenced by any rule")
}
