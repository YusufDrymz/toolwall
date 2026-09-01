package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/YusufDrymz/toolwall/internal/policy"
)

func mustPolicy(t *testing.T, yaml string) *policy.Config {
	t.Helper()
	cfg, err := policy.Parse([]byte(yaml))
	require.NoError(t, err)
	return cfg
}

const explainPolicy = `
version: 1
tools:
  hr.read_record:
    labels: [sensitive]
  mail.send:
    labels: [sink]
    args:
      to:
        allow: ['@corp\.test$']
`

func TestParseSteps(t *testing.T) {
	steps, err := parseSteps([]string{"hr.read_record", "mail.send={\"to\":\"x\"}", "bare"})
	require.NoError(t, err)
	require.Len(t, steps, 3)

	assert.Equal(t, "hr", steps[0].server)
	assert.Equal(t, "read_record", steps[0].tool)
	assert.Nil(t, steps[0].args)

	assert.Equal(t, "mail", steps[1].server)
	assert.Equal(t, "send", steps[1].tool)
	assert.JSONEq(t, `{"to":"x"}`, string(steps[1].args))

	assert.Equal(t, "", steps[2].server)
	assert.Equal(t, "bare", steps[2].tool)
}

func TestParseStepsRejectsBadArgsAndEmptyTool(t *testing.T) {
	_, err := parseSteps([]string{"hr.read={not json}"})
	assert.ErrorContains(t, err, "not valid JSON")

	_, err = parseSteps([]string{"hr."})
	assert.ErrorContains(t, err, "no tool name")
}

// The cross-server exfiltration shows up in simulation without any server.
func TestSimulateCatchesCrossServerFlow(t *testing.T) {
	cfg := mustPolicy(t, explainPolicy)
	steps, err := parseSteps([]string{"mail.send", "hr.read_record", "mail.send"})
	require.NoError(t, err)

	got := simulate(cfg, steps)
	require.Len(t, got, 3)

	assert.False(t, got[0].decision.Deny, "clean sink is fine")
	assert.Contains(t, got[1].labels, "sensitive", "the read stains the scope")
	require.True(t, got[2].decision.Blocked(), "the second send is exfiltration")
	assert.Equal(t, "exfiltration", got[2].decision.Rule)
}

// A blocked call must not stain the scope, matching the runtime.
func TestSimulateBlockedCallDoesNotStain(t *testing.T) {
	cfg := mustPolicy(t, `
version: 1
tools:
  reader:
    labels: [sensitive]
    deny: true
  mail:
    labels: [sink]
`)
	steps, err := parseSteps([]string{"reader", "mail"})
	require.NoError(t, err)

	got := simulate(cfg, steps)
	assert.True(t, got[0].decision.Blocked(), "blocked tool")
	assert.False(t, got[1].decision.Deny, "sink stays clean because the blocked read never stained the scope")
}

func TestSimulateAppliesArgumentRules(t *testing.T) {
	cfg := mustPolicy(t, explainPolicy)
	steps, err := parseSteps([]string{`mail.send={"to":"attacker@evil.test"}`})
	require.NoError(t, err)

	got := simulate(cfg, steps)
	require.True(t, got[0].decision.Blocked())
	assert.Equal(t, "argument", got[0].decision.Rule)
}

// Offline mode must not refuse a pinned tool for want of a live definition.
func TestSimulateDoesNotTripOverPins(t *testing.T) {
	cfg := mustPolicy(t, `
version: 1
tools:
  hr.read_record:
    labels: [sensitive]
    digest: sha256:deadbeef
`)
	steps, err := parseSteps([]string{"hr.read_record"})
	require.NoError(t, err)

	got := simulate(cfg, steps)
	assert.False(t, got[0].decision.Deny, "a pinned tool is judged on flow rules offline, not refused for liveness")
}

func TestSimulateObserveModeReportsWithoutBlocking(t *testing.T) {
	cfg := mustPolicy(t, "version: 1\nmode: observe\n"+explainPolicy[len("\nversion: 1\n"):])
	steps, err := parseSteps([]string{"hr.read_record", "mail.send"})
	require.NoError(t, err)

	got := simulate(cfg, steps)
	assert.True(t, got[1].decision.Deny, "the violation is reported")
	assert.False(t, got[1].decision.Blocked(), "but observe mode lets it through")
}
