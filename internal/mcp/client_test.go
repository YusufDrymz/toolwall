package mcp_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/YusufDrymz/toolwall/internal/fakemcp"
	"github.com/YusufDrymz/toolwall/internal/mcp"
)

func TestMain(m *testing.M) {
	fakemcp.RunIfChild()
	os.Exit(m.Run())
}

func dial(t *testing.T, cfg fakemcp.Config) *mcp.Client {
	t.Helper()
	spec, err := fakemcp.Spec(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	c, err := mcp.Dial(ctx, spec)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestDialDetectsModernServer(t *testing.T) {
	c := dial(t, fakemcp.Config{Name: "modern-server", Era: "modern", StrictMeta: true})

	assert.Equal(t, mcp.EraModern, c.Era)
	assert.Equal(t, mcp.ProtocolVersion, c.ProtocolVersion)
	assert.Equal(t, "modern-server", c.ServerInfo.Name)
}

func TestDialFallsBackToLegacyHandshake(t *testing.T) {
	c := dial(t, fakemcp.Config{Name: "legacy-server", Era: "legacy"})

	assert.Equal(t, mcp.EraLegacy, c.Era)
	assert.Equal(t, "2025-06-18", c.ProtocolVersion)
	assert.Equal(t, "legacy-server", c.ServerInfo.Name)
}

// A modern server that does not speak our revision answers -32022 with the
// versions it does speak; that is still a modern server, not a legacy one.
func TestDialHonoursUnsupportedProtocolVersion(t *testing.T) {
	c := dial(t, fakemcp.Config{
		Name:              "future-server",
		Era:               "modern",
		SupportedVersions: []string{"2027-01-01", "2026-11-11"},
	})

	assert.Equal(t, mcp.EraModern, c.Era)
	assert.Equal(t, "2027-01-01", c.ProtocolVersion)
}

// StrictMeta rejects any request without the per-request protocol metadata, so
// a green listing here is proof that the client attaches it every time.
func TestListToolsAgainstStrictModernServer(t *testing.T) {
	c := dial(t, fakemcp.Config{
		Name:       "strict",
		Era:        "modern",
		StrictMeta: true,
		Tools: []mcp.Tool{
			{Name: "read_file", Description: "Read a file", InputSchema: json.RawMessage(`{"type":"object"}`)},
			{Name: "send_email", Description: "Send mail"},
		},
	})

	tools, err := c.ListTools()
	require.NoError(t, err)
	require.Len(t, tools, 2)
	assert.Equal(t, "read_file", tools[0].Name)
}

func TestListPromptsTreatsMethodNotFoundAsEmpty(t *testing.T) {
	c := dial(t, fakemcp.Config{Name: "no-prompts", Era: "modern"})

	prompts, err := c.ListPrompts()
	require.NoError(t, err)
	assert.Empty(t, prompts)
}

func TestDialTimesOutOnSilentServer(t *testing.T) {
	spec, err := fakemcp.Spec(fakemcp.Config{Name: "silent", Era: "silent"})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = mcp.Dial(ctx, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
}
