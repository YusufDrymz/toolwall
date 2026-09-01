package mcp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/YusufDrymz/toolwall/internal/mcp"
)

// httpServer is a small, scriptable Streamable HTTP MCP server. Each test
// wires the fields it cares about; the rest behave like a plain modern server.
type httpServer struct {
	t          *testing.T
	era        string // "modern" (default) or "legacy"
	tools      []mcp.Tool
	stream     bool              // answer tools/call as an SSE stream
	results    map[string]string // tool -> text
	wantHeader map[string]string // headers a tools/call must carry, by tool name key "tool:header"

	seenHeaders http.Header
	sessions    int
}

func (h *httpServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.seenHeaders = r.Header.Clone()

		var msg mcp.Message
		require.NoError(h.t, json.NewDecoder(r.Body).Decode(&msg))

		if h.era == "legacy" {
			h.serveLegacy(w, &msg)
			return
		}
		h.serveModern(w, r, &msg)
	})
}

func (h *httpServer) serveModern(w http.ResponseWriter, r *http.Request, msg *mcp.Message) {
	switch msg.Method {
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case mcp.MethodDiscover:
		writeJSON(w, reply(msg.ID, map[string]any{
			"resultType":        "complete",
			"supportedVersions": []string{mcp.ProtocolVersion},
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"_meta":             map[string]any{mcp.MetaServerInfo: mcp.Implementation{Name: "http-server", Version: "1.0.0"}},
		}))
	case mcp.MethodInitialize:
		// A modern server rejects initialize with a modern error so the client
		// keeps speaking modern instead of falling back.
		writeErr(w, http.StatusBadRequest, msg.ID, mcp.CodeMethodNotFound, "this server is stateless; use server/discover")
	case mcp.MethodToolsList:
		writeJSON(w, reply(msg.ID, map[string]any{"resultType": "complete", "tools": h.tools}))
	case mcp.MethodToolsCall:
		h.serveCall(w, r, msg)
	default:
		writeErr(w, http.StatusNotFound, msg.ID, mcp.CodeMethodNotFound, "unknown method")
	}
}

func (h *httpServer) serveCall(w http.ResponseWriter, r *http.Request, msg *mcp.Message) {
	var p mcp.CallToolParams
	_ = json.Unmarshal(msg.Params, &p)

	for key, want := range h.wantHeader {
		parts := strings.SplitN(key, ":", 2)
		if parts[0] != p.Name {
			continue
		}
		if got := r.Header.Get(parts[1]); got != want {
			writeErr(w, http.StatusBadRequest, msg.ID, mcp.CodeHeaderMismatch,
				fmt.Sprintf("header %s = %q, want %q", parts[1], got, want))
			return
		}
	}

	text := h.results[p.Name]
	if text == "" {
		text = "ok"
	}
	result := map[string]any{"resultType": "complete", "content": []mcp.TextContent{{Type: "text", Text: text}}}
	if h.stream {
		writeSSE(w, reply(msg.ID, result))
		return
	}
	writeJSON(w, reply(msg.ID, result))
}

func (h *httpServer) serveLegacy(w http.ResponseWriter, msg *mcp.Message) {
	switch msg.Method {
	case mcp.MethodDiscover:
		// Pre-2026 server: it has no idea what server/discover is.
		writeErr(w, http.StatusBadRequest, msg.ID, 0, "")
	case mcp.MethodInitialize:
		h.sessions++
		w.Header().Set("Mcp-Session-Id", "sess-123")
		writeJSON(w, reply(msg.ID, mcp.InitializeResult{
			ProtocolVersion: "2025-06-18",
			Capabilities:    json.RawMessage(`{"tools":{}}`),
			ServerInfo:      mcp.Implementation{Name: "legacy-http", Version: "0.9.0"},
		}))
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case mcp.MethodToolsList:
		writeJSON(w, reply(msg.ID, map[string]any{"tools": h.tools}))
	case mcp.MethodToolsCall:
		writeJSON(w, reply(msg.ID, map[string]any{"content": []mcp.TextContent{{Type: "text", Text: "legacy ok"}}}))
	default:
		writeErr(w, http.StatusNotFound, msg.ID, mcp.CodeMethodNotFound, "unknown")
	}
}

func dialHTTP(t *testing.T, h *httpServer, opts ...func(*mcp.ServerSpec)) *mcp.Client {
	t.Helper()
	h.t = t
	srv := httptest.NewServer(h.handler())
	t.Cleanup(srv.Close)

	spec := mcp.ServerSpec{URL: srv.URL}
	for _, fn := range opts {
		fn(&spec)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, err := mcp.Dial(ctx, spec)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestHTTPModernDiscoverAndList(t *testing.T) {
	c := dialHTTP(t, &httpServer{
		tools: []mcp.Tool{{Name: "get_weather", Description: "weather"}},
	})
	assert.Equal(t, mcp.EraModern, c.Era)
	assert.Equal(t, "http-server", c.ServerInfo.Name)

	tools, err := c.ListTools()
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "get_weather", tools[0].Name)
}

// Every modern POST must carry the protocol version and Mcp-Method headers.
func TestHTTPSendsRequiredHeaders(t *testing.T) {
	h := &httpServer{tools: []mcp.Tool{{Name: "t"}}}
	c := dialHTTP(t, h)
	_, err := c.CallRaw(mcp.MethodToolsCall, mustRaw(t, map[string]any{"name": "t"}))
	require.NoError(t, err)

	assert.Equal(t, mcp.ProtocolVersion, h.seenHeaders.Get("MCP-Protocol-Version"))
	assert.Equal(t, "tools/call", h.seenHeaders.Get("Mcp-Method"))
	assert.Equal(t, "t", h.seenHeaders.Get("Mcp-Name"))
	assert.Contains(t, h.seenHeaders.Get("Accept"), "text/event-stream")
}

// A tools/call answered as an SSE stream must be read the same as a plain one.
func TestHTTPReadsSSEResponse(t *testing.T) {
	c := dialHTTP(t, &httpServer{
		stream:  true,
		tools:   []mcp.Tool{{Name: "t"}},
		results: map[string]string{"t": "from-stream"},
	})
	out, err := c.CallRaw(mcp.MethodToolsCall, mustRaw(t, map[string]any{"name": "t"}))
	require.NoError(t, err)
	assert.Contains(t, string(out), "from-stream")
}

// x-mcp-header parameters must be mirrored into Mcp-Param-* headers.
func TestHTTPMirrorsToolParametersIntoHeaders(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"},"query":{"type":"string"}}}`)
	h := &httpServer{
		tools:      []mcp.Tool{{Name: "execute_sql", InputSchema: schema}},
		wantHeader: map[string]string{"execute_sql:Mcp-Param-Region": "us-west1"},
	}
	c := dialHTTP(t, h)

	_, err := c.CallRaw(mcp.MethodToolsCall, mustRaw(t, map[string]any{
		"name": "execute_sql", "arguments": map[string]any{"region": "us-west1", "query": "SELECT 1"},
	}))
	require.NoError(t, err)
	assert.Equal(t, "us-west1", h.seenHeaders.Get("Mcp-Param-Region"))
}

// A non-ASCII header value must be sent under the Base64 sentinel.
func TestHTTPEncodesNonASCIIHeaderValue(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"greeting":{"type":"string","x-mcp-header":"Greeting"}}}`)
	h := &httpServer{tools: []mcp.Tool{{Name: "hello", InputSchema: schema}}}
	c := dialHTTP(t, h)

	_, err := c.CallRaw(mcp.MethodToolsCall, mustRaw(t, map[string]any{
		"name": "hello", "arguments": map[string]any{"greeting": "Merhaba 世界"},
	}))
	require.NoError(t, err)

	got := h.seenHeaders.Get("Mcp-Param-Greeting")
	require.True(t, strings.HasPrefix(got, "=?base64?") && strings.HasSuffix(got, "?="), "got %q", got)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(got, "=?base64?"), "?="))
	require.NoError(t, err)
	assert.Equal(t, "Merhaba 世界", string(decoded))
}

// A tool with a malformed x-mcp-header annotation must be dropped from the list.
func TestHTTPDropsToolWithInvalidHeaderAnnotation(t *testing.T) {
	bad := json.RawMessage(`{"type":"object","properties":{"n":{"type":"number","x-mcp-header":"N"}}}`) // number is forbidden
	c := dialHTTP(t, &httpServer{tools: []mcp.Tool{
		{Name: "ok_tool", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "bad_tool", InputSchema: bad},
	}})

	tools, err := c.ListTools()
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "ok_tool", tools[0].Name)
	assert.NotEmpty(t, c.Warnings())
}

// A legacy Streamable HTTP server (no server/discover, initialize + session)
// must be detected and driven through the old handshake.
func TestHTTPFallsBackToLegacyHandshake(t *testing.T) {
	h := &httpServer{era: "legacy", tools: []mcp.Tool{{Name: "t"}}}
	c := dialHTTP(t, h)

	assert.Equal(t, mcp.EraLegacy, c.Era)
	assert.Equal(t, "legacy-http", c.ServerInfo.Name)
	assert.Equal(t, 1, h.sessions)

	_, err := c.CallRaw(mcp.MethodToolsCall, mustRaw(t, map[string]any{"name": "t"}))
	require.NoError(t, err)
	assert.Equal(t, "sess-123", h.seenHeaders.Get("Mcp-Session-Id"), "legacy session must be echoed")
}

func TestHTTPRefusesPlainHTTPToRemoteHost(t *testing.T) {
	_, err := mcp.Dial(context.Background(), mcp.ServerSpec{URL: "http://example.com/mcp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing plain http")
}

func TestHTTPHeaderEnvExpansion(t *testing.T) {
	t.Setenv("TW_TEST_TOKEN", "s3cret")
	h := &httpServer{tools: []mcp.Tool{{Name: "t"}}}
	c := dialHTTP(t, h, func(s *mcp.ServerSpec) {
		s.Headers = map[string]string{"Authorization": "Bearer ${TW_TEST_TOKEN}"}
	})
	_, err := c.CallRaw(mcp.MethodToolsCall, mustRaw(t, map[string]any{"name": "t"}))
	require.NoError(t, err)
	assert.Equal(t, "Bearer s3cret", h.seenHeaders.Get("Authorization"))
}

func TestHTTPMissingEnvVarIsAnError(t *testing.T) {
	srv := httptest.NewServer((&httpServer{t: t, tools: []mcp.Tool{{Name: "t"}}}).handler())
	defer srv.Close()
	_, err := mcp.Dial(context.Background(), mcp.ServerSpec{
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer ${TW_DEFINITELY_UNSET_VAR}"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unset environment variable")
}

func TestServerSpecValidate(t *testing.T) {
	assert.Error(t, mcp.ServerSpec{}.Validate())
	assert.Error(t, mcp.ServerSpec{Command: "x", URL: "http://y"}.Validate())
	assert.Error(t, mcp.ServerSpec{Command: "x", Insecure: true}.Validate())
	assert.NoError(t, mcp.ServerSpec{Command: "x"}.Validate())
	assert.NoError(t, mcp.ServerSpec{URL: "https://y"}.Validate())
}

// helpers

func reply(id json.RawMessage, result any) *mcp.Message {
	m, _ := mcp.Reply(id, result)
	return m
}

func writeJSON(w http.ResponseWriter, msg *mcp.Message) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(msg)
}

func writeSSE(w http.ResponseWriter, msg *mcp.Message) {
	w.Header().Set("Content-Type", "text/event-stream")
	raw, _ := json.Marshal(msg)
	fmt.Fprintf(w, ": keep-alive\n\n")
	fmt.Fprintf(w, "data: %s\n\n", raw)
}

func writeErr(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if code == 0 {
		return // legacy server: empty body, not a modern JSON-RPC error
	}
	_ = json.NewEncoder(w).Encode(mcp.Errorf(id, code, "%s", message))
}

func mustRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}
