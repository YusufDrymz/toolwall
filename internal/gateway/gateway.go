// Package gateway aggregates several MCP servers behind one toolwall endpoint
// and, crucially, tracks their tool calls in a single shared flow scope.
//
// That shared scope is the reason the package exists. The single-server proxy
// stops an agent from reading a secret and mailing it out through the same
// server; the gateway stops it from reading a secret on the HR server and
// mailing it out through the Slack server. Isolation tools guard the process,
// identity tools guard the door -- neither watches data cross from one server
// to another, and that crossing is exactly what an aggregating point can see.
//
// The client speaks MCP to the gateway; the gateway is a client to each
// upstream. Tool names are namespaced with the server id (`hr.read_record`),
// which is also how the policy already addresses them. Because the 2026-07-28
// revision made MCP stateless and request/response, the gateway handles one
// client request at a time: a tool call is judged, stained and forwarded
// before the next is read, which gives stricter ordering than a byte proxy can.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/YusufDrymz/toolwall/internal/audit"
	"github.com/YusufDrymz/toolwall/internal/flow"
	"github.com/YusufDrymz/toolwall/internal/mcp"
	"github.com/YusufDrymz/toolwall/internal/policy"
)

// nameSep joins a server id and a tool name into the namespaced name the client
// sees. A dot is used because the policy already addresses tools this way and
// the spec allows it in tool names; server ids may therefore not contain one.
const nameSep = "."

type Options struct {
	Config   *policy.Config
	Log      *audit.Log
	Notices  io.Writer
	ScopeKey string
}

type Gateway struct {
	cfg      *policy.Config
	eng      *flow.Engine
	log      *audit.Log
	notices  io.Writer
	scopeKey string

	order     []string // server ids, stable for deterministic listings
	upstreams map[string]*mcp.Client

	pinsOnce sync.Map // server -> *sync.Once, guards the one-time pin probe
}

// Dial starts every server in the config and completes each handshake. If any
// server fails to start the whole gateway fails: a policy that silently drops
// a server it was told to front is worse than an error.
func Dial(ctx context.Context, opts Options) (*Gateway, error) {
	if opts.Notices == nil {
		opts.Notices = io.Discard
	}
	if len(opts.Config.Servers) == 0 {
		return nil, fmt.Errorf("gateway: no servers in the policy")
	}

	g := &Gateway{
		cfg:       opts.Config,
		eng:       flow.New(opts.Config),
		log:       opts.Log,
		notices:   opts.Notices,
		scopeKey:  opts.ScopeKey,
		upstreams: map[string]*mcp.Client{},
	}

	for name := range opts.Config.Servers {
		if strings.Contains(name, nameSep) {
			g.closeAll()
			return nil, fmt.Errorf("gateway: server id %q may not contain %q", name, nameSep)
		}
		g.order = append(g.order, name)
	}
	sort.Strings(g.order)

	for _, name := range g.order {
		c, err := mcp.Dial(ctx, opts.Config.Servers[name])
		if err != nil {
			g.closeAll()
			return nil, fmt.Errorf("gateway: server %q: %w", name, err)
		}
		g.upstreams[name] = c
	}
	return g, nil
}

func (g *Gateway) Close() error { g.closeAll(); return nil }

func (g *Gateway) closeAll() {
	for _, c := range g.upstreams {
		_ = c.Close()
	}
}

// Serve reads client requests and answers them until the stream closes. One at
// a time, in arrival order: see the package comment.
func (g *Gateway) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	conn := mcp.NewConn(in, out)
	g.log.Write(audit.Event{Kind: audit.KindSession,
		Detail: fmt.Sprintf("gateway started over %d server(s), mode %s", len(g.order), g.cfg.Mode)})

	for {
		if ctx.Err() != nil {
			return nil
		}
		msg, err := conn.Read()
		if err != nil {
			if isClosed(err) {
				return nil
			}
			return err
		}
		if !msg.IsRequest() {
			continue // notifications from the client need no reply
		}
		reply := g.handle(msg)
		if reply == nil {
			continue
		}
		if err := conn.Write(reply); err != nil {
			if isClosed(err) {
				return nil
			}
			return err
		}
	}
}

func (g *Gateway) handle(msg *mcp.Message) *mcp.Message {
	switch msg.Method {
	case mcp.MethodDiscover:
		return g.discover(msg)
	case mcp.MethodInitialize:
		return g.initialize(msg)
	case mcp.MethodToolsList:
		return g.toolsList(msg)
	case mcp.MethodToolsCall:
		return g.toolsCall(msg)
	case mcp.MethodPromptsList:
		return g.promptsList(msg)
	case "ping":
		return reply(msg.ID, map[string]any{})
	default:
		return mcp.Errorf(msg.ID, mcp.CodeMethodNotFound,
			"toolwall gateway does not proxy %q (tools and prompts only)", msg.Method)
	}
}

func (g *Gateway) discover(msg *mcp.Message) *mcp.Message {
	return reply(msg.ID, map[string]any{
		"resultType":        "complete",
		"supportedVersions": []string{mcp.ProtocolVersion},
		"capabilities":      map[string]any{"tools": map[string]any{}, "prompts": map[string]any{}},
		"instructions":      fmt.Sprintf("Fronting %d MCP server(s) behind toolwall; tools are named server%stool.", len(g.order), nameSep),
		"_meta":             map[string]any{mcp.MetaServerInfo: mcp.Implementation{Name: "toolwall", Version: mcp.Version}},
	})
}

func (g *Gateway) initialize(msg *mcp.Message) *mcp.Message {
	return reply(msg.ID, mcp.InitializeResult{
		ProtocolVersion: "2025-06-18",
		Capabilities:    json.RawMessage(`{"tools":{"listChanged":false},"prompts":{"listChanged":false}}`),
		ServerInfo:      mcp.Implementation{Name: "toolwall", Version: mcp.Version},
		Instructions:    fmt.Sprintf("Fronting %d MCP server(s) behind toolwall; tools are named server%stool.", len(g.order), nameSep),
	})
}

// toolsList asks every upstream for its tools, checks each against its pin,
// drops the ones that changed, namespaces the survivors and merges them.
func (g *Gateway) toolsList(msg *mcp.Message) *mcp.Message {
	merged := make([]mcp.Tool, 0)
	for _, name := range g.order {
		tools, err := g.upstreams[name].ListTools()
		if err != nil {
			fmt.Fprintf(g.notices, "toolwall: %s tools/list failed: %v\n", name, err)
			continue
		}
		merged = append(merged, g.screen(name, tools)...)
	}
	return reply(msg.ID, map[string]any{"resultType": "complete", "tools": merged})
}

// screen runs the pin check for one server's tools and returns the namespaced
// survivors. Marking the probe done here means a later call to any of these
// tools does not have to re-list.
func (g *Gateway) screen(server string, tools []mcp.Tool) []mcp.Tool {
	g.markProbed(server)
	kept := make([]mcp.Tool, 0, len(tools))
	for _, t := range tools {
		action, reason := g.eng.CheckPin(server, t)
		if reason != "" {
			g.log.Write(audit.Event{Kind: audit.KindPin, Server: server, Tool: t.Name, Detail: reason})
			fmt.Fprintf(g.notices, "toolwall: %s %s.%s: %s\n", action, server, t.Name, reason)
		}
		if action == policy.ActionDeny {
			continue
		}
		t.Name = server + nameSep + t.Name
		kept = append(kept, t)
	}
	return kept
}

func (g *Gateway) promptsList(msg *mcp.Message) *mcp.Message {
	merged := make([]mcp.Prompt, 0)
	for _, name := range g.order {
		prompts, err := g.upstreams[name].ListPrompts()
		if err != nil {
			continue
		}
		for _, p := range prompts {
			p.Name = name + nameSep + p.Name
			merged = append(merged, p)
		}
	}
	return reply(msg.ID, map[string]any{"resultType": "complete", "prompts": merged})
}

// toolsCall routes a namespaced call to its server, judges it against the
// shared scope, and forwards or refuses it.
func (g *Gateway) toolsCall(msg *mcp.Message) *mcp.Message {
	var params mcp.CallToolParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return mcp.Errorf(msg.ID, mcp.CodeInvalidParams, "toolwall: bad tools/call params")
	}
	server, tool, ok := g.route(params.Name)
	if !ok {
		return mcp.Errorf(msg.ID, mcp.CodeInvalidParams,
			"toolwall: %q is not a known server.tool", params.Name)
	}

	if g.eng.NeedsPinCheck(server, tool) {
		g.verifyPins(server)
	}

	scope := g.scopeOf(msg.Params)
	d := g.eng.Decide(scope, server, tool, params.Arguments)

	ev := audit.Event{
		Kind: audit.KindCall, Server: server, Scope: scope, Tool: tool,
		Args: audit.Summarize(params.Arguments, g.cfg.Audit.LogArguments),
	}
	if d.Deny {
		// A denial is recorded as such even in observe mode, so the log shows
		// what the policy would have blocked; enforced:false is the tell.
		ev.Kind = audit.KindDenied
		ev.Decision = &d
	}
	if d.Deny && d.Enforced {
		g.log.Write(ev)
		fmt.Fprintf(g.notices, "toolwall: denied %s.%s (%s)\n", server, tool, d.Rule)
		return denial(msg.ID, server+nameSep+tool, d)
	}
	if d.Deny {
		fmt.Fprintf(g.notices, "toolwall: would deny %s.%s (%s) -- observe mode\n", server, tool, d.Rule)
	}

	// Stain before forwarding, never after the result: a client that pipelines
	// a read and a send must not have the send judged against a clean scope.
	ev.Labels = audit.SortedLabels(g.eng.Record(scope, server, tool))
	g.log.Write(ev)

	// Forward with the tool's real, un-namespaced name.
	forward, err := json.Marshal(mcp.CallToolParams{Name: tool, Arguments: params.Arguments})
	if err != nil {
		return mcp.Errorf(msg.ID, mcp.CodeInternalError, "toolwall: %v", err)
	}
	result, callErr := g.upstreams[server].CallRaw(mcp.MethodToolsCall, forward)
	if callErr != nil {
		var rpc *mcp.Error
		if asRPC(callErr, &rpc) {
			return &mcp.Message{JSONRPC: "2.0", ID: msg.ID, Error: rpc}
		}
		return mcp.Errorf(msg.ID, mcp.CodeInternalError, "toolwall: %s.%s: %v", server, tool, callErr)
	}

	var res mcp.CallToolResult
	_ = json.Unmarshal(result, &res)
	g.log.Write(audit.Event{Kind: audit.KindResult, Server: server, Scope: scope, Tool: tool, IsError: res.IsError})

	return &mcp.Message{JSONRPC: "2.0", ID: msg.ID, Result: result}
}

// route splits a namespaced name into (server, tool). It splits on the first
// separator, so a tool whose own name contains a dot survives.
func (g *Gateway) route(name string) (server, tool string, ok bool) {
	i := strings.Index(name, nameSep)
	if i < 0 {
		return "", "", false
	}
	server, tool = name[:i], name[i+len(nameSep):]
	if _, known := g.upstreams[server]; !known || tool == "" {
		return "", "", false
	}
	return server, tool, true
}

// verifyPins lists one server's tools so a pinned call can be judged against a
// live definition even when the client never listed them itself.
func (g *Gateway) verifyPins(server string) {
	g.probeOnce(server, func() {
		tools, err := g.upstreams[server].ListTools()
		if err != nil {
			fmt.Fprintf(g.notices, "toolwall: %s pin check failed: %v; pinned tools stay refused\n", server, err)
			return
		}
		g.screen(server, tools) // marks each pin ok/mismatched
	})
}

func (g *Gateway) markProbed(server string) { g.probeOnce(server, func() {}) }

func (g *Gateway) probeOnce(server string, fn func()) {
	once, _ := g.pinsOnce.LoadOrStore(server, &sync.Once{})
	once.(*sync.Once).Do(fn)
}

func (g *Gateway) scopeOf(params json.RawMessage) string {
	if g.scopeKey == "" {
		return "process"
	}
	var envelope struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &envelope); err != nil {
		return "process"
	}
	raw, ok := envelope.Meta[g.scopeKey]
	if !ok {
		return "process"
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return "process"
	}
	return s
}

func reply(id json.RawMessage, result any) *mcp.Message {
	m, err := mcp.Reply(id, result)
	if err != nil {
		return mcp.Errorf(id, mcp.CodeInternalError, "toolwall: %v", err)
	}
	return m
}

func denial(id json.RawMessage, name string, d flow.Decision) *mcp.Message {
	var b strings.Builder
	fmt.Fprintf(&b, "toolwall denied this call to %q: %s.", name, d.Reason)
	for _, ev := range d.Because {
		fmt.Fprintf(&b, " Call %d (%s) brought %s data into this session.", ev.Call, ev.Tool, ev.Label)
	}
	b.WriteString(" This is a policy decision, not a transient failure: do not retry, and tell the user which rule blocked it.")

	msg := mcp.Errorf(id, mcp.CodeInvalidRequest, "%s", b.String())
	if data, err := json.Marshal(map[string]any{"toolwall": d}); err == nil {
		msg.Error.Data = data
	}
	return msg
}

func asRPC(err error, target **mcp.Error) bool {
	e, ok := err.(*mcp.Error)
	if ok {
		*target = e
	}
	return ok
}

func isClosed(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	for _, quiet := range []string{"EOF", "file already closed", "broken pipe", "closed pipe"} {
		if strings.Contains(msg, quiet) {
			return true
		}
	}
	return false
}
