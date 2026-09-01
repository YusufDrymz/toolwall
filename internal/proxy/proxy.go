// Package proxy is the gateway itself: a stdio MCP server on one side, a real
// MCP server on the other, and the flow engine in between.
//
// Messages it has no opinion about are forwarded untouched, in both eras of
// the protocol. It only ever looks at three things: the tool list coming back
// (to check pins), tool calls going out (to decide), and tool results coming
// back (to record what entered the scope).
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/YusufDrymz/toolwall/internal/audit"
	"github.com/YusufDrymz/toolwall/internal/flow"
	"github.com/YusufDrymz/toolwall/internal/mcp"
	"github.com/YusufDrymz/toolwall/internal/policy"
)

// DefaultScope is used when no scope key is configured.
//
// The 2026-07-28 revision is explicit that a connection is not a session, so
// there is no conversation identifier to key on. One gateway process is the
// strongest boundary available locally; operators who can pass a correlation
// id through _meta can narrow it with ScopeKey.
const DefaultScope = "process"

// shutdownGrace is how long a server gets to answer what is already in flight
// after the client goes away.
const shutdownGrace = 5 * time.Second

// pinProbeID is the request id the gateway uses for its own tools/list. It is
// a string where clients overwhelmingly use integers, and the response is
// consumed here rather than forwarded, so it cannot collide with a real call.
const pinProbeID = `"toolwall/pin-check"`

// pinCheckTimeout bounds how long one call waits for that probe.
const pinCheckTimeout = 10 * time.Second

type Options struct {
	Server   string
	Spec     mcp.ServerSpec
	Config   *policy.Config
	Log      *audit.Log
	Notices  io.Writer
	ScopeKey string
}

type Proxy struct {
	opts Options
	eng  *flow.Engine

	mu     sync.Mutex
	calls  map[string]pending
	lists  map[string]bool
	server *mcp.Conn

	probeOnce sync.Once
	pinsOnce  sync.Once
	pinsReady chan struct{}
}

type pending struct {
	tool  string
	scope string
}

func New(opts Options) *Proxy {
	if opts.Notices == nil {
		opts.Notices = io.Discard
	}
	return &Proxy{
		opts:      opts,
		eng:       flow.New(opts.Config),
		calls:     map[string]pending{},
		lists:     map[string]bool{},
		pinsReady: make(chan struct{}),
	}
}

// Run proxies until one side goes away. in/out are the MCP client's stdio.
func (p *Proxy) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	spec := p.opts.Spec
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = os.Environ()
	for k, v := range spec.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stderr = p.opts.Notices // the server's own diagnostics stay visible

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("proxy: stdin pipe: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("proxy: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("proxy: start %q: %w", spec.Command, err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	client := mcp.NewConn(in, out)
	server := mcp.NewConn(serverOut, serverIn)
	p.mu.Lock()
	p.server = server
	p.mu.Unlock()

	p.opts.Log.Write(audit.Event{Kind: audit.KindSession, Detail: "gateway started, mode " + string(p.opts.Config.Mode)})

	stop := context.AfterFunc(ctx, func() { _ = cmd.Process.Kill() })
	defer stop()

	fromClient := make(chan error, 1)
	fromServer := make(chan error, 1)
	go func() { fromClient <- p.pumpFromClient(client, server) }()
	go func() { fromServer <- p.pumpFromServer(server, client) }()

	select {
	case err := <-fromClient:
		// The client hung up. Close the server's stdin so it shuts down the
		// way it expects to, and keep forwarding until it does: replies to
		// calls already in flight still belong to the client.
		_ = serverIn.Close()
		select {
		case <-fromServer:
		case <-time.After(shutdownGrace):
		}
		return ignoreClose(err)
	case err := <-fromServer:
		return ignoreClose(err)
	}
}

func (p *Proxy) pumpFromClient(client, server *mcp.Conn) error {
	for {
		msg, err := client.Read()
		if err != nil {
			return err
		}
		if msg.IsRequest() && msg.Method == mcp.MethodToolsCall {
			forward, reply := p.screenCall(msg)
			if reply != nil {
				if err := client.Write(reply); err != nil {
					return err
				}
			}
			if !forward {
				continue
			}
		}
		if msg.IsRequest() && msg.Method == mcp.MethodToolsList {
			p.mu.Lock()
			p.lists[string(msg.ID)] = true
			p.mu.Unlock()
		}
		if err := server.Write(msg); err != nil {
			return err
		}
	}
}

func (p *Proxy) pumpFromServer(server, client *mcp.Conn) error {
	for {
		msg, err := server.Read()
		if err != nil {
			return err
		}
		if msg.IsResponse() && string(msg.ID) == pinProbeID {
			// Our own request: check the definitions and keep the answer.
			p.screenToolList(msg)
			p.pinsOnce.Do(func() { close(p.pinsReady) })
			continue
		}
		if msg.IsResponse() {
			p.observeResponse(msg)
		}
		if err := client.Write(msg); err != nil {
			return err
		}
	}
}

// screenCall decides on an outgoing tool call. It returns whether to forward
// it and, when it is refused, the response to hand back to the client.
func (p *Proxy) screenCall(msg *mcp.Message) (bool, *mcp.Message) {
	var params mcp.CallToolParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		// Malformed for us is malformed for the server too; let it answer.
		return true, nil
	}
	if p.eng.NeedsPinCheck(p.opts.Server, params.Name) {
		p.verifyPins(msg.Params)
	}

	scope := p.scopeOf(msg.Params)
	d := p.eng.Decide(scope, p.opts.Server, params.Name, params.Arguments)

	ev := audit.Event{
		Kind:  audit.KindCall,
		Scope: scope,
		Tool:  params.Name,
		Args:  audit.Summarize(params.Arguments, p.opts.Config.Audit.LogArguments),
	}
	if d.Deny {
		ev.Kind = audit.KindDenied
		ev.Decision = &d
	}

	if d.Deny && d.Enforced {
		p.opts.Log.Write(ev)
		fmt.Fprintf(p.opts.Notices, "toolwall: denied %s (%s)\n", params.Name, d.Rule)
		return false, denial(msg.ID, params.Name, d)
	}
	if d.Deny {
		fmt.Fprintf(p.opts.Notices, "toolwall: would deny %s (%s) -- observe mode\n", params.Name, d.Rule)
	}

	// Stain before the call leaves, not when its result returns: see flow.Record.
	ev.Labels = audit.SortedLabels(p.eng.Record(scope, p.opts.Server, params.Name))
	p.opts.Log.Write(ev)
	p.remember(msg.ID, params.Name, scope)
	return true, nil
}

// verifyPins asks the server for its tool list and waits for the answer, so a
// pinned tool is judged against a definition seen in this session rather than
// against whatever the client happened to list earlier -- or never listed.
//
// The probe reuses the triggering request's _meta verbatim. On a modern server
// that carries the protocol version and capabilities the client negotiated, so
// the gateway does not have to guess an era or speak for the client.
func (p *Proxy) verifyPins(params json.RawMessage) {
	p.probeOnce.Do(func() {
		p.mu.Lock()
		server := p.server
		p.mu.Unlock()
		if server == nil {
			p.pinsOnce.Do(func() { close(p.pinsReady) })
			return
		}
		probe := &mcp.Message{
			JSONRPC: "2.0",
			ID:      json.RawMessage(pinProbeID),
			Method:  mcp.MethodToolsList,
			Params:  metaOnly(params),
		}
		if err := server.Write(probe); err != nil {
			p.pinsOnce.Do(func() { close(p.pinsReady) })
		}
	})

	select {
	case <-p.pinsReady:
	case <-time.After(pinCheckTimeout):
		fmt.Fprintln(p.opts.Notices, "toolwall: tool list check timed out; pinned tools stay refused")
	}
}

// metaOnly keeps just the protocol metadata from a request's params.
func metaOnly(params json.RawMessage) json.RawMessage {
	var envelope struct {
		Meta json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &envelope); err != nil || len(envelope.Meta) == 0 {
		return nil
	}
	out, err := json.Marshal(map[string]json.RawMessage{"_meta": envelope.Meta})
	if err != nil {
		return nil
	}
	return out
}

func (p *Proxy) observeResponse(msg *mcp.Message) {
	id := string(msg.ID)

	p.mu.Lock()
	call, isCall := p.calls[id]
	delete(p.calls, id)
	isList := p.lists[id]
	delete(p.lists, id)
	p.mu.Unlock()

	switch {
	case isCall:
		if msg.Error != nil {
			return
		}
		if resultType(msg.Result) == "input_required" {
			return // a round trip for more input, not tool output
		}
		var res mcp.CallToolResult
		_ = json.Unmarshal(msg.Result, &res)
		p.opts.Log.Write(audit.Event{
			Kind: audit.KindResult, Scope: call.scope, Tool: call.tool, IsError: res.IsError,
		})
	case isList:
		p.screenToolList(msg)
	}
}

// screenToolList checks every advertised tool against its pin and drops the
// ones that changed. A poisoned description that never reaches the client
// never reaches the model, which is the only reliable place to stop it.
func (p *Proxy) screenToolList(msg *mcp.Message) {
	if len(msg.Result) == 0 {
		return
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(msg.Result, &envelope); err != nil {
		return
	}
	rawTools, ok := envelope["tools"]
	if !ok {
		return
	}
	var tools []mcp.Tool
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return
	}

	kept := make([]mcp.Tool, 0, len(tools))
	dropped := 0
	for _, t := range tools {
		action, reason := p.eng.CheckPin(p.opts.Server, t)
		if reason != "" {
			p.opts.Log.Write(audit.Event{Kind: audit.KindPin, Tool: t.Name, Detail: reason})
			fmt.Fprintf(p.opts.Notices, "toolwall: %s %s: %s\n", action, t.Name, reason)
		}
		if action == policy.ActionDeny {
			dropped++
			continue
		}
		kept = append(kept, t)
	}
	if dropped == 0 {
		return
	}

	patched, err := json.Marshal(kept)
	if err != nil {
		return
	}
	envelope["tools"] = patched
	if rebuilt, err := json.Marshal(envelope); err == nil {
		msg.Result = rebuilt
	}
}

func (p *Proxy) remember(id json.RawMessage, tool, scope string) {
	p.mu.Lock()
	p.calls[string(id)] = pending{tool: tool, scope: scope}
	p.mu.Unlock()
}

// scopeOf reads the configured correlation key out of the request metadata.
func (p *Proxy) scopeOf(params json.RawMessage) string {
	if p.opts.ScopeKey == "" {
		return DefaultScope
	}
	var envelope struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &envelope); err != nil {
		return DefaultScope
	}
	raw, ok := envelope.Meta[p.opts.ScopeKey]
	if !ok {
		return DefaultScope
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || s == "" {
		return DefaultScope
	}
	return s
}

// denial is what the model gets to read, so it says what happened, why, and
// what not to do next -- an agent that reads "denied" with no reason will
// simply try the same call again with different wording.
func denial(id json.RawMessage, tool string, d flow.Decision) *mcp.Message {
	var b strings.Builder
	fmt.Fprintf(&b, "toolwall denied this call to %q: %s.", tool, d.Reason)
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

func resultType(result json.RawMessage) string {
	var envelope struct {
		ResultType string `json:"resultType"`
	}
	if err := json.Unmarshal(result, &envelope); err != nil {
		return ""
	}
	return envelope.ResultType
}

// ignoreClose swallows the errors that just mean "the other end went away".
func ignoreClose(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, quiet := range []string{"EOF", "file already closed", "broken pipe", "read/write on closed pipe"} {
		if strings.Contains(msg, quiet) {
			return nil
		}
	}
	return err
}
