package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// ProtocolVersion is the revision toolwall speaks when it talks to a server on
// its own behalf (init, verify). In proxy mode nothing is rewritten: whatever
// the client sends is what the server sees.
const ProtocolVersion = "2026-07-28"

// Era is which dialect a server speaks. The 2026-07-28 revision dropped the
// initialize handshake and made every request self-contained; everything up to
// 2025-11-25 requires a session. Plenty of deployed servers are still legacy,
// so toolwall probes and adapts instead of picking a side.
type Era string

const (
	EraModern Era = "modern"
	EraLegacy Era = "legacy"
)

const (
	defaultCallTimeout = 30 * time.Second
	// The era probe and the legacy fallback both run before we know the server
	// is even alive, so they get short leashes: a server that ignores us must
	// not cost the user half a minute of silence at startup.
	defaultProbeTimeout     = 5 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
)

// ServerSpec is how to start a stdio MCP server.
type ServerSpec struct {
	Command string            `yaml:"command" json:"command"`
	Args    []string          `yaml:"args,omitempty" json:"args,omitempty"`
	Env     map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Dir     string            `yaml:"dir,omitempty" json:"dir,omitempty"`
}

// Client is a synchronous MCP client over a spawned stdio server, used for
// inventory work: list what a server exposes so it can be labelled and pinned.
type Client struct {
	cmd    *exec.Cmd
	conn   *Conn
	stderr *tailBuffer

	incoming chan *Message
	readErr  error
	readOnce sync.Once

	mu     sync.Mutex
	nextID int64

	Era             Era
	ProtocolVersion string
	ServerInfo      Implementation
	Capabilities    json.RawMessage
	Instructions    string
}

// Dial starts the server and works out which protocol era it speaks.
//
// The child inherits the parent environment: MCP servers routinely need PATH,
// HOME and their own credentials, and an inventory taken against a crippled
// server would not describe the server the client actually talks to.
func Dial(ctx context.Context, spec ServerSpec) (*Client, error) {
	if spec.Command == "" {
		return nil, errors.New("mcp: empty command")
	}
	cmd := exec.Command(spec.Command, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = os.Environ()
	for k, v := range spec.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdout pipe: %w", err)
	}
	stderrBuf := &tailBuffer{limit: 4 << 10}
	cmd.Stderr = stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp: start %q: %w", spec.Command, err)
	}

	c := &Client{
		cmd:      cmd,
		conn:     NewConn(stdout, stdin),
		stderr:   stderrBuf,
		incoming: make(chan *Message, 8),
	}
	go c.readLoop()

	// Cancelling the context has to unblock whatever we are waiting on, and
	// killing the child is the only thing that reliably does that.
	stop := context.AfterFunc(ctx, func() { _ = c.kill() })
	defer stop()

	if err := c.detectEra(); err != nil {
		_ = c.kill()
		return nil, err
	}
	return c, nil
}

func (c *Client) readLoop() {
	defer close(c.incoming)
	for {
		msg, err := c.conn.Read()
		if err != nil {
			c.readOnce.Do(func() { c.readErr = err })
			return
		}
		c.incoming <- msg
	}
}

// detectEra follows the stdio backward-compatibility probe from the spec: send
// server/discover, and treat a result or a recognized modern error as proof of
// a modern server. Anything else -- method not found, a silent server, a crash
// -- means legacy, and we retry with the old handshake.
func (c *Client) detectEra() error {
	c.Era = EraModern
	c.ProtocolVersion = ProtocolVersion

	var res DiscoverResult
	err := c.call(defaultProbeTimeout, MethodDiscover, nil, &res)
	switch {
	case err == nil:
		c.ProtocolVersion = pickVersion(res.SupportedVersions)
		c.Capabilities = res.Capabilities
		c.Instructions = res.Instructions
		c.ServerInfo = res.ServerInfo()
		return nil

	case isUnsupportedVersion(err):
		// A modern server that does not speak our revision still identifies
		// itself as modern, and tells us what it does speak.
		var rpcErr *Error
		errors.As(err, &rpcErr)
		var data UnsupportedVersionData
		if len(rpcErr.Data) > 0 {
			_ = json.Unmarshal(rpcErr.Data, &data)
		}
		if len(data.Supported) == 0 {
			return fmt.Errorf("mcp: server rejected protocol %s and offered no alternative", ProtocolVersion)
		}
		c.ProtocolVersion = pickVersion(data.Supported)
		return nil

	default:
		return c.legacyInitialize()
	}
}

func (c *Client) legacyInitialize() error {
	c.Era = EraLegacy
	c.ProtocolVersion = "2025-06-18"

	var res InitializeResult
	params := InitializeParams{
		ProtocolVersion: c.ProtocolVersion,
		Capabilities:    json.RawMessage(`{}`),
		ClientInfo:      clientInfo,
	}
	if err := c.call(defaultHandshakeTimeout, MethodInitialize, params, &res); err != nil {
		return c.annotate(fmt.Errorf("mcp: server speaks neither era: %w", err))
	}
	if res.ProtocolVersion != "" {
		c.ProtocolVersion = res.ProtocolVersion
	}
	c.ServerInfo = res.ServerInfo
	c.Capabilities = res.Capabilities
	c.Instructions = res.Instructions

	raw, err := c.encodeParams(nil)
	if err != nil {
		return err
	}
	return c.conn.Write(&Message{JSONRPC: "2.0", Method: "notifications/initialized", Params: raw})
}

// ListTools walks tools/list to the end of its cursor.
func (c *Client) ListTools() ([]Tool, error) {
	var all []Tool
	cursor := ""
	for {
		var res ToolsListResult
		if err := c.call(defaultCallTimeout, MethodToolsList, ListParams{Cursor: cursor}, &res); err != nil {
			return nil, c.annotate(err)
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" || res.NextCursor == cursor {
			return all, nil
		}
		cursor = res.NextCursor
	}
}

// ListPrompts returns the server's prompts. Prompt text lands in the model's
// context verbatim, so it is inventoried alongside tools. A server without
// prompts answers method-not-found, which is not an error for us.
func (c *Client) ListPrompts() ([]Prompt, error) {
	var all []Prompt
	cursor := ""
	for {
		var res PromptsListResult
		err := c.call(defaultCallTimeout, MethodPromptsList, ListParams{Cursor: cursor}, &res)
		if isMethodNotFound(err) {
			return nil, nil
		}
		if err != nil {
			return nil, c.annotate(err)
		}
		all = append(all, res.Prompts...)
		if res.NextCursor == "" || res.NextCursor == cursor {
			return all, nil
		}
		cursor = res.NextCursor
	}
}

func (c *Client) call(timeout time.Duration, method string, params, out any) error {
	c.mu.Lock()
	c.nextID++
	id := json.RawMessage(strconv.FormatInt(c.nextID, 10))
	c.mu.Unlock()

	raw, err := c.encodeParams(params)
	if err != nil {
		return err
	}
	if err := c.conn.Write(&Message{JSONRPC: "2.0", ID: id, Method: method, Params: raw}); err != nil {
		return err
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case msg, ok := <-c.incoming:
			if !ok {
				if c.readErr != nil {
					return fmt.Errorf("mcp: %s: %w", method, c.readErr)
				}
				return fmt.Errorf("mcp: %s: server closed the connection", method)
			}
			switch {
			case msg.IsResponse() && string(msg.ID) == string(id):
				if msg.Error != nil {
					return msg.Error
				}
				if out == nil || len(msg.Result) == 0 {
					return nil
				}
				if err := json.Unmarshal(msg.Result, out); err != nil {
					return fmt.Errorf("mcp: %s result: %w", method, err)
				}
				return nil
			case msg.IsRequest():
				// Server-initiated round trips are out of scope for inventory
				// work; refuse politely so the server stops waiting on us.
				_ = c.conn.Write(Errorf(msg.ID, CodeMethodNotFound, "toolwall does not handle %s", msg.Method))
			}
			// Notifications and stale responses are ignored.
		case <-deadline.C:
			return fmt.Errorf("mcp: %s: timed out after %s", method, timeout)
		}
	}
}

// encodeParams marshals params and, on a modern server, attaches the
// per-request metadata the revision requires on every single request.
func (c *Client) encodeParams(params any) (json.RawMessage, error) {
	fields := map[string]json.RawMessage{}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("mcp: marshal params: %w", err)
		}
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("mcp: params must be an object: %w", err)
		}
	}
	if c.Era == EraModern {
		meta, err := json.Marshal(map[string]any{
			MetaProtocolVersion:    c.ProtocolVersion,
			MetaClientInfo:         clientInfo,
			MetaClientCapabilities: map[string]any{},
		})
		if err != nil {
			return nil, fmt.Errorf("mcp: marshal _meta: %w", err)
		}
		fields["_meta"] = meta
	}
	if len(fields) == 0 {
		return nil, nil
	}
	return json.Marshal(fields)
}

// annotate decorates a failure with whatever the server printed on stderr,
// which is usually the only clue about why it died.
func (c *Client) annotate(err error) error {
	if tail := c.stderr.String(); tail != "" {
		return fmt.Errorf("%w (server stderr: %s)", err, tail)
	}
	return err
}

func (c *Client) Close() error { return c.kill() }

func (c *Client) kill() error {
	if c.cmd.Process == nil {
		return nil
	}
	_ = c.cmd.Process.Kill()
	_, err := c.cmd.Process.Wait()
	return err
}

var clientInfo = Implementation{Name: "toolwall", Version: Version}

// pickVersion prefers the revision we implement and otherwise takes the newest
// on offer -- revisions are dates, so lexical order is chronological order.
func pickVersion(supported []string) string {
	best := ""
	for _, v := range supported {
		if v == ProtocolVersion {
			return v
		}
		if v > best {
			best = v
		}
	}
	if best == "" {
		return ProtocolVersion
	}
	return best
}

func isUnsupportedVersion(err error) bool { return rpcCode(err) == CodeUnsupportedProtocolVersion }
func isMethodNotFound(err error) bool     { return rpcCode(err) == CodeMethodNotFound }

func rpcCode(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

// tailBuffer keeps only the last limit bytes written to it.
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		t.buf = t.buf[len(t.buf)-t.limit:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(trimSpace(t.buf))
}
