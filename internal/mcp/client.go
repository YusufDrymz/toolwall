package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// ProtocolVersion is the revision toolwall speaks when it talks to a server on
// its own behalf (init, verify, serve). In proxy mode nothing is rewritten:
// whatever the client sends is what the server sees.
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

// ServerSpec is how to reach an MCP server: a command to spawn on stdio, or a
// URL to POST to over Streamable HTTP. Exactly one of Command and URL is set.
type ServerSpec struct {
	Command string            `yaml:"command,omitempty" json:"command,omitempty"`
	Args    []string          `yaml:"args,omitempty" json:"args,omitempty"`
	Env     map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Dir     string            `yaml:"dir,omitempty" json:"dir,omitempty"`

	URL string `yaml:"url,omitempty" json:"url,omitempty"`
	// Headers are sent on every request; values may reference the environment
	// as ${NAME} so a committed policy never has to hold a credential.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	// Insecure permits plain http:// to a host other than loopback. Off by
	// default: a bearer token on the wire in clear is the kind of mistake a
	// security tool should refuse to make quietly.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty"`
}

func (s ServerSpec) IsHTTP() bool { return s.URL != "" }

// Validate rejects a spec that is neither or both transports.
func (s ServerSpec) Validate() error {
	switch {
	case s.Command == "" && s.URL == "":
		return errors.New("server needs a command or a url")
	case s.Command != "" && s.URL != "":
		return errors.New("server has both a command and a url; pick one")
	case s.URL == "" && (len(s.Headers) > 0 || s.Insecure):
		return errors.New("headers and insecure only apply to a url server")
	}
	return nil
}

// Client is a synchronous MCP client used for inventory work and for the
// gateway's upstream calls. One call at a time.
type Client struct {
	t    transport
	http bool

	mu      sync.Mutex
	nextID  int64
	schemas map[string]json.RawMessage // tool name -> inputSchema, for header mirroring
	warns   []string

	Era             Era
	ProtocolVersion string
	ServerInfo      Implementation
	Capabilities    json.RawMessage
	Instructions    string
}

// Dial connects to the server and works out which protocol era it speaks.
func Dial(ctx context.Context, spec ServerSpec) (*Client, error) {
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("mcp: %w", err)
	}

	c := &Client{schemas: map[string]json.RawMessage{}}
	var err error
	if spec.IsHTTP() {
		c.http = true
		c.t, err = startHTTP(spec, c.schemaFor)
	} else {
		c.t, err = startStdio(spec)
	}
	if err != nil {
		return nil, err
	}

	// Cancelling the context has to unblock whatever we are waiting on, and
	// tearing the transport down is the only thing that reliably does that.
	stop := context.AfterFunc(ctx, func() { _ = c.t.close() })
	defer stop()

	if err := c.detectEra(); err != nil {
		_ = c.t.close()
		return nil, err
	}
	return c, nil
}

// detectEra follows the spec's backward-compatibility probe: send
// server/discover and treat a result or a recognized modern error as proof of
// a modern server. Anything else means legacy, and we retry with the old
// handshake -- except an HTTP failure that is clearly not an era question
// (auth, a dead server), which is reported as is instead of being buried
// under a second, equally doomed attempt.
func (c *Client) detectEra() error {
	c.Era = EraModern
	c.ProtocolVersion = ProtocolVersion
	c.syncVersion()

	var res DiscoverResult
	err := c.call(defaultProbeTimeout, MethodDiscover, nil, &res)
	switch {
	case err == nil:
		c.ProtocolVersion = pickVersion(res.SupportedVersions)
		c.syncVersion()
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
		c.syncVersion()
		return nil

	case c.http && isModernHTTPSignal(err):
		// HeaderMismatch, a missing capability, or 404 + method-not-found: the
		// server is modern and simply did not like or offer server/discover.
		return nil

	case c.http && !isLegacyHTTPSignal(err):
		return c.annotate(fmt.Errorf("mcp: %w", err))

	default:
		return c.legacyInitialize()
	}
}

func (c *Client) legacyInitialize() error {
	c.Era = EraLegacy
	c.ProtocolVersion = "2025-06-18"
	c.syncVersion()

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
		c.syncVersion()
	}
	c.ServerInfo = res.ServerInfo
	c.Capabilities = res.Capabilities
	c.Instructions = res.Instructions

	if s, ok := c.t.(sessioned); ok {
		s.legacyMode()
	}

	raw, err := c.encodeParams(nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultHandshakeTimeout)
	defer cancel()
	_, err = c.t.roundTrip(ctx, &Message{JSONRPC: "2.0", Method: "notifications/initialized", Params: raw})
	return err
}

// CallRaw sends one request with raw params and hands back the raw result.
// The aggregating gateway uses it to forward a client's tool call to the right
// upstream: rpc errors come back as *Error so they can be relayed unchanged,
// and the per-request protocol metadata is refilled by the client, so toolwall
// speaks to the upstream as itself rather than replaying the caller's _meta.
func (c *Client) CallRaw(method string, params json.RawMessage) (json.RawMessage, error) {
	var p any
	if len(params) > 0 {
		p = params
	}

	if c.http && method == MethodToolsCall {
		// Streamable HTTP clients must mirror x-mcp-header parameters into
		// headers, and that needs the tool's schema. Make sure we have it.
		if name := nameIn(params); name != "" && c.schemaFor(name) == nil {
			if _, err := c.ListTools(); err != nil {
				return nil, err
			}
		}
	}

	var out json.RawMessage
	err := c.call(defaultCallTimeout, method, p, &out)
	if c.http && method == MethodToolsCall && rpcCode(err) == CodeHeaderMismatch {
		// The spec's prescribed recovery: the schema moved under us, so list
		// again and retry once with the headers the server now expects.
		if _, lerr := c.ListTools(); lerr == nil {
			out = nil
			err = c.call(defaultCallTimeout, method, p, &out)
		}
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListTools walks tools/list to the end of its cursor. Over Streamable HTTP it
// also drops any tool whose x-mcp-header annotations are invalid, as the
// transport spec requires of clients, and remembers each schema so calls can
// mirror the right headers.
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
			break
		}
		cursor = res.NextCursor
	}
	if !c.http {
		return all, nil
	}

	kept := make([]Tool, 0, len(all))
	schemas := make(map[string]json.RawMessage, len(all))
	for _, t := range all {
		if _, err := headerAnnotations(t.InputSchema); err != nil {
			c.warn(fmt.Sprintf("tool %q dropped: %v", t.Name, err))
			continue
		}
		schemas[t.Name] = t.InputSchema
		kept = append(kept, t)
	}
	c.mu.Lock()
	c.schemas = schemas
	c.mu.Unlock()
	return kept, nil
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

// Warnings are things the client decided on the operator's behalf and wants
// them to know about, such as a tool dropped for a malformed header annotation.
func (c *Client) Warnings() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.warns...)
}

func (c *Client) warn(s string) {
	c.mu.Lock()
	c.warns = append(c.warns, s)
	c.mu.Unlock()
}

func (c *Client) schemaFor(tool string) json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.schemas[tool]
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

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	msg, err := c.t.roundTrip(ctx, &Message{JSONRPC: "2.0", ID: id, Method: method, Params: raw})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("mcp: %s: timed out after %s", method, timeout)
		}
		var rpc *Error
		if errors.As(err, &rpc) {
			return err // keep the wrapping; callers use errors.As
		}
		return fmt.Errorf("mcp: %s: %w", method, err)
	}
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

func (c *Client) syncVersion() {
	if v, ok := c.t.(versioned); ok {
		v.setVersion(c.ProtocolVersion)
	}
}

// annotate decorates a failure with whatever the transport knows that the
// wire did not say -- usually the only clue about why a server died.
func (c *Client) annotate(err error) error {
	if d := c.t.diagnostics(); d != "" {
		return fmt.Errorf("%w (%s)", err, d)
	}
	return err
}

func (c *Client) Close() error { return c.t.close() }

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

// isModernHTTPSignal is the transport spec's list of 4xx bodies that identify
// a modern server: the reserved 2026-07-28 error codes, or a 404 carrying
// method-not-found (a modern server that lacks the method, as opposed to a
// legacy server that lacks the endpoint).
func isModernHTTPSignal(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) || he.RPC == nil {
		return false
	}
	switch he.RPC.Code {
	case CodeHeaderMismatch, CodeMissingRequiredClientCapability, CodeUnsupportedProtocolVersion:
		return true
	case CodeMethodNotFound:
		return he.Status == 404
	}
	return false
}

// isLegacyHTTPSignal is a 400/404/405 whose body is empty or not a recognized
// modern error: the response a pre-2026 Streamable HTTP server gives to a
// request it does not understand.
func isLegacyHTTPSignal(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) {
		return false
	}
	switch he.Status {
	case 400, 404, 405:
		return !isModernHTTPSignal(err)
	}
	return false
}

func rpcCode(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

// nameIn pulls params.name out of raw call params, for the schema lookup.
func nameIn(params json.RawMessage) string {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Name
}
