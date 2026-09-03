package mcp

import "encoding/json"

// Tool is a tool definition as advertised by a server in tools/list.
//
// Everything in here except Name is model-facing text: the description and the
// schema field descriptions are read by the model and are the payload surface
// for tool poisoning. That is why the lock file fingerprints all of it, not
// just the name.
type Tool struct {
	Name         string          `json:"name"`
	Title        string          `json:"title,omitempty"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

type ToolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// Prompt definitions are injected into the conversation verbatim, so they are
// fingerprinted alongside tools.
type Prompt struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
}

type PromptsListResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

// Resource is a resource definition as advertised by a server. Reading one is
// a data ingress just like a tool result, which is why the flow engine has to
// see it: a file resource can carry exactly the private data a rule is about.
type Resource struct {
	URI         string          `json:"uri"`
	Name        string          `json:"name,omitempty"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	MimeType    string          `json:"mimeType,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

type ResourcesListResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

type ReadResourceParams struct {
	URI string `json:"uri"`
}

type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// CallToolResult carries the tool output that will be fed back to the model.
// Content is left as raw JSON: blocks can be text, image, audio or an embedded
// resource, and toolwall only needs to walk the text ones.
type CallToolResult struct {
	Content           []json.RawMessage `json:"content,omitempty"`
	StructuredContent json.RawMessage   `json:"structuredContent,omitempty"`
	IsError           bool              `json:"isError,omitempty"`
}

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ListParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type InitializeParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
	ClientInfo      Implementation  `json:"clientInfo"`
}

type InitializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
	ServerInfo      Implementation  `json:"serverInfo"`
	Instructions    string          `json:"instructions,omitempty"`
}

type Implementation struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version,omitempty"`
}

// Per-request metadata keys introduced by the 2026-07-28 revision. The
// protocol has no handshake any more: every request restates the version and
// the client capabilities, and the server answers each one independently.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaServerInfo         = "io.modelcontextprotocol/serverInfo"
)

type DiscoverResult struct {
	SupportedVersions []string                   `json:"supportedVersions"`
	Capabilities      json.RawMessage            `json:"capabilities,omitempty"`
	Instructions      string                     `json:"instructions,omitempty"`
	Meta              map[string]json.RawMessage `json:"_meta,omitempty"`
}

// ServerInfo digs the self-reported identity out of a discover result. The
// spec is explicit that this is unverified and must not drive security
// decisions; toolwall only prints it.
func (d DiscoverResult) ServerInfo() Implementation {
	var impl Implementation
	if raw, ok := d.Meta[MetaServerInfo]; ok {
		_ = json.Unmarshal(raw, &impl)
	}
	return impl
}

// UnsupportedVersionData is the payload of a -32022 error.
type UnsupportedVersionData struct {
	Supported []string `json:"supported"`
	Requested string   `json:"requested"`
}
