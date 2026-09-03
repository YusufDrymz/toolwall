// Package mcp implements just enough of the Model Context Protocol to sit in
// the middle of a session: JSON-RPC framing over the stdio transport, plus the
// handful of result shapes toolwall actually inspects.
//
// Everything else passes through untouched. A proxy that fully parses a
// protocol it does not control breaks the day the protocol grows a field, so
// params and results stay as raw JSON unless there is a reason to look inside.
package mcp

import (
	"encoding/json"
	"fmt"
)

// Message is a JSON-RPC 2.0 request, response or notification. Which one it is
// depends on the fields present; see the Is* helpers.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// JSON-RPC reserved codes we produce. Tool calls denied by policy are answered
// with InvalidRequest rather than a transport error: the client should see a
// well-formed refusal, not a broken session.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Codes defined by the 2026-07-28 revision. UnsupportedProtocolVersion is the
// one that matters most here: it is a positive signal that the peer is a
// modern server, which is what the era probe keys on.
const (
	CodeHeaderMismatch                  = -32020
	CodeMissingRequiredClientCapability = -32021
	CodeUnsupportedProtocolVersion      = -32022
)

// MCP methods toolwall reacts to. Anything not listed here is forwarded as-is.
const (
	MethodDiscover      = "server/discover"
	MethodInitialize    = "initialize"
	MethodToolsList     = "tools/list"
	MethodToolsCall     = "tools/call"
	MethodPromptsList   = "prompts/list"
	MethodPromptsGet    = "prompts/get"
	MethodResourcesLst  = "resources/list"
	MethodResourcesRead = "resources/read"
)

func (m *Message) IsRequest() bool      { return m.Method != "" && len(m.ID) > 0 }
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }
func (m *Message) IsResponse() bool     { return m.Method == "" && len(m.ID) > 0 }

// Errorf builds an error response for the given request id.
func Errorf(id json.RawMessage, code int, format string, args ...any) *Message {
	return &Message{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &Error{Code: code, Message: fmt.Sprintf(format, args...)},
	}
}

// Reply builds a success response carrying result for the given request id.
func Reply(id json.RawMessage, result any) (*Message, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return &Message{JSONRPC: "2.0", ID: id, Result: raw}, nil
}
