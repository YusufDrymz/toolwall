// Package fakemcp is a scriptable MCP server used by toolwall's own tests.
//
// It exists because the interesting cases -- a legacy server that has never
// heard of server/discover, a modern one that rejects a request with no _meta,
// a tool that returns attacker text -- are awkward to reproduce with a real
// server and impossible to reproduce in CI without network access.
package fakemcp

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/YusufDrymz/toolwall/internal/mcp"
)

// envConfig carries the server script to the child process. Tests spawn the
// test binary itself, so the configuration has to survive an exec.
const envConfig = "TOOLWALL_FAKE_MCP"

type Config struct {
	Name string `json:"name"`
	// Era is "modern" (2026-07-28, no handshake), "legacy" (initialize) or
	// "silent" (answers nothing, like a server that hangs on startup).
	Era               string            `json:"era"`
	SupportedVersions []string          `json:"supportedVersions,omitempty"`
	Tools             []mcp.Tool        `json:"tools,omitempty"`
	Prompts           []mcp.Prompt      `json:"prompts,omitempty"`
	Resources         []mcp.Resource    `json:"resources,omitempty"`
	Results           map[string]string `json:"results,omitempty"`
	// NeedsInput names tools that answer the first call with an
	// InputRequiredResult and only complete once the retry carries the
	// matching inputResponses and requestState back.
	NeedsInput []string `json:"needsInput,omitempty"`
	// StrictMeta makes a modern server reject requests without the required
	// per-request metadata, the way the spec says it must.
	StrictMeta bool `json:"strictMeta,omitempty"`
}

// Spec returns the ServerSpec that starts this configuration as a child of the
// current test binary. The package under test must call RunIfChild from
// TestMain for this to work.
func Spec(cfg Config) (mcp.ServerSpec, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return mcp.ServerSpec{}, err
	}
	return mcp.ServerSpec{
		Command: os.Args[0],
		Env:     map[string]string{envConfig: string(raw)},
	}, nil
}

// RunIfChild serves stdio and exits when the process was started by Spec.
// Call it first thing in TestMain.
func RunIfChild() {
	raw := os.Getenv(envConfig)
	if raw == "" {
		return
	}
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "fakemcp: bad config:", err)
		os.Exit(2)
	}
	Serve(cfg)
	os.Exit(0)
}

// Serve runs the fake server on stdin/stdout until the stream closes.
func Serve(cfg Config) {
	conn := mcp.NewConn(os.Stdin, os.Stdout)
	for {
		msg, err := conn.Read()
		if err != nil {
			return
		}
		if cfg.Era == "silent" {
			continue // reads, never answers: the caller's timeout has to save it
		}
		if !msg.IsRequest() {
			continue
		}
		if reply := cfg.handle(msg); reply != nil {
			if err := conn.Write(reply); err != nil {
				return
			}
		}
	}
}

func (cfg Config) handle(msg *mcp.Message) *mcp.Message {
	modern := cfg.Era == "modern"

	if modern && cfg.StrictMeta && msg.Method != mcp.MethodInitialize && !hasProtocolMeta(msg.Params) {
		return mcp.Errorf(msg.ID, mcp.CodeInvalidParams, "missing required _meta fields")
	}

	switch msg.Method {
	case mcp.MethodDiscover:
		if !modern {
			return mcp.Errorf(msg.ID, mcp.CodeMethodNotFound, "unknown method %s", msg.Method)
		}
		versions := cfg.SupportedVersions
		if len(versions) == 0 {
			versions = []string{mcp.ProtocolVersion}
		}
		if !contains(versions, mcp.ProtocolVersion) {
			return &mcp.Message{
				JSONRPC: "2.0", ID: msg.ID,
				Error: &mcp.Error{
					Code:    mcp.CodeUnsupportedProtocolVersion,
					Message: "Unsupported protocol version",
					Data:    raw(mcp.UnsupportedVersionData{Supported: versions, Requested: mcp.ProtocolVersion}),
				},
			}
		}
		return cfg.reply(msg.ID, map[string]any{
			"resultType":        "complete",
			"supportedVersions": versions,
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"_meta":             map[string]any{mcp.MetaServerInfo: mcp.Implementation{Name: cfg.Name, Version: "1.0.0"}},
		})

	case mcp.MethodInitialize:
		if modern {
			return mcp.Errorf(msg.ID, mcp.CodeMethodNotFound, "this server is stateless; use server/discover")
		}
		return cfg.reply(msg.ID, mcp.InitializeResult{
			ProtocolVersion: "2025-06-18",
			Capabilities:    json.RawMessage(`{"tools":{}}`),
			ServerInfo:      mcp.Implementation{Name: cfg.Name, Version: "1.0.0"},
		})

	case mcp.MethodToolsList:
		res := map[string]any{"tools": cfg.Tools}
		if modern {
			res["resultType"] = "complete"
		}
		return cfg.reply(msg.ID, res)

	case mcp.MethodPromptsList:
		if len(cfg.Prompts) == 0 {
			return mcp.Errorf(msg.ID, mcp.CodeMethodNotFound, "no prompts here")
		}
		return cfg.reply(msg.ID, map[string]any{"prompts": cfg.Prompts})

	case mcp.MethodResourcesLst:
		if len(cfg.Resources) == 0 {
			return mcp.Errorf(msg.ID, mcp.CodeMethodNotFound, "no resources here")
		}
		return cfg.reply(msg.ID, map[string]any{"resultType": "complete", "resources": cfg.Resources})

	case mcp.MethodResourcesRead:
		var params mcp.ReadResourceParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return mcp.Errorf(msg.ID, mcp.CodeInvalidParams, "bad params")
		}
		return cfg.reply(msg.ID, map[string]any{
			"resultType": "complete",
			"contents": []map[string]any{{
				"uri": params.URI, "mimeType": "text/plain",
				"text": "contents of " + params.URI,
			}},
		})

	case mcp.MethodPromptsGet:
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return mcp.Errorf(msg.ID, mcp.CodeInvalidParams, "bad params")
		}
		for _, p := range cfg.Prompts {
			if p.Name == params.Name {
				return cfg.reply(msg.ID, map[string]any{
					"resultType": "complete",
					"messages": []map[string]any{{
						"role":    "user",
						"content": mcp.TextContent{Type: "text", Text: "prompt " + p.Name + " from " + cfg.Name},
					}},
				})
			}
		}
		return mcp.Errorf(msg.ID, mcp.CodeInvalidParams, "unknown prompt %q", params.Name)

	case mcp.MethodToolsCall:
		var params mcp.CallToolParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return mcp.Errorf(msg.ID, mcp.CodeInvalidParams, "bad params")
		}
		if contains(cfg.NeedsInput, params.Name) {
			var retry struct {
				InputResponses map[string]json.RawMessage `json:"inputResponses"`
				RequestState   string                     `json:"requestState"`
			}
			_ = json.Unmarshal(msg.Params, &retry)
			if len(retry.InputResponses) == 0 || retry.RequestState != "state-1" {
				return cfg.reply(msg.ID, map[string]any{
					"resultType":    "input_required",
					"inputRequests": map[string]any{"who": map[string]any{"method": "elicitation/create"}},
					"requestState":  "state-1",
				})
			}
			return cfg.reply(msg.ID, map[string]any{
				"resultType": "complete",
				"content":    []mcp.TextContent{{Type: "text", Text: "completed with input"}},
			})
		}

		text, ok := cfg.Results[params.Name]
		if !ok {
			text = "ok"
		}
		res := map[string]any{"content": []mcp.TextContent{{Type: "text", Text: text}}}
		if modern {
			res["resultType"] = "complete"
		}
		return cfg.reply(msg.ID, res)
	}
	return mcp.Errorf(msg.ID, mcp.CodeMethodNotFound, "unknown method %s", msg.Method)
}

func (cfg Config) reply(id json.RawMessage, result any) *mcp.Message {
	m, err := mcp.Reply(id, result)
	if err != nil {
		return mcp.Errorf(id, mcp.CodeInternalError, "%v", err)
	}
	return m
}

func hasProtocolMeta(params json.RawMessage) bool {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return false
	}
	_, ok := p.Meta[mcp.MetaProtocolVersion]
	return ok
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func raw(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
