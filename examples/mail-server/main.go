// Command mail-server is a second throwaway MCP server for the multi-server
// demo: a single sink tool, on a different server than the one that reads
// private data. It exists to show that toolwall's flow scope spans servers.
package main

import (
	"encoding/json"
	"os"

	"github.com/YusufDrymz/toolwall/internal/mcp"
)

var tools = []mcp.Tool{
	{
		Name:        "send",
		Description: "Send a message to a recipient",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"to":{"type":"string"},"body":{"type":"string"}},"required":["to"]}`),
	},
}

func main() {
	conn := mcp.NewConn(os.Stdin, os.Stdout)
	for {
		msg, err := conn.Read()
		if err != nil {
			return
		}
		if !msg.IsRequest() {
			continue
		}
		var reply *mcp.Message
		switch msg.Method {
		case mcp.MethodDiscover:
			reply, _ = mcp.Reply(msg.ID, map[string]any{
				"resultType":        "complete",
				"supportedVersions": []string{mcp.ProtocolVersion},
				"capabilities":      map[string]any{"tools": map[string]any{}},
				"_meta":             map[string]any{mcp.MetaServerInfo: mcp.Implementation{Name: "mail-server", Version: "0.1.0"}},
			})
		case mcp.MethodToolsList:
			reply, _ = mcp.Reply(msg.ID, map[string]any{"resultType": "complete", "tools": tools})
		case mcp.MethodToolsCall:
			reply, _ = mcp.Reply(msg.ID, map[string]any{
				"resultType": "complete",
				"content":    []mcp.TextContent{{Type: "text", Text: "sent"}},
			})
		default:
			reply = mcp.Errorf(msg.ID, mcp.CodeMethodNotFound, "unknown method %q", msg.Method)
		}
		if reply != nil {
			if err := conn.Write(reply); err != nil {
				return
			}
		}
	}
}
