// Command http-server is a throwaway Streamable HTTP MCP server for trying
// toolwall's serve command against a remote-style upstream. It listens on
// localhost, answers server/discover, tools/list and tools/call, and exposes
// one tool that reads private data.
//
// Nothing here is production MCP -- it is the smallest thing that speaks the
// 2026-07-28 wire well enough to demonstrate the gateway across transports.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/YusufDrymz/toolwall/internal/mcp"
)

var tools = []mcp.Tool{
	{
		Name:        "read_record",
		Description: "Read an employee record",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`),
	},
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8848", "listen address")
	flag.Parse()

	http.HandleFunc("/mcp", handle)
	fmt.Fprintf(os.Stderr, "http-server: listening on http://%s/mcp\n", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, "http-server:", err)
		os.Exit(1)
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var msg mcp.Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch msg.Method {
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case mcp.MethodDiscover:
		writeJSON(w, msg.ID, map[string]any{
			"resultType":        "complete",
			"supportedVersions": []string{mcp.ProtocolVersion},
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"_meta":             map[string]any{mcp.MetaServerInfo: mcp.Implementation{Name: "http-server", Version: "0.1.0"}},
		})
	case mcp.MethodToolsList:
		writeJSON(w, msg.ID, map[string]any{"resultType": "complete", "tools": tools})
	case mcp.MethodToolsCall:
		writeJSON(w, msg.ID, map[string]any{
			"resultType": "complete",
			"content":    []mcp.TextContent{{Type: "text", Text: "Q3 salary review: 14 people, total 2.4M TRY."}},
		})
	default:
		writeErr(w, msg.ID)
	}
}

func writeJSON(w http.ResponseWriter, id json.RawMessage, result any) {
	msg, err := mcp.Reply(id, result)
	if err != nil {
		writeErr(w, id)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(msg)
}

func writeErr(w http.ResponseWriter, id json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(mcp.Errorf(id, mcp.CodeMethodNotFound, "unknown method"))
}
