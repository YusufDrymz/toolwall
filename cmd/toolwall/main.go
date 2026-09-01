// Command toolwall is an information-flow firewall for MCP tool calls.
package main

import (
	"fmt"
	"os"

	"github.com/YusufDrymz/toolwall/internal/mcp"
)

const usage = `toolwall - keep an agent from sending out what it just read

usage:
  toolwall init   --server NAME [--config FILE] (-- COMMAND [ARGS...] | --url URL)
  toolwall verify [--config FILE] [--server NAME]
  toolwall run    --server NAME [--config FILE] [-- COMMAND [ARGS...]]
  toolwall serve  [--config FILE]
  toolwall explain [--config FILE] SERVER.TOOL[=ARGS_JSON] ...
  toolwall audit  [--file FILE] [--scope NAME]
  toolwall version

  init    connect to a server, list what it exposes, write a draft policy
  verify  re-list every server and fail if a reviewed definition changed
  run     front one server; put toolwall in your client config instead of it
  serve   front every server in the policy behind one shared flow scope
  explain simulate a policy against a call sequence, offline, before deploying
  audit   read the decision trail back as a timeline

exit codes: 0 ok, 1 policy violation or drift, 2 usage or runtime error
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	code := 0
	switch os.Args[1] {
	case "init":
		code, err = runInit(os.Args[2:])
	case "verify":
		code, err = runVerify(os.Args[2:])
	case "run":
		code, err = runGateway(os.Args[2:])
	case "serve":
		code, err = runServe(os.Args[2:])
	case "explain":
		code, err = runExplain(os.Args[2:])
	case "audit":
		code, err = runAudit(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("toolwall", mcp.Version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "toolwall: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "toolwall:", err)
		if code == 0 {
			code = 2
		}
	}
	os.Exit(code)
}
