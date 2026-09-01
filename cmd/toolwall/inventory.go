package main

import (
	"context"
	"fmt"
	"time"

	"github.com/YusufDrymz/toolwall/internal/mcp"
)

const dialTimeout = 60 * time.Second

type inventory struct {
	era     mcp.Era
	version string
	info    mcp.Implementation
	tools   []mcp.Tool
	prompts []mcp.Prompt
}

// take starts the server, asks it what it exposes and shuts it down again.
func take(spec mcp.ServerSpec) (inventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	c, err := mcp.Dial(ctx, spec)
	if err != nil {
		return inventory{}, err
	}
	defer func() { _ = c.Close() }()

	tools, err := c.ListTools()
	if err != nil {
		return inventory{}, fmt.Errorf("list tools: %w", err)
	}
	prompts, err := c.ListPrompts()
	if err != nil {
		return inventory{}, fmt.Errorf("list prompts: %w", err)
	}
	return inventory{
		era:     c.Era,
		version: c.ProtocolVersion,
		info:    c.ServerInfo,
		tools:   tools,
		prompts: prompts,
	}, nil
}
