package mcp

import "context"

// transport carries one message to a server and brings back its answer. The
// client above it does not care whether that means a line on a pipe or an HTTP
// round trip; it only cares that a request gets its matching response and a
// notification gets accepted.
type transport interface {
	// roundTrip sends req and returns the response carrying the same id. For a
	// notification (no id) it returns nil, nil once the server has taken it.
	// Server-initiated requests seen along the way are refused by the
	// transport itself; notifications are dropped.
	roundTrip(ctx context.Context, req *Message) (*Message, error)

	// diagnostics is whatever the transport can add to an error message that
	// the wire itself did not say: a child's stderr, an HTTP status line.
	diagnostics() string

	close() error
}

// versioned transports need to know the negotiated protocol revision after the
// era probe, because Streamable HTTP mirrors it into a header on every request.
type versioned interface {
	setVersion(v string)
}

// sessioned transports keep legacy per-connection state -- the Mcp-Session-Id
// of Streamable HTTP revisions 2025-03-26 through 2025-11-25 -- and are told
// when the legacy handshake has happened so they can start honouring it.
type sessioned interface {
	legacyMode()
}
