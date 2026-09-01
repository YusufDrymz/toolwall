package mcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
)

// stdioTransport is a spawned child speaking newline-delimited JSON-RPC on its
// stdin and stdout.
type stdioTransport struct {
	cmd    *exec.Cmd
	conn   *Conn
	stderr *tailBuffer

	incoming chan *Message
	readErr  error
	readOnce sync.Once
}

// startStdio launches the server. The child inherits the parent environment:
// MCP servers routinely need PATH, HOME and their own credentials, and an
// inventory taken against a crippled server would not describe the server the
// client actually talks to.
func startStdio(spec ServerSpec) (*stdioTransport, error) {
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

	t := &stdioTransport{
		cmd:      cmd,
		conn:     NewConn(stdout, stdin),
		stderr:   stderrBuf,
		incoming: make(chan *Message, 8),
	}
	go t.readLoop()
	return t, nil
}

func (t *stdioTransport) readLoop() {
	defer close(t.incoming)
	for {
		msg, err := t.conn.Read()
		if err != nil {
			t.readOnce.Do(func() { t.readErr = err })
			return
		}
		t.incoming <- msg
	}
}

func (t *stdioTransport) roundTrip(ctx context.Context, req *Message) (*Message, error) {
	if err := t.conn.Write(req); err != nil {
		return nil, err
	}
	if req.IsNotification() {
		return nil, nil
	}

	for {
		select {
		case msg, ok := <-t.incoming:
			if !ok {
				if t.readErr != nil {
					return nil, t.readErr
				}
				return nil, fmt.Errorf("server closed the connection")
			}
			switch {
			case msg.IsResponse() && string(msg.ID) == string(req.ID):
				return msg, nil
			case msg.IsRequest():
				// Server-initiated round trips are out of scope for a client
				// that only does inventory and forwarding; refuse politely so
				// the server stops waiting on us.
				_ = t.conn.Write(Errorf(msg.ID, CodeMethodNotFound, "toolwall does not handle %s", msg.Method))
			}
			// Notifications and stale responses are ignored.
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (t *stdioTransport) diagnostics() string {
	if tail := t.stderr.String(); tail != "" {
		return "server stderr: " + tail
	}
	return ""
}

func (t *stdioTransport) close() error {
	if t.cmd.Process == nil {
		return nil
	}
	_ = t.cmd.Process.Kill()
	_, err := t.cmd.Process.Wait()
	return err
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
