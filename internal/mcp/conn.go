package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MaxMessageBytes caps a single JSON-RPC line. The stdio transport is
// newline-delimited with no length prefix, so without a cap a hostile or
// runaway server can grow the reader until the gateway dies. 16 MiB is far
// above any legitimate tool result we have seen.
const MaxMessageBytes = 16 << 20

// ErrMessageTooLarge is returned when a line exceeds MaxMessageBytes. The
// connection is unusable afterwards: the rest of the oversized line is still
// in the stream and would be read as garbage.
var ErrMessageTooLarge = errors.New("mcp: message exceeds size limit")

// Conn is one end of a newline-delimited JSON-RPC stream.
//
// Reads are single-threaded by contract (one pump goroutine per direction);
// writes are not, because a denial has to be written by the pump handling the
// other direction, so Write holds a mutex.
type Conn struct {
	r  *bufio.Reader
	w  io.Writer
	mu sync.Mutex
}

func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{r: bufio.NewReaderSize(r, 64<<10), w: w}
}

// Read returns the next message. Blank lines are skipped: some servers flush a
// stray newline on startup and that should not look like a parse error.
func (c *Conn) Read() (*Message, error) {
	for {
		line, err := c.readLine()
		if err != nil {
			return nil, err
		}
		if len(trimSpace(line)) == 0 {
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, fmt.Errorf("mcp: decode: %w", err)
		}
		return &m, nil
	}
}

func (c *Conn) Write(m *Message) error {
	if m.JSONRPC == "" {
		m.JSONRPC = "2.0"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("mcp: encode: %w", err)
	}
	b = append(b, '\n')

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(b); err != nil {
		return fmt.Errorf("mcp: write: %w", err)
	}
	if f, ok := c.w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// readLine reads one newline-terminated line, enforcing MaxMessageBytes.
// bufio.Scanner is avoided on purpose: its default 64 KiB token limit silently
// truncates real tool results.
func (c *Conn) readLine() ([]byte, error) {
	var buf []byte
	for {
		chunk, err := c.r.ReadSlice('\n')
		if len(buf)+len(chunk) > MaxMessageBytes {
			return nil, ErrMessageTooLarge
		}
		buf = append(buf, chunk...)
		if err == nil {
			return buf, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) && len(buf) > 0 {
			return buf, nil // last line without a trailing newline
		}
		return nil, err
	}
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
