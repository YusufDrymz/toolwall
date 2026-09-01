package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// httpTransport speaks Streamable HTTP: one POST per message, the answer
// either a single JSON object or an SSE stream that ends with it.
//
// The 2026-07-28 revision removed sessions and the GET stream, so a modern
// exchange is entirely stateless. Servers from 2025-03-26 through 2025-11-25
// hand out an Mcp-Session-Id on initialize and expect it back on every request;
// the transport honours that only after the client has fallen back to the
// legacy handshake.
type httpTransport struct {
	endpoint  string
	headers   map[string]string
	client    *http.Client
	schemaFor func(tool string) json.RawMessage

	mu         sync.Mutex
	version    string
	legacy     bool
	sessionID  string
	lastStatus string
}

// HTTPError is a non-2xx answer. RPC is set when the body was a JSON-RPC error,
// which is how the era probe tells a modern server's refusal from a legacy
// server's confusion.
type HTTPError struct {
	Status int
	Body   string
	RPC    *Error
}

func (e *HTTPError) Error() string {
	if e.RPC != nil {
		return fmt.Sprintf("http %d: %v", e.Status, e.RPC)
	}
	body := strings.TrimSpace(e.Body)
	if len(body) > 200 {
		body = body[:200] + "..."
	}
	if body == "" {
		return fmt.Sprintf("http %d", e.Status)
	}
	return fmt.Sprintf("http %d: %s", e.Status, body)
}

func (e *HTTPError) Unwrap() error {
	if e.RPC != nil {
		return e.RPC
	}
	return nil
}

const (
	maxErrorBody = 64 << 10
	// A refused server-initiated request on a legacy stream is answered with
	// its own short POST; it must not hold the real call hostage.
	refuseTimeout = 3 * time.Second
)

func startHTTP(spec ServerSpec, schemaFor func(string) json.RawMessage) (*httpTransport, error) {
	u, err := url.Parse(spec.URL)
	if err != nil {
		return nil, fmt.Errorf("mcp: url: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !spec.Insecure && !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("mcp: refusing plain http to %s; use https, or set insecure: true if you accept credentials on the wire in clear", u.Host)
		}
	default:
		return nil, fmt.Errorf("mcp: url scheme %q is not http or https", u.Scheme)
	}

	headers, err := expandHeaders(spec.Headers)
	if err != nil {
		return nil, err
	}

	return &httpTransport{
		endpoint:  spec.URL,
		headers:   headers,
		schemaFor: schemaFor,
		client: &http.Client{
			// An MCP endpoint is given exactly; following a redirect could carry
			// a credential to a host the operator never named.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// expandHeaders resolves ${NAME} references. A reference to an unset variable
// is an error rather than an empty string: silently sending "Bearer " is worse
// than not starting.
func expandHeaders(in map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for k, v := range in {
		var missing []string
		expanded := os.Expand(v, func(name string) string {
			val, ok := os.LookupEnv(name)
			if !ok || val == "" {
				missing = append(missing, name)
			}
			return val
		})
		if len(missing) > 0 {
			return nil, fmt.Errorf("mcp: header %s references unset environment variable(s) %s", k, strings.Join(missing, ", "))
		}
		out[k] = expanded
	}
	return out, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (t *httpTransport) setVersion(v string) {
	t.mu.Lock()
	t.version = v
	t.mu.Unlock()
}

func (t *httpTransport) legacyMode() {
	t.mu.Lock()
	t.legacy = true
	t.mu.Unlock()
}

func (t *httpTransport) roundTrip(ctx context.Context, req *Message) (*Message, error) {
	resp, err := t.post(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	t.mu.Lock()
	t.lastStatus = resp.Status
	if req.Method == MethodInitialize {
		if sid := resp.Header.Get(headerSessionID); sid != "" {
			t.sessionID = sid
		}
	}
	t.mu.Unlock()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, readHTTPError(resp)
	}
	if req.IsNotification() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		return nil, nil
	}

	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch ct {
	case "application/json":
		var msg Message
		if err := json.NewDecoder(io.LimitReader(resp.Body, MaxMessageBytes)).Decode(&msg); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		if !msg.IsResponse() || string(msg.ID) != string(req.ID) {
			return nil, fmt.Errorf("response id does not match request")
		}
		return &msg, nil
	case "text/event-stream":
		return t.readStream(ctx, resp.Body, req.ID)
	default:
		return nil, fmt.Errorf("unexpected content type %q", resp.Header.Get("Content-Type"))
	}
}

func (t *httpTransport) post(ctx context.Context, msg *Message) (*http.Response, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	version, legacy, session := t.version, t.legacy, t.sessionID
	t.mu.Unlock()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if version != "" {
		req.Header.Set(headerProtocolVersion, version)
	}
	if msg.Method != "" {
		req.Header.Set(headerMethod, msg.Method)
		if name := mcpName(msg.Method, msg.Params); name != "" {
			req.Header.Set(headerName, encodeHeaderValue(name))
		}
		if msg.Method == MethodToolsCall && t.schemaFor != nil {
			var p CallToolParams
			if json.Unmarshal(msg.Params, &p) == nil {
				for k, v := range mirrorHeaders(t.schemaFor(p.Name), p.Arguments) {
					req.Header.Set(k, v)
				}
			}
		}
	}
	if legacy && session != "" {
		req.Header.Set(headerSessionID, session)
	}
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
	return resp, nil
}

// readStream consumes an SSE response stream until the message answering id
// arrives. Notifications along the way are dropped; on a legacy server a
// request from the server side is refused with its own POST, since that
// revision let servers ask things over the stream.
func (t *httpTransport) readStream(ctx context.Context, body io.Reader, id json.RawMessage) (*Message, error) {
	r := bufio.NewReaderSize(body, 64<<10)
	var data []byte
	dispatch := func() (*Message, bool, error) {
		if len(data) == 0 {
			return nil, false, nil
		}
		var msg Message
		err := json.Unmarshal(data, &msg)
		data = data[:0]
		if err != nil {
			return nil, false, nil // not JSON-RPC; a comment-like event, skip it
		}
		switch {
		case msg.IsResponse() && string(msg.ID) == string(id):
			return &msg, true, nil
		case msg.IsRequest():
			t.refuse(msg)
		}
		return nil, false, nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimRight(line, "\r\n")
			switch {
			case len(line) == 0:
				if msg, done, derr := dispatch(); done || derr != nil {
					return msg, derr
				}
			case line[0] == ':':
				// keep-alive comment
			case bytes.HasPrefix(line, []byte("data:")):
				chunk := bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" "))
				if len(data) > 0 {
					data = append(data, '\n')
				}
				data = append(data, chunk...)
				if len(data) > MaxMessageBytes {
					return nil, ErrMessageTooLarge
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if msg, done, derr := dispatch(); done || derr != nil {
					return msg, derr
				}
				return nil, fmt.Errorf("stream ended without a response")
			}
			return nil, err
		}
	}
}

func (t *httpTransport) refuse(req Message) {
	t.mu.Lock()
	legacy := t.legacy
	t.mu.Unlock()
	if !legacy {
		return // modern servers must not send requests on the stream; nothing to answer
	}
	ctx, cancel := context.WithTimeout(context.Background(), refuseTimeout)
	defer cancel()
	resp, err := t.post(ctx, Errorf(req.ID, CodeMethodNotFound, "toolwall does not handle %s", req.Method))
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
	}
}

func readHTTPError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	he := &HTTPError{Status: resp.StatusCode, Body: string(raw)}
	var msg Message
	if json.Unmarshal(raw, &msg) == nil && msg.Error != nil {
		he.RPC = msg.Error
	}
	return he
}

func (t *httpTransport) diagnostics() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastStatus != "" {
		return "last http status: " + t.lastStatus
	}
	return ""
}

// close ends a legacy session with DELETE, which those revisions defined and a
// modern server answers with 405; either way there is nothing to report.
func (t *httpTransport) close() error {
	t.mu.Lock()
	legacy, session := t.legacy, t.sessionID
	t.mu.Unlock()
	if !legacy || session == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), refuseTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, t.endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set(headerSessionID, session)
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	if resp, err := t.client.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
	}
	return nil
}
