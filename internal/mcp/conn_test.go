package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnReadSkipsBlankLinesAndTolerantOfMissingNewline(t *testing.T) {
	in := strings.NewReader("\n\n" + `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete"}}`)
	c := NewConn(in, io.Discard)

	first, err := c.Read()
	require.NoError(t, err)
	assert.True(t, first.IsRequest())
	assert.Equal(t, "tools/list", first.Method)

	second, err := c.Read()
	require.NoError(t, err)
	assert.True(t, second.IsResponse())

	_, err = c.Read()
	assert.ErrorIs(t, err, io.EOF)
}

// A tool result carrying a file easily blows past bufio's default 64 KiB
// token size, which is why the reader does not use a Scanner.
func TestConnReadHandlesMessagesLargerThanTheBuffer(t *testing.T) {
	payload := strings.Repeat("x", 512<<10)
	line, err := json.Marshal(Message{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "big", Params: mustJSON(t, payload)})
	require.NoError(t, err)

	c := NewConn(bytes.NewReader(append(line, '\n')), io.Discard)
	msg, err := c.Read()
	require.NoError(t, err)

	var got string
	require.NoError(t, json.Unmarshal(msg.Params, &got))
	assert.Len(t, got, len(payload))
}

func TestConnReadRejectsOversizedMessage(t *testing.T) {
	huge := bytes.Repeat([]byte("x"), MaxMessageBytes+1)
	c := NewConn(bytes.NewReader(huge), io.Discard)

	_, err := c.Read()
	assert.ErrorIs(t, err, ErrMessageTooLarge)
}

func TestConnWriteIsNewlineDelimitedAndFillsInVersion(t *testing.T) {
	var out bytes.Buffer
	c := NewConn(strings.NewReader(""), &out)

	require.NoError(t, c.Write(&Message{ID: json.RawMessage("1"), Method: "ping"}))
	require.NoError(t, c.Write(&Message{ID: json.RawMessage("2"), Method: "ping"}))

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	for _, line := range lines {
		var m Message
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		assert.Equal(t, "2.0", m.JSONRPC)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}
