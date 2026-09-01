package suggest_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/YusufDrymz/toolwall/internal/mcp"
	"github.com/YusufDrymz/toolwall/internal/policy"
	"github.com/YusufDrymz/toolwall/internal/suggest"
)

func TestSuggestsSinkForSendingTools(t *testing.T) {
	s := suggest.For(mcp.Tool{Name: "send_email", Description: "Send an email to a recipient"})
	assert.Contains(t, s.Labels, policy.LabelSink)
	assert.NotEmpty(t, s.Why)
}

func TestSuggestsBothLabelsForAFetcher(t *testing.T) {
	// A URL fetcher is the awkward one: the response is attacker-controlled
	// and the request itself is an exit, since data fits in a query string.
	s := suggest.For(mcp.Tool{Name: "http_request", Description: "Fetch a URL"})
	assert.Contains(t, s.Labels, policy.LabelUntrusted)
	assert.Contains(t, s.Labels, policy.LabelSink)
}

func TestReadOnlyHintClearsTheSinkGuess(t *testing.T) {
	s := suggest.For(mcp.Tool{
		Name:        "post_lookup",
		Description: "Look up a post",
		Annotations: json.RawMessage(`{"readOnlyHint":true}`),
	})
	assert.NotContains(t, s.Labels, policy.LabelSink)
}

func TestNoGuessIsHonestAboutIt(t *testing.T) {
	s := suggest.For(mcp.Tool{Name: "roll_dice", Description: "Return a random number"})
	assert.Empty(t, s.Labels)
	assert.Contains(t, s.Why, "label it yourself")
}
