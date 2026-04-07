package tokens

import (
	"testing"
)

func TestScanSimpleBasic(t *testing.T) {
	patterns := []TokenPattern{
		simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	}

	body := "abcdefghijklmnopqrstuvwxyz0123456789"
	text := "token: ghp_" + body + " done"

	spans := Scan(text, patterns)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	s := spans[0]
	if s.Pattern.Name() != "github-pat" {
		t.Errorf("pattern = %q, want github-pat", s.Pattern.Name())
	}
	if s.Body != body {
		t.Errorf("body = %q, want %q", s.Body, body)
	}
	if s.Start != 7 {
		t.Errorf("start = %d, want 7", s.Start)
	}
	if s.End != 7+4+36 {
		t.Errorf("end = %d, want %d", s.End, 7+4+36)
	}
}

func TestScanNoMatch(t *testing.T) {
	patterns := []TokenPattern{
		simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	}
	spans := Scan("no tokens here", patterns)
	if len(spans) != 0 {
		t.Fatalf("got %d spans, want 0", len(spans))
	}
}

func TestScanBodyTooShort(t *testing.T) {
	patterns := []TokenPattern{
		simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	}
	spans := Scan("ghp_short", patterns)
	if len(spans) != 0 {
		t.Fatalf("got %d spans, want 0", len(spans))
	}
}

func TestScanMultipleMatches(t *testing.T) {
	patterns := []TokenPattern{
		simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	}
	body := "abcdefghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + body + " ghp_" + body
	spans := Scan(text, patterns)
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
	if spans[0].Start != 0 {
		t.Errorf("first start = %d, want 0", spans[0].Start)
	}
	if spans[1].Start != 41 {
		t.Errorf("second start = %d, want 41", spans[1].Start)
	}
}

func TestScanOverlapResolution(t *testing.T) {
	patterns := []TokenPattern{
		simplePattern("openai", "sk-proj-", "[A-Za-z0-9_-]{48,}", Base64URL, 48),
		simplePattern("openai-legacy", "sk-", "[A-Za-z0-9]{48}", Alphanumeric, 48),
	}

	body48 := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"
	text := "sk-proj-" + body48

	spans := Scan(text, patterns)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Pattern.Name() != "openai" {
		t.Errorf("pattern = %q, want openai (longer prefix wins)", spans[0].Pattern.Name())
	}
}

func TestScanPrefixSpecificity(t *testing.T) {
	anthropic := simplePattern("anthropic", "sk-ant-api03-", "[A-Za-z0-9_-]{80,}", Base64URL, 80)
	openaiLegacy := simplePattern("openai-legacy", "sk-", "[A-Za-z0-9]{48}", Alphanumeric, 48)

	body80 := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrs"
	text := "sk-ant-api03-" + body80

	spans := Scan(text, []TokenPattern{anthropic, openaiLegacy})
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Pattern.Name() != "anthropic" {
		t.Errorf("pattern = %q, want anthropic", spans[0].Pattern.Name())
	}
}

func TestScanWordBoundary(t *testing.T) {
	patterns := []TokenPattern{
		simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	}
	body := "abcdefghijklmnopqrstuvwxyz0123456789"

	t.Run("at start of text", func(t *testing.T) {
		text := "ghp_" + body
		spans := Scan(text, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
	})

	t.Run("after space", func(t *testing.T) {
		text := "prefix ghp_" + body
		spans := Scan(text, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
	})

	t.Run("after alphanumeric rejected", func(t *testing.T) {
		text := "Xghp_" + body
		spans := Scan(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0 (no word boundary)", len(spans))
		}
	})

	t.Run("after colon accepted", func(t *testing.T) {
		text := ":ghp_" + body
		spans := Scan(text, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
	})
}

func TestScanStructuredSlack(t *testing.T) {
	slack := makeSlackPattern("xoxb-", "slack-bot")
	patterns := []TokenPattern{slack}

	t.Run("valid slack token", func(t *testing.T) {
		text := "token: xoxb-123456789-987654321-abcdefABCDEF"
		spans := Scan(text, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
		if spans[0].Pattern.Name() != "slack-bot" {
			t.Errorf("pattern = %q, want slack-bot", spans[0].Pattern.Name())
		}
	})

	t.Run("body too short", func(t *testing.T) {
		text := "xoxb-1-2-3"
		spans := Scan(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0 (too short)", len(spans))
		}
	})
}

func TestScanStructuredSendGrid(t *testing.T) {
	patterns := []TokenPattern{sendgridPattern}

	seg1 := "aBcDeFgHiJkLmNoPqRsT01"                      // 22 chars
	seg2 := "0123456789abcdefABCDEF0123456789abcdefABCDE" // 43 chars
	text := "key: SG." + seg1 + "." + seg2 + " end"

	spans := Scan(text, patterns)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Pattern.Name() != "sendgrid" {
		t.Errorf("pattern = %q, want sendgrid", spans[0].Pattern.Name())
	}
	expectedBody := seg1 + "." + seg2
	if spans[0].Body != expectedBody {
		t.Errorf("body = %q, want %q", spans[0].Body, expectedBody)
	}
}

func TestScanNestedPrefixTruncation(t *testing.T) {
	vercel := simplePattern("vercel", "vercel_", "[A-Za-z0-9_-]{20,}", Base64URL, 20)
	gh := simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36)
	patterns := []TokenPattern{vercel, gh}

	vercelBody := "abcdefghijklmnopqrst"
	ghBody := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	t.Run("truncation splits at nested prefix", func(t *testing.T) {
		// vercel_ body would greedily consume into ghp_ because Base64URL
		// includes all alphanumeric, _, and -. Truncation should split at ghp_.
		// ghp_ itself fails word boundary (preceded by 't'), so only vercel matches,
		// but with the truncated body.
		text := "vercel_" + vercelBody + "ghp_" + ghBody
		spans := Scan(text, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
		if spans[0].Pattern.Name() != "vercel" {
			t.Errorf("pattern = %q, want vercel", spans[0].Pattern.Name())
		}
		if spans[0].Body != vercelBody {
			t.Errorf("body = %q, want %q", spans[0].Body, vercelBody)
		}
	})

	t.Run("both tokens found with word boundary", func(t *testing.T) {
		// With a space separator, both tokens have valid word boundaries.
		text := "vercel_" + vercelBody + " ghp_" + ghBody
		spans := Scan(text, patterns)
		if len(spans) != 2 {
			t.Fatalf("got %d spans, want 2", len(spans))
		}
		if spans[0].Pattern.Name() != "vercel" {
			t.Errorf("first = %q, want vercel", spans[0].Pattern.Name())
		}
		if spans[1].Pattern.Name() != "github-pat" {
			t.Errorf("second = %q, want github-pat", spans[1].Pattern.Name())
		}
	})
}

func TestScanBuiltinPatterns(t *testing.T) {
	ghBody := "abcdefghijklmnopqrstuvwxyz0123456789"
	text := "GitHub PAT: ghp_" + ghBody + "\n" +
		"Stripe: sk_live_" + "abcdefghijklmnopqrstuvwx" + "\n"

	spans := Scan(text, BuiltinPatterns)
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}

	names := map[string]bool{}
	for _, s := range spans {
		names[s.Pattern.Name()] = true
	}
	if !names["github-pat"] {
		t.Error("missing github-pat match")
	}
	if !names["stripe-secret-live"] {
		t.Error("missing stripe-secret-live match")
	}
}

func TestScanEmptyText(t *testing.T) {
	spans := Scan("", BuiltinPatterns)
	if len(spans) != 0 {
		t.Fatalf("got %d spans for empty text, want 0", len(spans))
	}
}

func TestScanAdjacentTokens(t *testing.T) {
	gh := simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36)
	patterns := []TokenPattern{gh}

	body := "abcdefghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + body + " ghp_" + body

	spans := Scan(text, patterns)
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
}

func TestScanGreedyConsumption(t *testing.T) {
	pat := simplePattern("stripe-secret-live", "sk_live_", "[A-Za-z0-9]{24,}", Alphanumeric, 24)
	patterns := []TokenPattern{pat}

	body := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
	text := "sk_live_" + body

	spans := Scan(text, patterns)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Body != body {
		t.Errorf("body = %q (len %d), want %q (len %d)", spans[0].Body, len(spans[0].Body), body, len(body))
	}
}

func TestScanStructuredTrailingBoundary(t *testing.T) {
	patterns := []TokenPattern{sendgridPattern}

	seg1 := "aBcDeFgHiJkLmNoPqRsT01"
	seg2 := "0123456789abcdefABCDEF0123456789abcdefABCDE"
	token := "SG." + seg1 + "." + seg2

	t.Run("trailing non-alphabet char accepted", func(t *testing.T) {
		text := token + " rest"
		spans := Scan(text, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
	})

	t.Run("end of text accepted", func(t *testing.T) {
		spans := Scan(token, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
	})
}

func TestFindAllPositions(t *testing.T) {
	text := "abc-abc-abc"
	positions := findAllPositions(text, "abc")
	if len(positions) != 3 {
		t.Fatalf("got %d positions, want 3", len(positions))
	}
	expected := []int{0, 4, 8}
	for i, pos := range positions {
		if pos != expected[i] {
			t.Errorf("position[%d] = %d, want %d", i, pos, expected[i])
		}
	}
}

func TestFindAllPositionsOverlapping(t *testing.T) {
	text := "aaaa"
	positions := findAllPositions(text, "aa")
	if len(positions) != 3 {
		t.Fatalf("got %d positions, want 3", len(positions))
	}
	expected := []int{0, 1, 2}
	for i, pos := range positions {
		if pos != expected[i] {
			t.Errorf("position[%d] = %d, want %d", i, pos, expected[i])
		}
	}
}

func TestIsWordBoundary(t *testing.T) {
	text := "abc ghp_token"
	if !isWordBoundary(text, 0) {
		t.Error("start of text should be a boundary")
	}
	if isWordBoundary(text, 1) {
		t.Error("after 'a' should not be a boundary")
	}
	if !isWordBoundary(text, 4) {
		t.Error("after space should be a boundary")
	}
}

func TestScanCrossLanguageParity(t *testing.T) {
	type spanExpect struct {
		start       int
		end         int
		patternName string
		body        string
	}
	tests := []struct {
		name  string
		text  string
		spans []spanExpect
	}{
		{
			name: "github-pat",
			text: "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
			spans: []spanExpect{
				{0, 40, "github-pat", "ABCDEFghijklmnopqrstuvwxyz0123456789"},
			},
		},
		{
			name: "stripe-secret-live with context",
			text: "My key is sk_live_abcdefghijklmnopqrstuvwx in config",
			spans: []spanExpect{
				{10, 42, "stripe-secret-live", "abcdefghijklmnopqrstuvwx"},
			},
		},
		{
			name: "sendgrid",
			text: "SG.aBcDeFgHiJkLmNoPqRsT01.0123456789abcdefABCDEF0123456789abcdefABCDE",
			spans: []spanExpect{
				{0, 69, "sendgrid", "aBcDeFgHiJkLmNoPqRsT01.0123456789abcdefABCDEF0123456789abcdefABCDE"},
			},
		},
		{
			name: "slack-bot",
			text: "xoxb-123456789-987654321-abcdefABCDEF",
			spans: []spanExpect{
				{0, 37, "slack-bot", "123456789-987654321-abcdefABCDEF"},
			},
		},
		{
			name: "aws-access-key",
			text: "AKIA1234567890ABCDEF",
			spans: []spanExpect{
				{0, 20, "aws-access-key", "1234567890ABCDEF"},
			},
		},
		{
			name: "two tokens",
			text: "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789 sk_live_abcdefghijklmnopqrstuvwx",
			spans: []spanExpect{
				{0, 40, "github-pat", "ABCDEFghijklmnopqrstuvwxyz0123456789"},
				{41, 73, "stripe-secret-live", "abcdefghijklmnopqrstuvwx"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spans := Scan(tt.text, BuiltinPatterns)
			if len(spans) != len(tt.spans) {
				t.Fatalf("got %d spans, want %d", len(spans), len(tt.spans))
			}
			for i, want := range tt.spans {
				got := spans[i]
				if got.Start != want.start {
					t.Errorf("span[%d].Start = %d, want %d", i, got.Start, want.start)
				}
				if got.End != want.end {
					t.Errorf("span[%d].End = %d, want %d", i, got.End, want.end)
				}
				if got.Pattern.Name() != want.patternName {
					t.Errorf("span[%d].Pattern = %q, want %q", i, got.Pattern.Name(), want.patternName)
				}
				if got.Body != want.body {
					t.Errorf("span[%d].Body = %q, want %q", i, got.Body, want.body)
				}
			}
		})
	}
}
