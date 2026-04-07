package tokens

import (
	"testing"
)

func TestBuiltinPatternCount(t *testing.T) {
	if got := len(BuiltinPatterns); got != 28 {
		t.Fatalf("len(BuiltinPatterns) = %d, want 28", got)
	}

	simple, structured, heuristic := 0, 0, 0
	for _, p := range BuiltinPatterns {
		switch p.Kind() {
		case "simple":
			simple++
		case "structured":
			structured++
		case "heuristic":
			heuristic++
		default:
			t.Errorf("unknown kind %q for pattern %q", p.Kind(), p.Name())
		}
	}
	if simple != 23 {
		t.Errorf("simple count = %d, want 23", simple)
	}
	if structured != 3 {
		t.Errorf("structured count = %d, want 3", structured)
	}
	if heuristic != 2 {
		t.Errorf("heuristic count = %d, want 2", heuristic)
	}
}

func TestBuiltinPatternOrdering(t *testing.T) {
	expected := []string{
		"anthropic",
		"openai",
		"openai-legacy",
		"stripe-secret-live",
		"stripe-publish-live",
		"stripe-secret-test",
		"stripe-publish-test",
		"vercel",
		"gitlab",
		"datadog",
		"pypi",
		"slack-bot",
		"slack-user",
		"github-pat",
		"github-oauth",
		"github-user",
		"github-server",
		"github-refresh",
		"aws-access-key",
		"google-api",
		"npm",
		"supabase",
		"grafana",
		"huggingface",
		"sendgrid",
		"twilio",
		"fastly",
		"aws-secret-key",
	}
	if len(expected) != len(BuiltinPatterns) {
		t.Fatalf("expected %d names, got %d patterns", len(expected), len(BuiltinPatterns))
	}
	for i, name := range expected {
		if BuiltinPatterns[i].Name() != name {
			t.Errorf("BuiltinPatterns[%d].Name() = %q, want %q", i, BuiltinPatterns[i].Name(), name)
		}
	}
}

func TestSimplePatternMetadata(t *testing.T) {
	tests := []struct {
		name          string
		prefix        string
		alphabetName  string
		minBodyLength int
	}{
		{"anthropic", "sk-ant-api03-", "base64url", 80},
		{"openai", "sk-proj-", "base64url", 48},
		{"openai-legacy", "sk-", "alphanumeric", 48},
		{"stripe-secret-live", "sk_live_", "alphanumeric", 24},
		{"stripe-publish-live", "pk_live_", "alphanumeric", 24},
		{"stripe-secret-test", "sk_test_", "alphanumeric", 24},
		{"stripe-publish-test", "pk_test_", "alphanumeric", 24},
		{"vercel", "vercel_", "base64url", 20},
		{"gitlab", "glpat-", "base64url", 20},
		{"datadog", "ddapi_", "alphanumeric-lower", 40},
		{"pypi", "pypi-", "base64url", 50},
		{"github-pat", "ghp_", "alphanumeric", 36},
		{"github-oauth", "gho_", "alphanumeric", 36},
		{"github-user", "ghu_", "alphanumeric", 36},
		{"github-server", "ghs_", "alphanumeric", 36},
		{"github-refresh", "ghr_", "alphanumeric", 36},
		{"aws-access-key", "AKIA", "alphanumeric-upper", 16},
		{"google-api", "AIza", "base64url", 35},
		{"npm", "npm_", "alphanumeric", 36},
		{"supabase", "sbp_", "hex-lower", 40},
		{"grafana", "glc_", "base64url", 30},
		{"huggingface", "hf_", "alphanumeric", 34},
		{"twilio", "SK", "hex-lower", 32},
	}

	byName := make(map[string]SimpleTokenPattern)
	for _, p := range BuiltinPatterns {
		if sp, ok := p.(SimpleTokenPattern); ok {
			byName[sp.Name()] = sp
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp, ok := byName[tt.name]
			if !ok {
				t.Fatalf("pattern %q not found", tt.name)
			}
			if sp.Prefix() != tt.prefix {
				t.Errorf("prefix = %q, want %q", sp.Prefix(), tt.prefix)
			}
			if sp.bodyAlphabet.Name() != tt.alphabetName {
				t.Errorf("alphabet = %q, want %q", sp.bodyAlphabet.Name(), tt.alphabetName)
			}
			if sp.minBodyLength != tt.minBodyLength {
				t.Errorf("minBodyLength = %d, want %d", sp.minBodyLength, tt.minBodyLength)
			}
		})
	}
}

func TestStructuredPatternMetadata(t *testing.T) {
	tests := []struct {
		name             string
		prefix           string
		trailingAlphabet string
	}{
		{"slack-bot", "xoxb-", "alphanumeric"},
		{"slack-user", "xoxp-", "alphanumeric"},
		{"sendgrid", "SG.", "base64url"},
	}

	byName := make(map[string]StructuredTokenPattern)
	for _, p := range BuiltinPatterns {
		if sp, ok := p.(StructuredTokenPattern); ok {
			byName[sp.Name()] = sp
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp, ok := byName[tt.name]
			if !ok {
				t.Fatalf("pattern %q not found", tt.name)
			}
			if sp.Prefix() != tt.prefix {
				t.Errorf("prefix = %q, want %q", sp.Prefix(), tt.prefix)
			}
			if sp.trailingAlphabet.Name() != tt.trailingAlphabet {
				t.Errorf("trailingAlphabet = %q, want %q", sp.trailingAlphabet.Name(), tt.trailingAlphabet)
			}
		})
	}
}

func TestHeuristicPatternMetadata(t *testing.T) {
	tests := []struct {
		name           string
		alphabetName   string
		minLength      int
		maxLength      int
		minEntropy     float64
		minCharClasses int
	}{
		{"fastly", "base64url", 32, 32, 4.0, 3},
		{"aws-secret-key", "base64", 40, 40, 4.0, 3},
	}

	byName := make(map[string]HeuristicTokenPattern)
	for _, p := range BuiltinPatterns {
		if hp, ok := p.(HeuristicTokenPattern); ok {
			byName[hp.Name()] = hp
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hp, ok := byName[tt.name]
			if !ok {
				t.Fatalf("pattern %q not found", tt.name)
			}
			if hp.bodyAlphabet.Name() != tt.alphabetName {
				t.Errorf("alphabet = %q, want %q", hp.bodyAlphabet.Name(), tt.alphabetName)
			}
			if hp.minLength != tt.minLength {
				t.Errorf("minLength = %d, want %d", hp.minLength, tt.minLength)
			}
			if hp.maxLength != tt.maxLength {
				t.Errorf("maxLength = %d, want %d", hp.maxLength, tt.maxLength)
			}
			if hp.minEntropy != tt.minEntropy {
				t.Errorf("minEntropy = %f, want %f", hp.minEntropy, tt.minEntropy)
			}
			if hp.minCharClasses != tt.minCharClasses {
				t.Errorf("minCharClasses = %d, want %d", hp.minCharClasses, tt.minCharClasses)
			}
		})
	}
}

func TestSlackParse(t *testing.T) {
	slack := makeSlackPattern("xoxb-", "slack-bot")

	t.Run("valid three segments", func(t *testing.T) {
		result := slack.Parse("123456789-987654321-abcdefABCD")
		if result == nil {
			t.Fatal("expected non-nil parse result")
		}
		if len(result.Segments) != 3 {
			t.Fatalf("segments = %d, want 3", len(result.Segments))
		}
		if result.Segments[0] != "123456789" || result.Segments[1] != "987654321" || result.Segments[2] != "abcdefABCD" {
			t.Errorf("segments = %v", result.Segments)
		}
		if result.Alphabets[0].Name() != "digits" {
			t.Errorf("first segment alphabet = %q, want digits", result.Alphabets[0].Name())
		}
		if result.Alphabets[1].Name() != "digits" {
			t.Errorf("second segment alphabet = %q, want digits", result.Alphabets[1].Name())
		}
		if result.Alphabets[2].Name() != "alphanumeric" {
			t.Errorf("third segment alphabet = %q, want alphanumeric", result.Alphabets[2].Name())
		}
	})

	t.Run("too few segments", func(t *testing.T) {
		if slack.Parse("123-456") != nil {
			t.Error("expected nil for fewer than 3 segments")
		}
	})

	t.Run("total length too short", func(t *testing.T) {
		if slack.Parse("1-2-3") != nil {
			t.Error("expected nil for total length < 20")
		}
	})

	t.Run("invalid characters", func(t *testing.T) {
		if slack.Parse("123-456-abc!def") != nil {
			t.Error("expected nil for non-alphanumeric segment")
		}
	})

	t.Run("empty segment from consecutive dashes", func(t *testing.T) {
		if slack.Parse("123456789--987654321-abcdefABCD") != nil {
			t.Error("expected nil for empty segment between consecutive dashes")
		}
	})

	t.Run("format round trip", func(t *testing.T) {
		segments := []string{"123", "456", "abc"}
		if got := slack.Format(segments); got != "123-456-abc" {
			t.Errorf("Format() = %q, want %q", got, "123-456-abc")
		}
	})
}

func TestSendGridParse(t *testing.T) {
	sg := sendgridPattern

	t.Run("valid segments", func(t *testing.T) {
		seg1 := "aBcDeFgHiJkLmNoPqRsT01"                      // 22 chars
		seg2 := "0123456789abcdefABCDEF0123456789abcdefABCDE" // 43 chars
		result := sg.Parse(seg1 + "." + seg2)
		if result == nil {
			t.Fatal("expected non-nil parse result")
		}
		if len(result.Segments) != 2 {
			t.Fatalf("segments = %d, want 2", len(result.Segments))
		}
		if result.Segments[0] != seg1 || result.Segments[1] != seg2 {
			t.Errorf("segments = %v", result.Segments)
		}
		if result.Alphabets[0].Name() != "base64url" || result.Alphabets[1].Name() != "base64url" {
			t.Error("expected base64url alphabets")
		}
	})

	t.Run("no dot", func(t *testing.T) {
		if sg.Parse("abcdefghijklmnopqrstuv0123456789abcdefABCDEF012345678901234") != nil {
			t.Error("expected nil for missing dot")
		}
	})

	t.Run("wrong segment lengths", func(t *testing.T) {
		if sg.Parse("short.toolong") != nil {
			t.Error("expected nil for wrong segment lengths")
		}
	})

	t.Run("format round trip", func(t *testing.T) {
		segments := []string{"seg1", "seg2"}
		if got := sg.Format(segments); got != "seg1.seg2" {
			t.Errorf("Format() = %q, want %q", got, "seg1.seg2")
		}
	})
}

func TestMinSegmentLength(t *testing.T) {
	if MinSegmentLength != 4 {
		t.Errorf("MinSegmentLength = %d, want 4", MinSegmentLength)
	}
}

func TestHeuristicPrefixEmpty(t *testing.T) {
	for _, p := range BuiltinPatterns {
		if p.Kind() == "heuristic" {
			if p.Prefix() != "" {
				t.Errorf("heuristic pattern %q has non-empty prefix %q", p.Name(), p.Prefix())
			}
		}
	}
}

func TestPatternNamesUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range BuiltinPatterns {
		if seen[p.Name()] {
			t.Errorf("duplicate pattern name %q", p.Name())
		}
		seen[p.Name()] = true
	}
}
