package tokens

import (
	"math"
	"strings"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantMin float64
		wantMax float64
	}{
		{"empty", "", 0, 0},
		{"single char repeated", "aaaa", 0, 0},
		{"two equal chars", "ab", 1.0, 1.0},
		{"uniform 4 chars", "abcd", 2.0, 2.0},
		{"high entropy", "aB3+cD5/eF7hG9jK1LmN2oPqR4sT6uVwX8yZ0ab", 4.0, 6.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.wantMin-0.01 || got > tt.wantMax+0.01 {
				t.Errorf("shannonEntropy(%q) = %f, want [%f, %f]", tt.input, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestCountCharClasses(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"abc", 1},
		{"ABC", 1},
		{"123", 1},
		{"abc123", 2},
		{"abcABC", 2},
		{"abcABC123", 3},
		{"abcABC123+", 4},
		{"+/", 1},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := countCharClasses(tt.input); got != tt.want {
				t.Errorf("countCharClasses(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// 32-char high-entropy Base64URL body (upper+lower+digits = 3 classes)
const fastlyBody = "aB3cD5eF7hG9jK1LmN2oPqR4sT6uVwX0"

// 40-char high-entropy Base64 body (upper+lower+digits+other = 4 classes)
const awsSecretBody = "aB3+cD5/eF7hG9jK1LmN2oPqR4sT6uVwX8yZ0abc"

func TestScanHeuristicFastly(t *testing.T) {
	fastly := heuristicPattern("fastly", Base64URL, 32, 32, 4.0, 3)
	patterns := []TokenPattern{fastly}

	if len(fastlyBody) != 32 {
		t.Fatalf("fastlyBody len = %d, want 32", len(fastlyBody))
	}

	t.Run("valid token", func(t *testing.T) {
		text := "key=" + fastlyBody + " done"
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
		if spans[0].Pattern.Name() != "fastly" {
			t.Errorf("pattern = %q, want fastly", spans[0].Pattern.Name())
		}
		if spans[0].Body != fastlyBody {
			t.Errorf("body = %q, want %q", spans[0].Body, fastlyBody)
		}
	})

	t.Run("too short rejected", func(t *testing.T) {
		body := fastlyBody[:31]
		text := "key=" + body + " done"
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0", len(spans))
		}
	})

	t.Run("too long rejected", func(t *testing.T) {
		body := fastlyBody + "Z" // 33 chars, but run is 33 so length check fails
		text := "key=" + body + " done"
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0", len(spans))
		}
	})

	t.Run("low entropy rejected", func(t *testing.T) {
		body := "aaaaAAAA1111aaaaAAAA1111aaaaAAAA11" // 32 chars, low entropy
		text := "key=" + body + " done"
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0", len(spans))
		}
	})

	t.Run("too few char classes rejected", func(t *testing.T) {
		body := "abcdefghijklmnopqrstuvwxyz012345" // 32 chars, 2 classes (lower+digit)
		text := "key=" + body + " done"
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0", len(spans))
		}
	})

	t.Run("alphabet char extends run past max length", func(t *testing.T) {
		// For Base64URL, all word chars ([A-Za-z0-9_-]) are in the alphabet,
		// so boundary rejection and length rejection are inseparable.
		// An adjacent alphabet char extends the run to 33, failing the length check.
		text := " " + fastlyBody + "Z "
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0 (run is 33 chars)", len(spans))
		}
	})

	t.Run("at start and end of text", func(t *testing.T) {
		spans := ScanHeuristic(fastlyBody, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
	})
}

func TestScanHeuristicAWSSecretKey(t *testing.T) {
	awsSecret := heuristicPattern("aws-secret-key", Base64, 40, 40, 4.0, 3)
	patterns := []TokenPattern{awsSecret}

	if len(awsSecretBody) != 40 {
		t.Fatalf("awsSecretBody len = %d, want 40", len(awsSecretBody))
	}

	t.Run("valid aws secret key", func(t *testing.T) {
		text := "secret=" + awsSecretBody + "\n"
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
		if spans[0].Pattern.Name() != "aws-secret-key" {
			t.Errorf("pattern = %q, want aws-secret-key", spans[0].Pattern.Name())
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		body := awsSecretBody[:39]
		text := "secret=" + body + "\n"
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0", len(spans))
		}
	})

	// For Base64 alphabet, '_' and '-' are word chars NOT in the alphabet.
	// This allows isolating boundary rejection from length rejection: the
	// run is exactly 40 chars but adjacent to a word char outside Base64.
	t.Run("start boundary rejected in isolation", func(t *testing.T) {
		// '_' is a word char but NOT in Base64, so it won't extend the run.
		// The run is exactly 40 chars, but isWordBoundary fails because
		// the preceding '_' is not a non-word char.
		text := "_" + awsSecretBody + " "
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0 (start boundary only)", len(spans))
		}
	})

	t.Run("end boundary rejected in isolation", func(t *testing.T) {
		// Run is exactly 40 chars, but '_' after it fails isWordBoundaryEnd.
		text := " " + awsSecretBody + "_"
		spans := ScanHeuristic(text, patterns)
		if len(spans) != 0 {
			t.Fatalf("got %d spans, want 0 (end boundary only)", len(spans))
		}
	})
}

func TestScanHeuristicSkipsPrefixPatterns(t *testing.T) {
	patterns := []TokenPattern{
		simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
		heuristicPattern("fastly", Base64URL, 32, 32, 4.0, 3),
	}
	text := "=" + fastlyBody + " ghp_abcdefghijklmnopqrstuvwxyz0123456789"

	spans := ScanHeuristic(text, patterns)
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1 (only heuristic)", len(spans))
	}
	if spans[0].Pattern.Name() != "fastly" {
		t.Errorf("pattern = %q, want fastly", spans[0].Pattern.Name())
	}
}

func TestScanAllMixed(t *testing.T) {
	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + ghBody + " " + fastlyBody + " end"

	spans := ScanAll(text, BuiltinPatterns)

	names := map[string]bool{}
	for _, s := range spans {
		names[s.Pattern.Name()] = true
	}
	if !names["github-pat"] {
		t.Error("missing github-pat")
	}
	if !names["fastly"] {
		t.Error("missing fastly")
	}
	if len(spans) != 2 {
		t.Errorf("got %d spans, want 2", len(spans))
	}
}

func TestScanAllWithAllTruncation(t *testing.T) {
	vercel := simplePattern("vercel", "vercel_", "[A-Za-z0-9_-]{20,}", Base64URL, 20)

	ghBody := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	text := "vercel_abcdefghijklmnopqrstghp_" + ghBody

	t.Run("filtered scan without allPatterns overshoots", func(t *testing.T) {
		// With only vercel in the pattern list, ghp_ is not a known prefix,
		// so no truncation happens and vercel greedily consumes everything.
		spans := ScanAll(text, []TokenPattern{vercel})
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
		// Body extends past ghp_ because ghp_ is unknown
		if len(spans[0].Body) <= 20 {
			t.Errorf("expected oversized body without allPatterns, got len %d", len(spans[0].Body))
		}
	})

	t.Run("filtered scan with allPatterns truncates correctly", func(t *testing.T) {
		// With BuiltinPatterns as allPatterns, ghp_ is recognized and
		// vercel's body is truncated at the ghp_ prefix boundary.
		spans := ScanAllWithAll(text, []TokenPattern{vercel}, BuiltinPatterns)
		if len(spans) != 1 {
			t.Fatalf("got %d spans, want 1", len(spans))
		}
		if spans[0].Body != "abcdefghijklmnopqrst" {
			t.Errorf("body = %q, want truncated at ghp_ prefix", spans[0].Body)
		}
	})
}

func TestScanAllPrefixBeatsHeuristic(t *testing.T) {
	text := "AKIA1234567890ABCDEF"
	spans := ScanAll(text, BuiltinPatterns)

	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Pattern.Name() != "aws-access-key" {
		t.Errorf("pattern = %q, want aws-access-key", spans[0].Pattern.Name())
	}
}

func TestShannonEntropyMathProperties(t *testing.T) {
	e := shannonEntropy("abcdefghijklmnop")
	expected := math.Log2(16)
	if math.Abs(e-expected) > 0.001 {
		t.Errorf("entropy of 16 unique chars = %f, want %f (log2(16))", e, expected)
	}
}

func BenchmarkScanHeuristicNoMatches(b *testing.B) {
	text := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100)
	patterns := []TokenPattern{
		heuristicPattern("fastly", Base64URL, 32, 32, 4.0, 3),
		heuristicPattern("aws-secret-key", Base64, 40, 40, 4.0, 3),
	}
	b.ResetTimer()
	for b.Loop() {
		ScanHeuristic(text, patterns)
	}
}

func BenchmarkScanHeuristicWithMatches(b *testing.B) {
	text := strings.Repeat("config="+fastlyBody+" ", 50)
	patterns := []TokenPattern{
		heuristicPattern("fastly", Base64URL, 32, 32, 4.0, 3),
	}
	b.ResetTimer()
	for b.Loop() {
		ScanHeuristic(text, patterns)
	}
}

func BenchmarkScanAllMixed(b *testing.B) {
	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := strings.Repeat("ghp_"+ghBody+" "+fastlyBody+" key=sk_live_abcdefghijklmnopqrstuvwx\n", 20)
	b.ResetTimer()
	for b.Loop() {
		ScanAll(text, BuiltinPatterns)
	}
}
