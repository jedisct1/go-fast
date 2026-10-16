package tokens

import (
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

func TestScanHeuristic(t *testing.T) {
	fastly := builtinsNamed("fastly")
	awsSecret := builtinsNamed("aws-secret-key")
	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	vercelFastly := "vercel_AB3dE5fG7hJ9kL1mN2pQ4rS6t"
	tests := []struct {
		name     string
		patterns []TokenPattern
		text     string
		want     []string
	}{
		{"fastly", fastly, "key=" + fastlyBody + " done", []string{"fastly@4-36:" + fastlyBody}},
		{"fastly as the whole text", fastly, fastlyBody, []string{"fastly@0-32:" + fastlyBody}},
		{"too short", fastly, "key=" + fastlyBody[:31] + " done", nil},
		{"too long", fastly, "key=" + fastlyBody + "Z done", nil},
		{"low entropy", fastly, "key=aaaaAAAA1111aaaaAAAA1111aaaaAAAA done", nil},
		{"two character classes", fastly, "key=abcdefghijklmnopqrstuvwxyz012345 done", nil},
		{"aws secret key", awsSecret, "secret=" + awsSecretBody + "\n", []string{"aws-secret-key@7-47:" + awsSecretBody}},
		{"wrong length", awsSecret, "secret=" + awsSecretBody[:39] + "\n", nil},

		// '_' is a word character but not a Base64 one, so only the word
		// boundary check rejects these.
		{"word character before", awsSecret, "_" + awsSecretBody + " ", nil},
		{"word character after", awsSecret, " " + awsSecretBody + "_", nil},

		{
			"next to a prefixed token", BuiltinPatterns, "ghp_" + ghBody + " " + fastlyBody + " end",
			[]string{"github-pat@0-40:" + ghBody, "fastly@41-73:" + fastlyBody},
		},
		{"vercel token without prefixed patterns", fastly, " " + vercelFastly + " ", []string{"fastly@1-33:" + vercelFastly}},
		{"prefixed pattern wins", BuiltinPatterns, " " + vercelFastly + " ", []string{"vercel@1-33:" + vercelFastly[7:]}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectSpans(t, Scan(tt.text, tt.patterns), tt.want...)
		})
	}
}

func BenchmarkScanHeuristicNoMatches(b *testing.B) {
	text := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100)
	patterns := builtinsNamed("fastly", "aws-secret-key")
	for b.Loop() {
		Scan(text, patterns)
	}
}

func BenchmarkScanHeuristicWithMatches(b *testing.B) {
	text := strings.Repeat("config="+fastlyBody+" ", 50)
	patterns := builtinsNamed("fastly")
	for b.Loop() {
		Scan(text, patterns)
	}
}

func BenchmarkScanMixed(b *testing.B) {
	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := strings.Repeat("ghp_"+ghBody+" "+fastlyBody+" key=sk_live_abcdefghijklmnopqrstuvwx\n", 20)
	for b.Loop() {
		Scan(text, BuiltinPatterns)
	}
}
