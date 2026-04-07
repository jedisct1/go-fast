package tokens

import (
	"strings"
	"testing"
)

var testKey = []byte("0123456789abcdef")

func TestNewEncryptor(t *testing.T) {
	t.Run("valid key sizes", func(t *testing.T) {
		for _, size := range []int{16, 24, 32} {
			key := make([]byte, size)
			_, err := New(key)
			if err != nil {
				t.Errorf("key size %d: %v", size, err)
			}
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		_, err := New([]byte("short"))
		if err == nil {
			t.Error("expected error for invalid key size")
		}
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := "token: ghp_" + ghBody + " done"

	encrypted, err := enc.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}

	if encrypted == text {
		t.Error("encrypted should differ from plaintext")
	}
	if !strings.HasPrefix(encrypted, "token: ghp_") {
		t.Error("prefix should be preserved")
	}
	if !strings.HasSuffix(encrypted, " done") {
		t.Error("surrounding text should be preserved")
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != text {
		t.Errorf("round trip failed:\n  got:  %q\n  want: %q", decrypted, text)
	}
}

func TestEncryptDecryptStripe(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	text := "sk_live_abcdefghijklmnopqrstuvwx"
	encrypted, err := enc.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "sk_live_") {
		t.Error("prefix should be preserved")
	}
	if len(encrypted) != len(text) {
		t.Errorf("length changed: %d -> %d", len(text), len(encrypted))
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != text {
		t.Errorf("round trip failed: got %q, want %q", decrypted, text)
	}
}

func TestEncryptDecryptSlack(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	text := "xoxb-123456789-987654321-abcdefABCDEF"
	encrypted, err := enc.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "xoxb-") {
		t.Error("prefix should be preserved")
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != text {
		t.Errorf("round trip failed: got %q, want %q", decrypted, text)
	}
}

func TestEncryptDecryptSendGrid(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	seg1 := "aBcDeFgHiJkLmNoPqRsT01"
	seg2 := "0123456789abcdefABCDEF0123456789abcdefABCDE"
	text := "SG." + seg1 + "." + seg2

	encrypted, err := enc.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "SG.") {
		t.Error("prefix should be preserved")
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != text {
		t.Errorf("round trip failed: got %q, want %q", decrypted, text)
	}
}

func TestEncryptDecryptHeuristic(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	text := "key=" + fastlyBody + " end"
	encrypted, err := enc.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(encrypted, "[ENCRYPTED:fastly]") {
		t.Error("should contain heuristic marker")
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != text {
		t.Errorf("round trip failed:\n  got:  %q\n  want: %q", decrypted, text)
	}
}

func TestEncryptDecryptMultiHeuristic(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	// AWS secret (40 chars, Base64) appears before Fastly (32 chars, Base64URL).
	// Both are heuristic patterns. The decrypt must process markers in text order,
	// not pattern iteration order.
	text := "aws=" + awsSecretBody + " fastly=" + fastlyBody + " end"

	encrypted, err := enc.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(encrypted, "[ENCRYPTED:aws-secret-key]") {
		t.Error("should contain aws-secret-key marker")
	}
	if !strings.Contains(encrypted, "[ENCRYPTED:fastly]") {
		t.Error("should contain fastly marker")
	}

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != text {
		t.Errorf("multi-heuristic round trip failed:\n  got:  %q\n  want: %q", decrypted, text)
	}
}

func TestEncryptNoMatch(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	text := "no tokens here"
	encrypted, err := enc.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted != text {
		t.Errorf("no-match text should pass through unchanged: got %q", encrypted)
	}
}

func TestEncryptWithSpans(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + ghBody

	result, err := enc.EncryptWithSpans(text)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(result.Spans))
	}
	s := result.Spans[0]
	if s.PatternName != "github-pat" {
		t.Errorf("pattern = %q, want github-pat", s.PatternName)
	}
	if s.Original != text {
		t.Errorf("original = %q, want %q", s.Original, text)
	}
	if s.Encrypted == s.Original {
		t.Error("encrypted should differ from original")
	}
}

func TestEncryptWithMappings(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + ghBody + " ghp_" + ghBody

	result, mappings, err := enc.EncryptWithMappings(text)
	if err != nil {
		t.Fatal(err)
	}
	if result == text {
		t.Error("should be encrypted")
	}
	if len(mappings) != 1 {
		t.Errorf("got %d mappings, want 1 (deduplicated)", len(mappings))
	}
	if len(mappings) > 0 && mappings[0].PatternName != "github-pat" {
		t.Errorf("pattern = %q, want github-pat", mappings[0].PatternName)
	}
}

func TestEncryptDecryptWithTweak(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + ghBody

	enc1, err := enc.Encrypt(text, WithCallTweak([]byte("tweak1")))
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := enc.Encrypt(text, WithCallTweak([]byte("tweak2")))
	if err != nil {
		t.Fatal(err)
	}

	if enc1 == enc2 {
		t.Error("different tweaks should produce different ciphertext")
	}

	dec1, err := enc.Decrypt(enc1, WithCallTweak([]byte("tweak1")))
	if err != nil {
		t.Fatal(err)
	}
	if dec1 != text {
		t.Errorf("decrypt with correct tweak failed: got %q", dec1)
	}
}

func TestEncryptDecryptDefaultTweak(t *testing.T) {
	enc1, _ := New(testKey, WithTweak([]byte("default")))
	enc2, _ := New(testKey)

	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + ghBody

	ct1, _ := enc1.Encrypt(text)
	ct2, _ := enc2.Encrypt(text)

	if ct1 == ct2 {
		t.Error("default tweak should change ciphertext")
	}

	dec, _ := enc1.Decrypt(ct1)
	if dec != text {
		t.Errorf("round trip with default tweak failed: got %q", dec)
	}
}

func TestEncryptWithTypes(t *testing.T) {
	enc, _ := New(testKey)

	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	stripeBody := "abcdefghijklmnopqrstuvwx"
	text := "ghp_" + ghBody + " sk_live_" + stripeBody

	encrypted, _ := enc.Encrypt(text, WithTypes("github-pat"))
	if !strings.Contains(encrypted, "sk_live_"+stripeBody) {
		t.Error("unselected pattern should pass through")
	}

	decrypted, _ := enc.Decrypt(encrypted, WithTypes("github-pat"))
	if decrypted != text {
		t.Errorf("round trip with types filter failed: got %q", decrypted)
	}
}

func TestEncryptDecryptMultipleTokens(t *testing.T) {
	enc, _ := New(testKey)

	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	stripeBody := "abcdefghijklmnopqrstuvwx"
	text := "GitHub: ghp_" + ghBody + "\nStripe: sk_live_" + stripeBody + "\nEnd"

	encrypted, _ := enc.Encrypt(text)
	decrypted, _ := enc.Decrypt(encrypted)
	if decrypted != text {
		t.Errorf("multi-token round trip failed:\n  got:  %q\n  want: %q", decrypted, text)
	}
}

func TestEncryptDecryptAWSAccessKey(t *testing.T) {
	enc, _ := New(testKey)

	text := "aws_key=AKIA1234567890ABCDEF"
	encrypted, _ := enc.Encrypt(text)
	if !strings.HasPrefix(encrypted, "aws_key=AKIA") {
		t.Error("AKIA prefix should be preserved")
	}
	decrypted, _ := enc.Decrypt(encrypted)
	if decrypted != text {
		t.Errorf("round trip failed: got %q, want %q", decrypted, text)
	}
}

func TestMakeTweak(t *testing.T) {
	t.Run("no extra", func(t *testing.T) {
		tweak := makeTweak("github-pat", nil)
		if string(tweak) != "github-pat" {
			t.Errorf("got %q, want %q", tweak, "github-pat")
		}
	})

	t.Run("with extra", func(t *testing.T) {
		tweak := makeTweak("github-pat", []byte("extra"))
		expected := "github-pat\x00extra"
		if string(tweak) != expected {
			t.Errorf("got %q, want %q", tweak, expected)
		}
	})
}

func TestHeuristicMarker(t *testing.T) {
	if got := heuristicMarker("fastly"); got != "[ENCRYPTED:fastly]" {
		t.Errorf("got %q, want %q", got, "[ENCRYPTED:fastly]")
	}
}

func TestEncryptCrossLanguageParity(t *testing.T) {
	enc, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		input     string
		tweak     []byte
		encrypted string
	}{
		{
			name:      "github-pat no tweak",
			input:     "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
			encrypted: "ghp_5fHZkNjXZvztZCycGSRVqScThCoK46AxcG7U",
		},
		{
			name:      "stripe-secret-live no tweak",
			input:     "sk_live_abcdefghijklmnopqrstuvwx",
			encrypted: "sk_live_x23dqrBujbJyNqRm0ArZxCO1",
		},
		{
			name:      "aws-access-key no tweak",
			input:     "AKIA1234567890ABCDEF",
			encrypted: "AKIAZCMJXYMIWSKJXOU8",
		},
		{
			name:      "github-pat with tweak",
			input:     "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789",
			tweak:     []byte("mytweak"),
			encrypted: "ghp_Mj7BLITKdNVYIspEou6LaTmm9pGIp2IpGTax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []CallOption
			if tt.tweak != nil {
				opts = append(opts, WithCallTweak(tt.tweak))
			}
			got, err := enc.Encrypt(tt.input, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.encrypted {
				t.Errorf("encrypted = %q, want %q", got, tt.encrypted)
			}

			decrypted, err := enc.Decrypt(got, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if decrypted != tt.input {
				t.Errorf("round trip failed: got %q, want %q", decrypted, tt.input)
			}
		})
	}
}

func TestStructuredMinSegmentLength(t *testing.T) {
	enc, _ := New(testKey)

	// Slack token with a short first segment (< 4 chars)
	text := "xoxb-12-987654321012-abcdefABCDEF"
	encrypted, err := enc.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}

	// The short segment "12" should pass through unchanged
	parts := strings.SplitN(strings.TrimPrefix(encrypted, "xoxb-"), "-", 2)
	if parts[0] != "12" {
		t.Errorf("short segment should be preserved: got %q", parts[0])
	}

	decrypted, _ := enc.Decrypt(encrypted)
	if decrypted != text {
		t.Errorf("round trip failed: got %q, want %q", decrypted, text)
	}
}

func BenchmarkEncryptSingleToken(b *testing.B) {
	enc, _ := New(testKey)
	text := "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789"
	for b.Loop() {
		enc.Encrypt(text)
	}
}

func BenchmarkEncryptLargeText(b *testing.B) {
	enc, _ := New(testKey)
	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	stripeBody := "abcdefghijklmnopqrstuvwx"
	text := strings.Repeat("GitHub: ghp_"+ghBody+"\nStripe: sk_live_"+stripeBody+"\n", 50)
	b.ResetTimer()
	for b.Loop() {
		enc.Encrypt(text)
	}
}

func BenchmarkDecryptLargeText(b *testing.B) {
	enc, _ := New(testKey)
	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	stripeBody := "abcdefghijklmnopqrstuvwx"
	text := strings.Repeat("GitHub: ghp_"+ghBody+"\nStripe: sk_live_"+stripeBody+"\n", 50)
	encrypted, _ := enc.Encrypt(text)
	b.ResetTimer()
	for b.Loop() {
		enc.Decrypt(encrypted)
	}
}

func BenchmarkEncryptDecryptRoundTrip(b *testing.B) {
	enc, _ := New(testKey)
	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + ghBody
	for b.Loop() {
		ct, _ := enc.Encrypt(text)
		enc.Decrypt(ct)
	}
}
