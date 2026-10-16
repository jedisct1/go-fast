package tokens

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// decodeSecret undoes the ROT13 that keeps fake credentials away from secret
// scanners.
func decodeSecret(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

var awsKey = "AKIA" + strings.Repeat("B", 16)

func describeSpans(spans []TokenSpan) []string {
	out := make([]string, len(spans))
	for i, s := range spans {
		out[i] = fmt.Sprintf("%s@%d-%d:%s", s.Pattern.Name(), s.Start, s.End, s.Body)
	}
	return out
}

func builtinsNamed(names ...string) []TokenPattern {
	var out []TokenPattern
	for _, p := range BuiltinPatterns {
		if slices.Contains(names, p.Name()) {
			out = append(out, p)
		}
	}
	return out
}

func expectSpans(t *testing.T, spans []TokenSpan, want ...string) {
	t.Helper()
	if got := describeSpans(spans); !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestScan(t *testing.T) {
	ghBody := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	slackUser := decodeSecret("kbkc-1234567890-9876543210-2468013579-NoPqRsTuVwXyZaBcDeFgHiJk")
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"empty", "", nil},
		{"no tokens", "no tokens here", nil},
		{"body too short", "ghp_short", nil},
		{"slack too short", "xoxb-1-2-3", nil},

		// These match the JS and Python implementations.
		{"github-pat", "ghp_" + ghBody, []string{"github-pat@0-40:" + ghBody}},
		{
			"stripe in a sentence", "My key is sk_live_abcdefghijklmnopqrstuvwx in config",
			[]string{"stripe-secret-live@10-42:abcdefghijklmnopqrstuvwx"},
		},
		{
			"sendgrid", "SG.aBcDeFgHiJkLmNoPqRsT01.0123456789abcdefABCDEF0123456789abcdefABCDE",
			[]string{"sendgrid@0-69:aBcDeFgHiJkLmNoPqRsT01.0123456789abcdefABCDEF0123456789abcdefABCDE"},
		},
		{
			"slack-bot", "xoxb-123456789-987654321-abcdefABCDEF",
			[]string{"slack-bot@0-37:123456789-987654321-abcdefABCDEF"},
		},
		{"aws-access-key", "AKIA1234567890ABCDEF", []string{"aws-access-key@0-20:1234567890ABCDEF"}},
		{
			"two tokens", "ghp_" + ghBody + " sk_live_abcdefghijklmnopqrstuvwx",
			[]string{"github-pat@0-40:" + ghBody, "stripe-secret-live@41-73:abcdefghijklmnopqrstuvwx"},
		},

		{
			"anthropic", "sk-ant-api03-" + strings.Repeat("aB3_-", 16),
			[]string{"anthropic@0-93:" + strings.Repeat("aB3_-", 16)},
		},
		{
			"open-ended body", "sk_live_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",
			[]string{"stripe-secret-live@0-50:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"},
		},
		{"no boundary needed before a prefix", "X" + "ghp_" + ghBody, []string{"github-pat@1-41:" + ghBody}},
		{
			"body ends where the next token starts", "vercel_abcdefghijklmnopqrstghp_" + ghBody,
			[]string{"vercel@0-27:abcdefghijklmnopqrst", "github-pat@27-67:" + ghBody},
		},
		{"slack-user with three IDs", slackUser, []string{"slack-user@0-62:" + slackUser[5:]}},
		{"sendgrid right before a prefix", sendgridFixture.token + "AKIA", []string{sendgridFixture.spanAt(0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectSpans(t, Scan(tt.text, BuiltinPatterns), tt.want...)
		})
	}
}

func TestScanWithAll(t *testing.T) {
	vercel := builtinsNamed("vercel")
	text := "vercel_abcdefghijklmnopqrstghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	expectSpans(t, Scan(text, vercel), "vercel@0-67:"+text[7:])
	expectSpans(t, ScanWithAll(text, vercel, BuiltinPatterns), "vercel@0-27:abcdefghijklmnopqrst")
}

func TestScanSkipsEmptyStructuredTokens(t *testing.T) {
	caps := structuredPattern("caps", "", "[A-Z]*", AlphanumericUpper,
		func(body string) *StructuredParse {
			return &StructuredParse{Segments: []string{body}, Alphabets: []*Alphabet{AlphanumericUpper}}
		},
		func(segments []string) string { return strings.Join(segments, "") },
	)
	expectSpans(t, Scan("", []TokenPattern{caps}))
	expectSpans(t, Scan("ab CD", []TokenPattern{caps}), "caps@3-5:CD")
}

func TestScanKeepsOverlongTokens(t *testing.T) {
	// The last AWS key ends the Vercel body, even if an earlier one would
	// give a shorter token.
	text := "vercel_" + strings.Repeat("A", 20) + strings.Repeat(awsKey, 40)
	expectSpans(t, Scan(text, BuiltinPatterns),
		"vercel@0-807:"+text[7:807],
		"aws-access-key@807-827:"+strings.Repeat("B", 16))
}

func TestScanCustomBodyRegexes(t *testing.T) {
	find := func(t *testing.T, pattern TokenPattern, text string, want ...string) {
		t.Helper()
		expectSpans(t, Scan(text, append([]TokenPattern{pattern}, BuiltinPatterns...)), want...)
	}
	awsSpan := func(start int) string {
		return fmt.Sprintf("aws-access-key@%d-%d:%s", start, start+20, strings.Repeat("B", 16))
	}

	t.Run("class narrower than the alphabet", func(t *testing.T) {
		p := simplePattern("strict-upper", "foo_", "[A-Z]{8}", Alphanumeric, 8)
		find(t, p, "foo_ABCDEFGH", "strict-upper@0-12:ABCDEFGH")
		find(t, p, "foo_ABCDEFgH")
		find(t, p, "foo_ABCDEFGH"+awsKey, "strict-upper@0-12:ABCDEFGH", awsSpan(12))
		find(t, p, "foo_ABCDEFgH"+awsKey, awsSpan(12))
	})

	t.Run("fixed first character", func(t *testing.T) {
		p := simplePattern("fixed-char", "key-", "X[A-Z0-9]{7}", AlphanumericUpper, 8)
		find(t, p, "key-XABC1234", "fixed-char@0-12:XABC1234")
		find(t, p, "key-YABC1234")
		find(t, p, "key-XABC1234"+awsKey, "fixed-char@0-12:XABC1234", awsSpan(12))
		find(t, p, "key-YABC1234"+awsKey, awsSpan(12))
	})

	t.Run("upper length bound", func(t *testing.T) {
		p := simplePattern("bounded", "tok_", "[A-Za-z0-9]{8,12}", Alphanumeric, 8)
		find(t, p, "tok_"+strings.Repeat("a", 12)+awsKey, "bounded@0-16:"+strings.Repeat("a", 12), awsSpan(16))
		find(t, p, "tok_"+strings.Repeat("a", 13)+awsKey, awsSpan(17))
	})

	for _, bodyRegex := range []string{"[A-Za-z0-9_-]{8}", "X[A-Za-z0-9_-]{7}"} {
		t.Run("separator before the next token with "+bodyRegex, func(t *testing.T) {
			p := simplePattern("punctuated", "tok:", bodyRegex, Base64URL, 8)
			token := "tok:XAAA___-"
			find(t, p, token+"__--"+awsKey, "punctuated@0-12:XAAA___-", awsSpan(16))
			for _, suffix := range []string{"-", "__--AKIAshort", "A-" + awsKey} {
				for _, s := range Scan(token+suffix, append([]TokenPattern{p}, BuiltinPatterns...)) {
					if s.Pattern.Name() == "punctuated" {
						t.Errorf("%q: unexpected %v", token+suffix, describeSpans([]TokenSpan{s}))
					}
				}
			}
		})
	}

	t.Run("token starting at the last body character", func(t *testing.T) {
		inner := simplePattern("inner", "a-", "[0-9]{2}", Digits, 2)
		for _, bodyRegex := range []string{"[a-z]{3,}", "[a-z0-9]{3,}"} {
			outer := simplePattern("outer", "x", bodyRegex, AlphanumericLower, 3)
			expectSpans(t, Scan("xbbba-12", []TokenPattern{outer, inner}), "outer@0-4:bbb", "inner@4-8:12")
		}
	})

	t.Run("minimum length above the regex minimum", func(t *testing.T) {
		outer := simplePattern("outer", "x", "[a-z]{3,}", AlphanumericLower, 3)
		for _, bodyRegex := range []string{"[ab][a-z0-9]+", "[a-z0-9]{2,}"} {
			p := simplePattern("long", "hr_", bodyRegex, AlphanumericLower, 8)
			expectSpans(t, Scan("hr_abxbbbbbb", []TokenPattern{p, outer}), "long@0-12:abxbbbbbb")
		}
	})

	t.Run("no empty body before another token", func(t *testing.T) {
		p := simplePattern("short", "q:", "[A-Z0-9]{0,3}", AlphanumericUpper, 0)
		find(t, p, "q:"+awsKey, awsSpan(2))
	})

	t.Run("class missing one alphabet character", func(t *testing.T) {
		for bodyRegex, rejected := range map[string]string{"[1-9]{4}": "0000", "[02-9]{4}": "1111", "[0-8]{4}": "9999"} {
			p := simplePattern("partial", "n:", bodyRegex, Digits, 4)
			expectSpans(t, Scan("n:2345", []TokenPattern{p}), "partial@0-6:2345")
			expectSpans(t, Scan("n:"+rejected, []TokenPattern{p}))
		}
	})
}

type fixture struct {
	label, name, prefix, token string
}

var (
	sendgridFixture = fixture{"sendgrid", "sendgrid", "SG.", decodeSecret("FT.NOPQRSTUVWXYZABCDEFGHI.NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcd")}
	gitlabFixture   = fixture{"gitlab", "gitlab", "glpat-", decodeSecret("tycng-No1-_No1-_No1-_No1-_")}
	slackFixtures   = []fixture{
		{"slack-bot", "slack-bot", "xoxb-", decodeSecret("kbko-123456789012-1234567890123-NOPQRSTUVWXYZABCDEFGHIJKno")},
		{"slack-user", "slack-user", "xoxp-", decodeSecret("kbkc-123456789012-1234567890123-NOPQRSTUVWXYZABCDEFGHIJKno")},
		{"slack-user with three IDs", "slack-user", "xoxp-", decodeSecret("kbkc-1234567890-9876543210-2468013579-NoPqRsTuVwXyZaBcDeFgHiJk")},
	}
)

func (f fixture) spanAt(start int) string {
	return fmt.Sprintf("%s@%d-%d:%s", f.name, start, start+len(f.token), f.token[len(f.prefix):])
}

// joinFixtures returns the tokens joined by sep, and the spans Scan should
// find in the result.
func joinFixtures(sep string, fixtures ...fixture) (string, []string) {
	var tokens, spans []string
	start := 0
	for _, f := range fixtures {
		tokens = append(tokens, f.token)
		spans = append(spans, f.spanAt(start))
		start += len(f.token) + len(sep)
	}
	return strings.Join(tokens, sep), spans
}

func expectRoundTrip(t *testing.T, text string, count int) {
	t.Helper()
	enc, err := New(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	result, err := enc.EncryptWithSpans(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Spans) != count {
		t.Errorf("encrypted %d tokens, want %d", len(result.Spans), count)
	}
	if back, err := enc.Decrypt(result.Text); err != nil || back != text {
		t.Errorf("Decrypt() = %q, %v", back, err)
	}
}

func TestScanTokensNextToEachOther(t *testing.T) {
	separators := []string{"", "-", "_", "-_--"}
	for _, f := range append([]fixture{sendgridFixture, gitlabFixture}, slackFixtures...) {
		t.Run("four "+f.label+" tokens", func(t *testing.T) {
			for _, sep := range separators {
				text, spans := joinFixtures(sep, f, f, f, f)
				expectSpans(t, Scan(text, BuiltinPatterns), spans...)
				expectRoundTrip(t, text, 4)
			}
		})
	}

	mixed := []fixture{sendgridFixture, gitlabFixture, slackFixtures[0]}
	for _, left := range mixed {
		for _, right := range mixed {
			if left == right {
				continue
			}
			t.Run(left.label+" then "+right.label, func(t *testing.T) {
				for _, sep := range separators {
					text, spans := joinFixtures(sep, left, right)
					expectSpans(t, Scan(text, BuiltinPatterns), spans...)
					expectSpans(t, ScanWithAll(text, builtinsNamed(left.name), BuiltinPatterns), spans[0])
					expectRoundTrip(t, text, 2)
				}
			})
		}
	}
}

func TestScanStopsEarlyOnlyBeforeValidTokens(t *testing.T) {
	for _, f := range []fixture{sendgridFixture, gitlabFixture} {
		t.Run(f.label, func(t *testing.T) {
			for _, suffix := range []string{"Z", "-", "-" + f.prefix + "short"} {
				expectSpans(t, Scan(f.token+suffix, BuiltinPatterns))
			}
			text, spans := joinFixtures("Z", f, f)
			expectSpans(t, Scan(text, BuiltinPatterns), spans[1])
		})
	}

	for _, f := range slackFixtures {
		t.Run(f.label, func(t *testing.T) {
			incomplete := f.token + f.prefix + "12"
			end := len(f.token) + len(f.prefix) - 1
			expectSpans(t, Scan(incomplete, BuiltinPatterns), fmt.Sprintf("%s@0-%d:%s", f.name, end, incomplete[len(f.prefix):end]))

			invalid := "xoxb-1-1-"
			expectSpans(t, Scan(invalid+f.token, BuiltinPatterns), f.spanAt(len(invalid)))
		})
	}
}

func repeatTo(unit string, size int) string {
	if size <= 0 {
		return ""
	}
	return strings.Repeat(unit, size/len(unit)+1)[:size]
}

// These texts are packed with prefixes, which used to make scanning
// quadratic or worse.
var adversarialTexts = []struct {
	name string
	make func(size int) string
}{
	{"AKIA", func(n int) string { return repeatTo("AKIA", n) }},
	{"AWS keys", func(n int) string { return repeatTo(awsKey, n) }},
	{"AIza", func(n int) string { return repeatTo("AIza", n) }},
	{"pypi-", func(n int) string { return repeatTo("pypi-", n) }},
	{"glc_", func(n int) string { return repeatTo("glc_", n) }},
	{"glpat-", func(n int) string { return repeatTo("glpat-", n) }},
	{"vercel_", func(n int) string { return repeatTo("vercel_", n) }},
	{"sk-proj-", func(n int) string { return repeatTo("sk-proj-", n) }},
	{"sk-ant-api03-", func(n int) string { return repeatTo("sk-ant-api03-", n) }},
	{"slack + AWS keys", func(n int) string { return "xoxb-1-1-" + repeatTo(awsKey, n-9) }},
	{"slack + whole AWS keys", func(n int) string {
		text := "xoxb-1-1-" + strings.Repeat(awsKey, (n-9)/20)
		return text + strings.Repeat(" ", n-len(text))
	}},
	{"slack + Twilio keys", func(n int) string { return "xoxb-1-1-" + repeatTo("SK"+strings.Repeat("a", 32), n-9) }},
	{"slack + AIza", func(n int) string { return "xoxb-1-1-" + repeatTo("AIza", n-9) }},
	{"slack user + glc_", func(n int) string { return "xoxp-1-1-1-" + repeatTo("glc_", n-11) }},
	{"sendgrid + AIza", func(n int) string { return "SG." + repeatTo("AIza", n-3) }},
	{"adjacent Slack tokens", func(n int) string { return repeatTo(slackFixtures[0].token, n) }},
	{"dash-separated SendGrid tokens", func(n int) string { return repeatTo(sendgridFixture.token+"-", n) }},
	{"dash-separated GitLab tokens", func(n int) string { return repeatTo(gitlabFixture.token+"-", n) }},
	{"GitLab tokens with a long separator", func(n int) string {
		token := gitlabFixture.token
		return token + strings.Repeat("-", max(0, n-2*len(token))) + token
	}},
	{"mixed", func(n int) string { return repeatTo("AKIAglc_AIzasbp_pypi-hf_SKnpm_vercel_sk-proj-xoxb-1-1-", n) }},
}

func TestScanAdversarialTexts(t *testing.T) {
	const size = 200_000
	const limit = time.Second
	for _, a := range adversarialTexts {
		text := a.make(size)
		done := make(chan time.Duration, 1)
		go func() {
			start := time.Now()
			Scan(text, BuiltinPatterns)
			done <- time.Since(start)
		}()
		select {
		case elapsed := <-done:
			if elapsed > limit {
				t.Errorf("%s: %v", a.name, elapsed)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: still scanning after 30s", a.name)
		}
	}
}

func TestFindAllPositions(t *testing.T) {
	if got := findAllPositions("abc-abc-abc", "abc"); !slices.Equal(got, []int{0, 4, 8}) {
		t.Errorf("got %v", got)
	}
	if got := findAllPositions("aaaa", "aa"); !slices.Equal(got, []int{0, 1, 2}) {
		t.Errorf("overlapping: got %v", got)
	}
}

func BenchmarkScanShortText(b *testing.B) {
	for b.Loop() {
		Scan("a short sentence", BuiltinPatterns)
	}
}

func BenchmarkScanAdversarial(b *testing.B) {
	for _, a := range adversarialTexts {
		text := a.make(200_000)
		b.Run(a.name, func(b *testing.B) {
			for b.Loop() {
				Scan(text, BuiltinPatterns)
			}
		})
	}
}
