package tokens

import (
	"strings"
)

func simplePattern(name, prefix, bodyRegex string, alphabet *Alphabet, minBodyLength int) SimpleTokenPattern {
	return SimpleTokenPattern{
		name:          name,
		prefix:        prefix,
		bodyRegex:     bodyRegex,
		bodyAlphabet:  alphabet,
		minBodyLength: minBodyLength,
	}
}

func heuristicPattern(name string, alphabet *Alphabet, minLen, maxLen int, minEntropy float64, minCharClasses int) HeuristicTokenPattern {
	return HeuristicTokenPattern{
		name:           name,
		bodyAlphabet:   alphabet,
		minLength:      minLen,
		maxLength:      maxLen,
		minEntropy:     minEntropy,
		minCharClasses: minCharClasses,
	}
}

func makeSlackPattern(prefix, name string) StructuredTokenPattern {
	return StructuredTokenPattern{
		name:             name,
		prefix:           prefix,
		fullRegex:        prefix + `\d+-\d+-[A-Za-z0-9]+`,
		trailingAlphabet: Alphanumeric,
		parseFn: func(body string) *StructuredParse {
			parts := strings.Split(body, "-")
			if len(parts) < 3 {
				return nil
			}
			totalLen := 0
			for _, p := range parts {
				totalLen += len(p)
			}
			if totalLen < 20 {
				return nil
			}
			alphabets := make([]*Alphabet, len(parts))
			for i, part := range parts {
				if len(part) == 0 {
					return nil
				}
				switch {
				case Digits.ContainsAll(part):
					alphabets[i] = Digits
				case Alphanumeric.ContainsAll(part):
					alphabets[i] = Alphanumeric
				default:
					return nil
				}
			}
			return &StructuredParse{Segments: parts, Alphabets: alphabets}
		},
		formatFn: func(segments []string) string {
			return strings.Join(segments, "-")
		},
	}
}

var sendgridPattern = StructuredTokenPattern{
	name:             "sendgrid",
	prefix:           "SG.",
	fullRegex:        `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`,
	trailingAlphabet: Base64URL,
	parseFn: func(body string) *StructuredParse {
		dotIdx := strings.IndexByte(body, '.')
		if dotIdx == -1 {
			return nil
		}
		seg1 := body[:dotIdx]
		seg2 := body[dotIdx+1:]
		if len(seg1) != 22 || len(seg2) != 43 {
			return nil
		}
		return &StructuredParse{
			Segments:  []string{seg1, seg2},
			Alphabets: []*Alphabet{Base64URL, Base64URL},
		}
	},
	formatFn: func(segments []string) string {
		return segments[0] + "." + segments[1]
	},
}

// BuiltinPatterns contains all 28 built-in token patterns in canonical
// registry order matching the JS and Python implementations. Structured
// patterns are interleaved with simple patterns by prefix length; heuristic
// patterns come last. The scanner depends on this ordering for overlap
// resolution.
var BuiltinPatterns = []TokenPattern{
	simplePattern("anthropic", "sk-ant-api03-", "[A-Za-z0-9_-]{80,}", Base64URL, 80),
	simplePattern("openai", "sk-proj-", "[A-Za-z0-9_-]{48,}", Base64URL, 48),
	simplePattern("openai-legacy", "sk-", "[A-Za-z0-9]{48}", Alphanumeric, 48),
	simplePattern("stripe-secret-live", "sk_live_", "[A-Za-z0-9]{24,}", Alphanumeric, 24),
	simplePattern("stripe-publish-live", "pk_live_", "[A-Za-z0-9]{24,}", Alphanumeric, 24),
	simplePattern("stripe-secret-test", "sk_test_", "[A-Za-z0-9]{24,}", Alphanumeric, 24),
	simplePattern("stripe-publish-test", "pk_test_", "[A-Za-z0-9]{24,}", Alphanumeric, 24),
	simplePattern("vercel", "vercel_", "[A-Za-z0-9_-]{20,}", Base64URL, 20),
	simplePattern("gitlab", "glpat-", "[A-Za-z0-9_-]{20}", Base64URL, 20),
	simplePattern("datadog", "ddapi_", "[a-z0-9]{40}", AlphanumericLower, 40),
	simplePattern("pypi", "pypi-", "[A-Za-z0-9_-]{50,}", Base64URL, 50),
	makeSlackPattern("xoxb-", "slack-bot"),
	makeSlackPattern("xoxp-", "slack-user"),
	simplePattern("github-pat", "ghp_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	simplePattern("github-oauth", "gho_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	simplePattern("github-user", "ghu_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	simplePattern("github-server", "ghs_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	simplePattern("github-refresh", "ghr_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	simplePattern("aws-access-key", "AKIA", "[A-Z0-9]{16}", AlphanumericUpper, 16),
	simplePattern("google-api", "AIza", "[A-Za-z0-9_-]{35}", Base64URL, 35),
	simplePattern("npm", "npm_", "[A-Za-z0-9]{36}", Alphanumeric, 36),
	simplePattern("supabase", "sbp_", "[a-f0-9]{40}", HexLower, 40),
	simplePattern("grafana", "glc_", "[A-Za-z0-9_-]{30,}", Base64URL, 30),
	simplePattern("huggingface", "hf_", "[A-Za-z0-9]{34}", Alphanumeric, 34),
	sendgridPattern,
	simplePattern("twilio", "SK", "[a-f0-9]{32}", HexLower, 32),
	heuristicPattern("fastly", Base64URL, 32, 32, 4.0, 3),
	heuristicPattern("aws-secret-key", Base64, 40, 40, 4.0, 3),
}
