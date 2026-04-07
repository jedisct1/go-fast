package tokens

import "math"

// ScanHeuristic finds tokens that match heuristic patterns (no prefix,
// entropy/character-class based). Results are non-overlapping and sorted
// by position. Prefix-based patterns in the list are silently skipped.
func ScanHeuristic(text string, patterns []TokenPattern) []TokenSpan {
	var candidates []TokenSpan
	for _, p := range patterns {
		hp, ok := p.(HeuristicTokenPattern)
		if !ok {
			continue
		}
		scanHeuristic(text, hp, &candidates)
	}
	return resolveOverlaps(candidates)
}

// ScanAll runs both prefix-based and heuristic scanning, returning a single
// merged, non-overlapping result sorted by position. Prefix matches take
// priority over heuristic matches at the same position.
func ScanAll(text string, patterns []TokenPattern) []TokenSpan {
	return ScanAllWithAll(text, patterns, patterns)
}

// ScanAllWithAll is like ScanAll but accepts a separate allPatterns list used
// for nested-prefix truncation in the prefix scanner. Use this when scanning
// with a filtered subset of patterns but needing truncation to consider the
// full registry.
func ScanAllWithAll(text string, patterns []TokenPattern, allPatterns []TokenPattern) []TokenSpan {
	prefixSpans := ScanWithAll(text, patterns, allPatterns)
	heuristicSpans := ScanHeuristic(text, patterns)

	all := make([]TokenSpan, 0, len(prefixSpans)+len(heuristicSpans))
	all = append(all, prefixSpans...)
	all = append(all, heuristicSpans...)
	return resolveOverlaps(all)
}

func scanHeuristic(text string, pattern HeuristicTokenPattern, candidates *[]TokenSpan) {
	i := 0
	for i < len(text) {
		if !pattern.bodyAlphabet.Contains(text[i]) {
			i++
			continue
		}

		if !isWordBoundary(text, i) {
			for i < len(text) && pattern.bodyAlphabet.Contains(text[i]) {
				i++
			}
			continue
		}

		end := i
		for end < len(text) && pattern.bodyAlphabet.Contains(text[end]) {
			end++
		}

		length := end - i
		if length >= pattern.minLength && length <= pattern.maxLength && isWordBoundaryEnd(text, end) {
			body := text[i:end]
			if countCharClasses(body) >= pattern.minCharClasses && shannonEntropy(body) >= pattern.minEntropy {
				*candidates = append(*candidates, TokenSpan{
					Start:   i,
					End:     end,
					Pattern: pattern,
					Body:    body,
				})
			}
		}

		i = end
	}
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func countCharClasses(s string) int {
	var hasUpper, hasLower, hasDigit, hasOther bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasOther = true
		}
	}
	n := 0
	if hasUpper {
		n++
	}
	if hasLower {
		n++
	}
	if hasDigit {
		n++
	}
	if hasOther {
		n++
	}
	return n
}
