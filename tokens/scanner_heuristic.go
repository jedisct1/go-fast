package tokens

import "math"

func scanHeuristic(text string, p TokenPattern, candidates []TokenSpan) []TokenSpan {
	pattern := p.(HeuristicTokenPattern)
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
				candidates = append(candidates, TokenSpan{Start: i, End: end, Pattern: p, Body: body})
			}
		}

		i = end
	}
	return candidates
}

func isWordBoundary(text string, pos int) bool {
	return pos == 0 || isNonWordChar(text[pos-1])
}

func isWordBoundaryEnd(text string, pos int) bool {
	return pos >= len(text) || isNonWordChar(text[pos])
}

func isNonWordChar(c byte) bool {
	return !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-')
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
