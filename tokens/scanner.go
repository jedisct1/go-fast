package tokens

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

func resolveOverlaps(candidates []TokenSpan) []TokenSpan {
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		pl1, pl2 := len(a.Pattern.Prefix()), len(b.Pattern.Prefix())
		if pl1 != pl2 {
			return pl1 > pl2
		}
		return (a.End - a.Start) > (b.End - b.Start)
	})

	var result []TokenSpan
	lastEnd := 0
	for _, s := range candidates {
		if s.Start >= lastEnd {
			result = append(result, s)
			lastEnd = s.End
		}
	}
	return result
}

// TokenSpan is an intermediate match found during scanning, before encryption.
type TokenSpan struct {
	Start   int
	End     int
	Pattern TokenPattern
	Body    string
}

func appendTokenSpan(candidates *[]TokenSpan, start, end int, pattern TokenPattern, body string) {
	*candidates = append(*candidates, TokenSpan{
		Start:   start,
		End:     end,
		Pattern: pattern,
		Body:    body,
	})
}

// Scan finds all non-overlapping token matches in text using the given
// patterns. Results are sorted by position, with longer prefixes and longer
// matches preferred at the same position. Heuristic patterns are skipped;
// use ScanHeuristic for those.
func Scan(text string, patterns []TokenPattern) []TokenSpan {
	return ScanWithAll(text, patterns, patterns)
}

// ScanWithAll is like Scan but accepts a separate allPatterns list used for
// nested-prefix truncation checks. This matters when scanning with a subset
// of patterns but needing to resolve overlaps against the full registry.
func ScanWithAll(text string, patterns []TokenPattern, allPatterns []TokenPattern) []TokenSpan {
	prefixPositions := buildPrefixPositions(text, allPatterns)

	var candidates []TokenSpan
	for _, p := range patterns {
		switch pat := p.(type) {
		case SimpleTokenPattern:
			scanSimple(text, pat, prefixPositions, allPatterns, &candidates)
		case StructuredTokenPattern:
			scanStructured(text, pat, prefixPositions, allPatterns, &candidates)
		}
	}

	return resolveOverlaps(candidates)
}

func buildPrefixPositions(text string, patterns []TokenPattern) map[int]struct{} {
	seen := make(map[string]struct{})
	var prefixes []string
	for _, p := range patterns {
		pfx := p.Prefix()
		if pfx == "" {
			continue
		}
		if _, ok := seen[pfx]; !ok {
			seen[pfx] = struct{}{}
			prefixes = append(prefixes, pfx)
		}
	}

	positions := make(map[int]struct{})
	for _, pfx := range prefixes {
		for _, pos := range findAllPositions(text, pfx) {
			positions[pos] = struct{}{}
		}
	}
	return positions
}

func findAllPositions(text, needle string) []int {
	var positions []int
	idx := 0
	for idx <= len(text)-len(needle) {
		pos := strings.Index(text[idx:], needle)
		if pos == -1 {
			break
		}
		positions = append(positions, idx+pos)
		idx = idx + pos + 1
	}
	return positions
}

func isWordBoundary(text string, pos int) bool {
	if pos == 0 {
		return true
	}
	return isNonWordChar(text[pos-1])
}

func isWordBoundaryEnd(text string, pos int) bool {
	if pos >= len(text) {
		return true
	}
	return isNonWordChar(text[pos])
}

func hasTrailingAlphabetChar(text string, pos int, alphabet *Alphabet, prefixPositions map[int]struct{}) bool {
	if pos >= len(text) || !alphabet.Contains(text[pos]) {
		return false
	}
	_, isPrefix := prefixPositions[pos]
	return !isPrefix
}

func isNonWordChar(c byte) bool {
	if c >= 'A' && c <= 'Z' {
		return false
	}
	if c >= 'a' && c <= 'z' {
		return false
	}
	if c >= '0' && c <= '9' {
		return false
	}
	if c == '_' || c == '-' {
		return false
	}
	return true
}

var (
	bodyValidatorCache sync.Map // map[string]*regexp.Regexp
)

func getBodyValidator(pattern SimpleTokenPattern) *regexp.Regexp {
	if v, ok := bodyValidatorCache.Load(pattern.bodyRegex); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile("^(?:" + pattern.bodyRegex + ")$")
	bodyValidatorCache.Store(pattern.bodyRegex, re)
	return re
}

func scanSimple(
	text string,
	pattern SimpleTokenPattern,
	prefixPositions map[int]struct{},
	allPatterns []TokenPattern,
	candidates *[]TokenSpan,
) {
	positions := findAllPositions(text, pattern.prefix)
	validator := getBodyValidator(pattern)

	validate := func(body string) bool {
		return len(body) >= pattern.minBodyLength && validator.MatchString(body)
	}

	for _, pos := range positions {
		if !isWordBoundary(text, pos) {
			continue
		}

		bodyStart := pos + len(pattern.prefix)
		bodyEnd := bodyStart
		for bodyEnd < len(text) && pattern.bodyAlphabet.Contains(text[bodyEnd]) {
			bodyEnd++
		}

		if bodyEnd-bodyStart < pattern.minBodyLength {
			continue
		}

		truncEnd := findTruncatedEnd(text, bodyStart, bodyEnd, prefixPositions, allPatterns, validate)
		if truncEnd != -1 {
			body := text[bodyStart:truncEnd]
			appendTokenSpan(candidates, pos, truncEnd, pattern, body)
			continue
		}

		body := text[bodyStart:bodyEnd]
		if validate(body) {
			appendTokenSpan(candidates, pos, bodyEnd, pattern, body)
		}
	}
}

func scanStructured(
	text string,
	pattern StructuredTokenPattern,
	prefixPositions map[int]struct{},
	allPatterns []TokenPattern,
	candidates *[]TokenSpan,
) {
	for _, loc := range pattern.compiledRegex.FindAllStringIndex(text, -1) {
		matchStart, matchEnd := loc[0], loc[1]

		if !isWordBoundary(text, matchStart) {
			continue
		}

		bodyStart := matchStart + len(pattern.prefix)

		truncEnd := findTruncatedEnd(
			text, bodyStart, matchEnd, prefixPositions, allPatterns,
			func(body string) bool { return pattern.Parse(body) != nil },
		)
		if truncEnd != -1 {
			body := text[bodyStart:truncEnd]
			appendTokenSpan(candidates, matchStart, truncEnd, pattern, body)
			continue
		}

		body := text[bodyStart:matchEnd]
		if pattern.Parse(body) != nil {
			if hasTrailingAlphabetChar(text, matchEnd, pattern.trailingAlphabet, prefixPositions) {
				continue
			}
			appendTokenSpan(candidates, matchStart, matchEnd, pattern, body)
		}
	}
}

func findTruncatedEnd(
	text string,
	bodyStart, bodyEnd int,
	prefixPositions map[int]struct{},
	allPatterns []TokenPattern,
	validateLeft func(string) bool,
) int {
	var splits []int
	for i := bodyStart + 1; i < bodyEnd; i++ {
		if _, ok := prefixPositions[i]; ok {
			splits = append(splits, i)
		}
	}
	if len(splits) == 0 {
		return -1
	}

	for i := len(splits) - 1; i >= 0; i-- {
		splitPos := splits[i]
		leftBody := text[bodyStart:splitPos]
		if !validateLeft(leftBody) {
			continue
		}
		if wouldMatchAt(text, splitPos, prefixPositions, allPatterns) {
			return splitPos
		}
	}
	return -1
}

func wouldMatchAt(
	text string,
	pos int,
	prefixPositions map[int]struct{},
	allPatterns []TokenPattern,
) bool {
	for _, p := range allPatterns {
		switch pat := p.(type) {
		case SimpleTokenPattern:
			if !strings.HasPrefix(text[pos:], pat.prefix) {
				continue
			}
			if wouldMatchSimpleAt(text, pos, pat, prefixPositions, allPatterns) {
				return true
			}
		case StructuredTokenPattern:
			if !strings.HasPrefix(text[pos:], pat.prefix) {
				continue
			}
			if wouldMatchStructuredAt(text, pos, pat, prefixPositions, allPatterns) {
				return true
			}
		}
	}
	return false
}

func wouldMatchSimpleAt(
	text string,
	pos int,
	pattern SimpleTokenPattern,
	prefixPositions map[int]struct{},
	allPatterns []TokenPattern,
) bool {
	bodyStart := pos + len(pattern.prefix)
	bodyEnd := bodyStart
	for bodyEnd < len(text) && pattern.bodyAlphabet.Contains(text[bodyEnd]) {
		bodyEnd++
	}

	if bodyEnd-bodyStart < pattern.minBodyLength {
		return false
	}

	validator := getBodyValidator(pattern)
	validate := func(body string) bool {
		return len(body) >= pattern.minBodyLength && validator.MatchString(body)
	}

	truncEnd := findTruncatedEnd(text, bodyStart, bodyEnd, prefixPositions, allPatterns, validate)
	if truncEnd != -1 {
		return true
	}

	return validate(text[bodyStart:bodyEnd])
}

func wouldMatchStructuredAt(
	text string,
	pos int,
	pattern StructuredTokenPattern,
	prefixPositions map[int]struct{},
	allPatterns []TokenPattern,
) bool {
	loc := pattern.compiledRegex.FindStringIndex(text[pos:])
	if loc == nil || loc[0] != 0 {
		return false
	}

	matchEnd := pos + loc[1]
	bodyStart := pos + len(pattern.prefix)

	truncEnd := findTruncatedEnd(
		text, bodyStart, matchEnd, prefixPositions, allPatterns,
		func(body string) bool { return pattern.Parse(body) != nil },
	)
	if truncEnd != -1 {
		return true
	}

	body := text[bodyStart:matchEnd]
	if pattern.Parse(body) != nil {
		if hasTrailingAlphabetChar(text, matchEnd, pattern.trailingAlphabet, prefixPositions) {
			return false
		}
		return true
	}

	return false
}
