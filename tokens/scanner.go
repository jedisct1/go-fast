package tokens

import (
	"cmp"
	"math"
	"regexp/syntax"
	"slices"
	"strings"
)

// TokenSpan is a token found by Scan.
type TokenSpan struct {
	Start   int
	End     int
	Pattern TokenPattern
	Body    string
}

// Scan finds the tokens in text that match one of the patterns.
//
// When matches overlap, the earliest one wins, then the one with the longest
// prefix, then the longest one.
func Scan(text string, patterns []TokenPattern) []TokenSpan {
	return ScanWithAll(text, patterns, patterns)
}

// ScanWithAll is like Scan, but tokens matching allPatterns can end the body
// of the token before them even when they are not returned.
//
// This keeps a scan for a few patterns consistent with a scan for all of them.
func ScanWithAll(text string, patterns, allPatterns []TokenPattern) []TokenSpan {
	b := newBoundaries(text, allPatterns)
	var candidates []TokenSpan
	for _, p := range patterns {
		switch p.(type) {
		case SimpleTokenPattern, StructuredTokenPattern:
			candidates = b.scanPrefixed(p, candidates)
		case HeuristicTokenPattern:
			candidates = scanHeuristic(text, p, candidates)
		}
	}

	slices.SortStableFunc(candidates, func(a, b TokenSpan) int {
		return cmp.Or(
			cmp.Compare(a.Start, b.Start),
			cmp.Compare(len(b.Pattern.Prefix()), len(a.Pattern.Prefix())),
			cmp.Compare(b.End-b.Start, a.End-a.Start),
		)
	})

	result := candidates[:0]
	lastEnd := 0
	for _, span := range candidates {
		if span.Start >= lastEnd {
			result = append(result, span)
			lastEnd = span.End
		}
	}
	return result
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
		idx += pos + 1
	}
	return positions
}

type lengthBounds struct {
	min, max int
}

// bodyLengthBounds returns the allowed body lengths when they are all that
// bodyRegex checks, and nil otherwise.
//
// That's the case for a single character class with a length, such as
// [A-Za-z0-9]{32}, when the class accepts the whole alphabet.
// Bodies only contain alphabet characters, so checking the length is then
// enough, and much faster than running the regex.
func bodyLengthBounds(bodyRegex string, alphabet *Alphabet, minBodyLength int) *lengthBounds {
	re, err := syntax.Parse(bodyRegex, syntax.Perl)
	if err != nil || re.Op != syntax.OpRepeat || re.Sub[0].Op != syntax.OpCharClass {
		return nil
	}
	ranges := re.Sub[0].Rune
	for _, c := range alphabet.chars {
		inClass := false
		for i := 0; i < len(ranges) && !inClass; i += 2 {
			inClass = ranges[i] <= c && c <= ranges[i+1]
		}
		if !inClass {
			return nil
		}
	}
	hi := re.Max
	if hi == -1 {
		hi = math.MaxInt
	}
	return &lengthBounds{min: max(re.Min, minBodyLength), max: hi}
}

// lastIndexAtMost returns the index of the last value at most limit in
// values, or -1 if there is none.
func lastIndexAtMost(values []int, limit int) int {
	lo, hi := 0, len(values)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if values[mid] <= limit {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo - 1
}

func isSeparator(c byte) bool {
	return c == '-' || c == '_'
}

// runEnds finds where a run of alphabet characters ends.
//
// It remembers the last run, so that going through positions in order reads
// each character only once.
type runEnds struct {
	text       string
	alphabet   *Alphabet
	start, end int
}

func newRunEnds(text string, alphabet *Alphabet) runEnds {
	return runEnds{text: text, alphabet: alphabet, start: -1, end: -2}
}

func (r *runEnds) from(pos int) int {
	if pos >= r.start && pos <= r.end {
		return r.end
	}
	end := pos
	for end < len(r.text) && r.alphabet.Contains(r.text[end]) {
		if end == r.start {
			end = r.end
			break
		}
		end++
	}
	r.start = pos
	r.end = end
	return end
}

// boundaries knows where token bodies can stop early in one text: where
// another token starts, or on the dashes and underscores right before it.
//
// Whether a token starts somewhere only depends on the text after it.
// So prefix positions are checked once, from the end of the text backward,
// and each check can use what was found to its right.
type boundaries struct {
	text       string
	prefixed   []prefixedPattern
	byFirst    [256]int32
	unprefixed []TokenPattern
	positions  []int
	ends       []int
}

// prefixedPattern is a simple or structured pattern with a prefix, linked to
// the next one whose prefix starts with the same byte.
type prefixedPattern struct {
	pattern   TokenPattern
	prefix    string
	next      int32
	positions []int
}

func newBoundaries(text string, allPatterns []TokenPattern) boundaries {
	b := boundaries{text: text}
	for _, p := range allPatterns {
		switch p.(type) {
		case SimpleTokenPattern, StructuredTokenPattern:
		default:
			continue
		}
		prefix := p.Prefix()
		if prefix == "" {
			b.unprefixed = append(b.unprefixed, p)
			continue
		}
		if b.prefixed == nil {
			b.prefixed = make([]prefixedPattern, 0, len(allPatterns))
		}
		b.prefixed = append(b.prefixed, prefixedPattern{pattern: p, prefix: prefix, next: b.byFirst[prefix[0]]})
		b.byFirst[prefix[0]] = int32(len(b.prefixed))
	}
	if len(b.prefixed) == 0 {
		return b
	}

	for i := range len(text) {
		found := false
		for j := b.byFirst[text[i]]; j != 0; j = b.prefixed[j-1].next {
			if pp := &b.prefixed[j-1]; strings.HasPrefix(text[i:], pp.prefix) {
				pp.positions = append(pp.positions, i)
				found = true
			}
		}
		if found {
			b.positions = append(b.positions, i)
		}
	}
	if len(b.positions) > 0 {
		b.findEnds()
	}
	return b
}

func (b *boundaries) findEnds() {
	text := b.text
	runs := make([]runEnds, len(b.prefixed)+len(b.unprefixed))
	var buf []int
	first := 0
	lowestEnd := len(text) + 1
	for k := len(b.positions) - 1; k >= 0; k-- {
		pos := b.positions[k]
		// Already a valid end, in the separators before a later token.
		if pos >= lowestEnd || !b.tokenStartsAt(pos, runs) {
			continue
		}
		if buf == nil {
			buf = make([]int, k+1+strings.Count(text[:pos], "-")+strings.Count(text[:pos], "_"))
			first = len(buf)
		}
		lowestEnd = pos
		for lowestEnd > 0 && isSeparator(text[lowestEnd-1]) {
			lowestEnd--
		}
		for end := pos; end >= lowestEnd; end-- {
			first--
			buf[first] = end
		}
		b.ends = buf[first:]
	}
}

func (b *boundaries) tokenStartsAt(pos int, runs []runEnds) bool {
	for j := b.byFirst[b.text[pos]]; j != 0; j = b.prefixed[j-1].next {
		pp := &b.prefixed[j-1]
		if strings.HasPrefix(b.text[pos:], pp.prefix) && b.tokenEnd(pp.pattern, pos, &runs[j-1]) != -1 {
			return true
		}
	}
	for i, p := range b.unprefixed {
		if b.tokenEnd(p, pos, &runs[len(b.prefixed)+i]) != -1 {
			return true
		}
	}
	return false
}

func (b *boundaries) occurrencesOf(prefix string) []int {
	if prefix != "" {
		for j := b.byFirst[prefix[0]]; j != 0; j = b.prefixed[j-1].next {
			if pp := &b.prefixed[j-1]; pp.prefix == prefix {
				return pp.positions
			}
		}
	}
	return findAllPositions(b.text, prefix)
}

// tokenEnd returns where a token of pattern p starting at pos ends, or -1.
func (b *boundaries) tokenEnd(p TokenPattern, pos int, runs *runEnds) int {
	switch pat := p.(type) {
	case SimpleTokenPattern:
		if runs.alphabet == nil {
			*runs = newRunEnds(b.text, pat.bodyAlphabet)
		}
		return b.simpleEnd(&pat, pos, runs)
	case StructuredTokenPattern:
		return b.structuredEnd(&pat, pos)
	}
	return -1
}

// simpleEnd returns where a simple token starting at pos ends, or -1.
//
// The body takes the whole run of alphabet characters, unless it can stop
// earlier before another token.
// The longest valid body wins.
func (b *boundaries) simpleEnd(p *SimpleTokenPattern, pos int, runs *runEnds) int {
	bodyStart := pos + len(p.prefix)
	bodyEnd := runs.from(bodyStart)
	length := bodyEnd - bodyStart
	if length < p.minBodyLength {
		return -1
	}

	if bounds := p.lengthBounds; bounds != nil {
		k := lastIndexAtMost(b.ends, bodyStart+min(length, bounds.max))
		if k >= 0 && b.ends[k] >= bodyStart+max(bounds.min, 1) {
			return b.ends[k]
		}
		if length >= bounds.min && length <= bounds.max {
			return bodyEnd
		}
		return -1
	}

	validate := func(body string) bool {
		return len(body) >= p.minBodyLength && p.bodyValidator.MatchString(body)
	}
	if end := b.split(bodyStart, bodyEnd, validate); end != -1 {
		return end
	}
	if validate(b.text[bodyStart:bodyEnd]) {
		return bodyEnd
	}
	return -1
}

// structuredEnd returns where a structured token starting at pos ends, or -1.
func (b *boundaries) structuredEnd(p *StructuredTokenPattern, pos int) int {
	loc := p.regex.FindStringIndex(b.text[pos:])
	if loc == nil {
		return -1
	}
	matchEnd := pos + loc[1]
	bodyStart := pos + len(p.prefix)
	validate := func(body string) bool {
		return p.Parse(body) != nil
	}
	if end := b.split(bodyStart, matchEnd, validate); end != -1 {
		return end
	}
	if !validate(b.text[bodyStart:matchEnd]) {
		return -1
	}
	if matchEnd < len(b.text) && p.trailingAlphabet.Contains(b.text[matchEnd]) && !b.isPrefixPosition(matchEnd) {
		return -1
	}
	return matchEnd
}

// split returns the end of the longest valid body that stops before another
// token, or -1.
func (b *boundaries) split(bodyStart, bodyEnd int, validateLeft func(string) bool) int {
	for k := lastIndexAtMost(b.ends, bodyEnd); k >= 0; k-- {
		end := b.ends[k]
		if end <= bodyStart {
			break
		}
		if validateLeft(b.text[bodyStart:end]) {
			return end
		}
	}
	return -1
}

func (b *boundaries) isPrefixPosition(pos int) bool {
	_, found := slices.BinarySearch(b.positions, pos)
	return found
}

func (b *boundaries) scanPrefixed(p TokenPattern, candidates []TokenSpan) []TokenSpan {
	_, structured := p.(StructuredTokenPattern)
	var runs runEnds
	for _, pos := range b.occurrencesOf(p.Prefix()) {
		end := b.tokenEnd(p, pos, &runs)
		// A structured regex that matches nothing doesn't make a token.
		if end == -1 || structured && end == pos {
			continue
		}
		candidates = append(candidates, TokenSpan{Start: pos, End: end, Pattern: p, Body: b.text[pos+len(p.Prefix()) : end]})
	}
	return candidates
}
