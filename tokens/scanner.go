package tokens

import (
	"cmp"
	"math"
	"regexp"
	"slices"
	"strconv"
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
		switch pat := p.(type) {
		case SimpleTokenPattern:
			candidates = scanSimple(text, p, &pat, b, candidates)
		case StructuredTokenPattern:
			candidates = scanStructured(text, p, &pat, b, candidates)
		case HeuristicTokenPattern:
			candidates = scanHeuristic(text, p, &pat, candidates)
		}
	}

	slices.SortStableFunc(candidates, func(a, b TokenSpan) int {
		if a.Start != b.Start {
			return cmp.Compare(a.Start, b.Start)
		}
		if la, lb := len(a.Pattern.Prefix()), len(b.Pattern.Prefix()); la != lb {
			return cmp.Compare(lb, la)
		}
		return cmp.Compare(b.End-b.Start, a.End-a.Start)
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

var characterClassWithLength = regexp.MustCompile(`^(\[(?:[^\\\[\]]|\\.)+\])\{(\d{1,9})(?:(,)(\d{0,9}))?\}$`)

// bodyLengthBounds returns the allowed body lengths when they are all that
// bodyRegex checks, and nil otherwise.
//
// That's the case for a single character class with a length, such as
// [A-Za-z0-9]{32}, when the class accepts the whole alphabet.
// Bodies only contain alphabet characters, so checking the length is then
// enough, and much faster than running the regex.
func bodyLengthBounds(bodyRegex string, alphabet *Alphabet, minBodyLength int) *lengthBounds {
	m := characterClassWithLength.FindStringSubmatch(bodyRegex)
	if m == nil {
		return nil
	}
	class, err := regexp.Compile("^" + m[1] + "$")
	if err != nil {
		return nil
	}
	for i := range len(alphabet.chars) {
		if !class.MatchString(alphabet.chars[i : i+1]) {
			return nil
		}
	}
	lo, err := strconv.Atoi(m[2])
	if err != nil {
		return nil
	}
	hi := lo
	if m[3] != "" {
		hi = math.MaxInt
		if m[4] != "" {
			if hi, err = strconv.Atoi(m[4]); err != nil {
				return nil
			}
		}
	}
	return &lengthBounds{min: max(lo, minBodyLength), max: hi}
}

// lastIndexAtMost returns the index of the last value at most limit in
// values[from:], or from-1 if there is none.
func lastIndexAtMost(values []int, from, limit int) int {
	lo, hi := from, len(values)
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

type startCheck struct {
	prefix     string
	simple     *SimpleTokenPattern
	structured *StructuredTokenPattern
	runs       runEnds
}

// boundaries knows where token bodies can stop early in one text: where
// another token starts, or on the dashes and underscores right before it.
//
// Whether a token starts somewhere only depends on the text after it.
// So prefix positions are checked once, from the end of the text backward,
// and each check can use what was found to its right.
type boundaries struct {
	text        string
	occurrences map[string][]int
	positions   []int
	ends        []int
	first       int
}

func newBoundaries(text string, allPatterns []TokenPattern) *boundaries {
	b := &boundaries{text: text}
	var found []int
	for _, p := range allPatterns {
		prefix := p.Prefix()
		if prefix == "" {
			continue
		}
		if _, seen := b.occurrences[prefix]; seen {
			continue
		}
		if b.occurrences == nil {
			b.occurrences = make(map[string][]int)
		}
		positions := findAllPositions(text, prefix)
		b.occurrences[prefix] = positions
		found = append(found, positions...)
	}
	if len(found) == 0 {
		return b
	}
	slices.Sort(found)
	b.positions = slices.Compact(found)
	b.ends = make([]int, len(b.positions)+strings.Count(text, "-")+strings.Count(text, "_"))
	b.first = len(b.ends)
	b.findEnds(allPatterns)
	return b
}

func (b *boundaries) findEnds(allPatterns []TokenPattern) {
	text := b.text
	checks := make([]startCheck, 0, len(allPatterns))
	for _, p := range allPatterns {
		switch pat := p.(type) {
		case SimpleTokenPattern:
			checks = append(checks, startCheck{prefix: pat.prefix, simple: &pat, runs: newRunEnds(text, pat.bodyAlphabet)})
		case StructuredTokenPattern:
			checks = append(checks, startCheck{prefix: pat.prefix, structured: &pat})
		}
	}
	byFirstByte := make(map[byte][]*startCheck)
	var unprefixed []*startCheck
	for i := range checks {
		c := &checks[i]
		if c.prefix == "" {
			unprefixed = append(unprefixed, c)
		} else {
			byFirstByte[c.prefix[0]] = append(byFirstByte[c.prefix[0]], c)
		}
	}

	lowestEnd := len(text) + 1
	for k := len(b.positions) - 1; k >= 0; k-- {
		pos := b.positions[k]
		// Already a valid end, in the separators before a later token.
		if pos >= lowestEnd {
			continue
		}
		if !b.tokenStartsAt(pos, byFirstByte[text[pos]]) && !b.tokenStartsAt(pos, unprefixed) {
			continue
		}
		lowestEnd = pos
		for lowestEnd > 0 && isSeparator(text[lowestEnd-1]) {
			lowestEnd--
		}
		for end := pos; end >= lowestEnd; end-- {
			b.first--
			b.ends[b.first] = end
		}
	}
}

func (b *boundaries) tokenStartsAt(pos int, checks []*startCheck) bool {
	for _, c := range checks {
		if !strings.HasPrefix(b.text[pos:], c.prefix) {
			continue
		}
		var end int
		if c.simple != nil {
			end = b.simpleEnd(c.simple, pos, &c.runs)
		} else {
			end = b.structuredEnd(c.structured, pos)
		}
		if end != -1 {
			return true
		}
	}
	return false
}

func (b *boundaries) occurrencesOf(prefix string) []int {
	if positions, ok := b.occurrences[prefix]; ok {
		return positions
	}
	return findAllPositions(b.text, prefix)
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
		limit := bodyEnd
		if length > bounds.max {
			limit = bodyStart + bounds.max
		}
		k := lastIndexAtMost(b.ends, b.first, limit)
		if k >= b.first && b.ends[k] >= bodyStart+max(bounds.min, 1) {
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
	for k := lastIndexAtMost(b.ends, b.first, bodyEnd); k >= b.first; k-- {
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

func scanSimple(text string, p TokenPattern, pat *SimpleTokenPattern, b *boundaries, candidates []TokenSpan) []TokenSpan {
	positions := b.occurrencesOf(pat.prefix)
	if len(positions) == 0 {
		return candidates
	}
	runs := newRunEnds(text, pat.bodyAlphabet)
	for _, pos := range positions {
		end := b.simpleEnd(pat, pos, &runs)
		if end == -1 {
			continue
		}
		candidates = append(candidates, TokenSpan{Start: pos, End: end, Pattern: p, Body: text[pos+len(pat.prefix) : end]})
	}
	return candidates
}

func scanStructured(text string, p TokenPattern, pat *StructuredTokenPattern, b *boundaries, candidates []TokenSpan) []TokenSpan {
	for _, pos := range b.occurrencesOf(pat.prefix) {
		end := b.structuredEnd(pat, pos)
		if end == -1 || end == pos {
			continue
		}
		candidates = append(candidates, TokenSpan{Start: pos, End: end, Pattern: p, Body: text[pos+len(pat.prefix) : end]})
	}
	return candidates
}
