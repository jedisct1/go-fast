package tokens

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	fast "github.com/jedisct1/go-fast"
)

// Encryptor performs format-preserving encryption and decryption of tokens
// found in text. It caches FAST cipher instances per (radix, wordLength) pair.
type Encryptor struct {
	key          []byte
	defaultTweak []byte
	patterns     []TokenPattern
	cache        sync.Map // map["radix:wordLength"]*fast.Cipher
}

// Option configures the Encryptor at construction time.
type Option func(*Encryptor)

// WithTweak sets a default tweak applied to all encrypt/decrypt calls
// unless overridden per-call.
func WithTweak(tweak []byte) Option {
	return func(e *Encryptor) {
		e.defaultTweak = tweak
	}
}

// WithPatterns prepends custom patterns before the built-in registry.
func WithPatterns(patterns []TokenPattern) Option {
	return func(e *Encryptor) {
		combined := make([]TokenPattern, 0, len(patterns)+len(BuiltinPatterns))
		combined = append(combined, patterns...)
		combined = append(combined, BuiltinPatterns...)
		e.patterns = combined
	}
}

// New creates a new Encryptor with the given AES key (16, 24, or 32 bytes).
func New(key []byte, opts ...Option) (*Encryptor, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("tokens: key must be 16, 24, or 32 bytes, got %d", len(key))
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	e := &Encryptor{
		key:      keyCopy,
		patterns: BuiltinPatterns,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
}

// CallOption configures a single Encrypt or Decrypt call.
type CallOption func(*callOptions)

type callOptions struct {
	types []string
	tweak *[]byte // nil means inherit default; non-nil pointer to nil slice means no tweak
}

// WithTypes filters scanning to only the named pattern types.
func WithTypes(types ...string) CallOption {
	return func(o *callOptions) {
		o.types = types
	}
}

// WithCallTweak overrides the default tweak for this call.
func WithCallTweak(tweak []byte) CallOption {
	return func(o *callOptions) {
		o.tweak = &tweak
	}
}

func (e *Encryptor) resolveOptions(opts []CallOption) callOptions {
	var o callOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func (e *Encryptor) resolveTweak(o callOptions) []byte {
	if o.tweak != nil {
		return *o.tweak
	}
	return e.defaultTweak
}

func (e *Encryptor) activePatterns(o callOptions) []TokenPattern {
	if len(o.types) == 0 {
		return e.patterns
	}
	allowed := make(map[string]bool, len(o.types))
	for _, t := range o.types {
		allowed[t] = true
	}
	var filtered []TokenPattern
	for _, p := range e.patterns {
		if allowed[p.Name()] {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// Encrypt scans text for tokens and returns the text with all matched tokens
// encrypted. Unmatched text passes through unchanged.
func (e *Encryptor) Encrypt(text string, opts ...CallOption) (string, error) {
	result, err := e.EncryptWithSpans(text, opts...)
	if err != nil {
		return "", err
	}
	return result.Text, nil
}

// EncryptWithSpans is like Encrypt but also returns per-token span details.
func (e *Encryptor) EncryptWithSpans(text string, opts ...CallOption) (EncryptResult, error) {
	o := e.resolveOptions(opts)
	patterns := e.activePatterns(o)
	extraTweak := e.resolveTweak(o)

	scanned := ScanAllWithAll(text, patterns, e.patterns)
	if len(scanned) == 0 {
		return EncryptResult{Text: text}, nil
	}

	var parts []string
	var spans []Span
	cursor := 0

	for _, span := range scanned {
		parts = append(parts, text[cursor:span.Start])
		original := text[span.Start:span.End]
		encrypted, err := e.transformSpan(span, extraTweak, true)
		if err != nil {
			return EncryptResult{}, err
		}
		parts = append(parts, encrypted)
		spans = append(spans, Span{
			Start:       span.Start,
			End:         span.End,
			Original:    original,
			Encrypted:   encrypted,
			PatternName: span.Pattern.Name(),
		})
		cursor = span.End
	}

	parts = append(parts, text[cursor:])
	return EncryptResult{
		Text:  strings.Join(parts, ""),
		Spans: spans,
	}, nil
}

// EncryptWithMappings is like Encrypt but also returns deduplicated mappings.
func (e *Encryptor) EncryptWithMappings(text string, opts ...CallOption) (string, []Mapping, error) {
	result, err := e.EncryptWithSpans(text, opts...)
	if err != nil {
		return "", nil, err
	}
	seen := make(map[string]bool)
	var mappings []Mapping
	for _, s := range result.Spans {
		key := s.Encrypted + "\x00" + s.PatternName
		if !seen[key] {
			seen[key] = true
			mappings = append(mappings, Mapping{
				Plaintext:   s.Original,
				Ciphertext:  s.Encrypted,
				PatternName: s.PatternName,
			})
		}
	}
	return result.Text, mappings, nil
}

// Decrypt scans text for encrypted tokens and returns the decrypted text.
// Uses a two-pass approach: heuristic markers first, then prefix-based tokens.
func (e *Encryptor) Decrypt(text string, opts ...CallOption) (string, error) {
	o := e.resolveOptions(opts)
	patterns := e.activePatterns(o)
	extraTweak := e.resolveTweak(o)

	// First pass: decrypt heuristic markers.
	var heuristicPatterns []HeuristicTokenPattern
	for _, p := range patterns {
		if hp, ok := p.(HeuristicTokenPattern); ok {
			heuristicPatterns = append(heuristicPatterns, hp)
		}
	}
	result := text
	if len(heuristicPatterns) > 0 {
		var err error
		result, err = e.decryptHeuristicMarkers(result, heuristicPatterns, extraTweak)
		if err != nil {
			return "", err
		}
	}

	// Second pass: decrypt prefix-based tokens.
	var prefixPatterns []TokenPattern
	for _, p := range patterns {
		if p.Kind() != "heuristic" {
			prefixPatterns = append(prefixPatterns, p)
		}
	}
	if len(prefixPatterns) == 0 {
		return result, nil
	}

	scanned := ScanWithAll(result, prefixPatterns, e.patterns)
	if len(scanned) == 0 {
		return result, nil
	}

	var parts []string
	cursor := 0
	for _, span := range scanned {
		parts = append(parts, result[cursor:span.Start])
		decrypted, err := e.transformSpan(span, extraTweak, false)
		if err != nil {
			return "", err
		}
		parts = append(parts, decrypted)
		cursor = span.End
	}
	parts = append(parts, result[cursor:])
	return strings.Join(parts, ""), nil
}

type cipherKey struct {
	radix, wordLength int
}

func (e *Encryptor) getCipher(radix, wordLength int) (*fast.Cipher, error) {
	key := cipherKey{radix, wordLength}
	if v, ok := e.cache.Load(key); ok {
		return v.(*fast.Cipher), nil
	}
	params, err := fast.CalculateRecommendedParams(radix, wordLength)
	if err != nil {
		return nil, fmt.Errorf("tokens: params for radix=%d wordLength=%d: %w", radix, wordLength, err)
	}
	cipher, err := fast.NewCipherFromParams(params, e.key)
	if err != nil {
		return nil, fmt.Errorf("tokens: cipher for radix=%d wordLength=%d: %w", radix, wordLength, err)
	}
	e.cache.Store(key, cipher)
	return cipher, nil
}

func makeTweak(patternName string, extra []byte) []byte {
	nameBytes := []byte(patternName)
	if len(extra) == 0 {
		return nameBytes
	}
	tweak := make([]byte, len(nameBytes)+1+len(extra))
	copy(tweak, nameBytes)
	tweak[len(nameBytes)] = 0x00
	copy(tweak[len(nameBytes)+1:], extra)
	return tweak
}

func heuristicMarker(patternName string) string {
	return "[ENCRYPTED:" + patternName + "]"
}

func charsToIndices(body string, a *Alphabet) []byte {
	indices := make([]byte, len(body))
	for i := 0; i < len(body); i++ {
		indices[i] = byte(a.Index(body[i]))
	}
	return indices
}

func indicesToChars(indices []byte, a *Alphabet) string {
	buf := make([]byte, len(indices))
	for i, idx := range indices {
		buf[i] = a.Char(int(idx))
	}
	return string(buf)
}

func (e *Encryptor) transformBody(body string, alphabet *Alphabet, encrypt bool, tweak []byte) (string, error) {
	cipher, err := e.getCipher(alphabet.Radix(), len(body))
	if err != nil {
		return "", err
	}
	indices := charsToIndices(body, alphabet)
	var result []byte
	if encrypt {
		result = cipher.Encrypt(indices, tweak)
	} else {
		result = cipher.Decrypt(indices, tweak)
	}
	return indicesToChars(result, alphabet), nil
}

func (e *Encryptor) transformSpan(span TokenSpan, extraTweak []byte, encrypt bool) (string, error) {
	tweak := makeTweak(span.Pattern.Name(), extraTweak)

	switch pat := span.Pattern.(type) {
	case HeuristicTokenPattern:
		result, err := e.transformBody(span.Body, pat.bodyAlphabet, encrypt, tweak)
		if err != nil {
			return "", err
		}
		if encrypt {
			return heuristicMarker(pat.name) + result, nil
		}
		return result, nil

	case SimpleTokenPattern:
		result, err := e.transformBody(span.Body, pat.bodyAlphabet, encrypt, tweak)
		if err != nil {
			return "", err
		}
		return pat.prefix + result, nil

	case StructuredTokenPattern:
		parsed := pat.Parse(span.Body)
		if parsed == nil {
			return pat.prefix + span.Body, nil
		}
		transformed := make([]string, len(parsed.Segments))
		for i, seg := range parsed.Segments {
			if len(seg) < MinSegmentLength {
				transformed[i] = seg
				continue
			}
			t, err := e.transformBody(seg, parsed.Alphabets[i], encrypt, tweak)
			if err != nil {
				return "", err
			}
			transformed[i] = t
		}
		return pat.prefix + pat.Format(transformed), nil
	}

	return span.Body, nil
}

func (e *Encryptor) decryptHeuristicMarkers(text string, patterns []HeuristicTokenPattern, extraTweak []byte) (string, error) {
	type hit struct {
		start       int
		end         int
		body        string
		patternName string
		alphabet    *Alphabet
	}

	var hits []hit
	for _, pattern := range patterns {
		marker := heuristicMarker(pattern.name)
		searchFrom := 0
		for searchFrom < len(text) {
			idx := strings.Index(text[searchFrom:], marker)
			if idx == -1 {
				break
			}
			idx += searchFrom

			bodyStart := idx + len(marker)
			bodyEnd := bodyStart
			for bodyEnd < len(text) && bodyEnd-bodyStart < pattern.maxLength && pattern.bodyAlphabet.Contains(text[bodyEnd]) {
				bodyEnd++
			}

			bodyLen := bodyEnd - bodyStart
			trailingAlpha := bodyEnd < len(text) && pattern.bodyAlphabet.Contains(text[bodyEnd])

			if bodyLen >= pattern.minLength && bodyLen <= pattern.maxLength && !trailingAlpha {
				hits = append(hits, hit{
					start:       idx,
					end:         bodyEnd,
					body:        text[bodyStart:bodyEnd],
					patternName: pattern.name,
					alphabet:    pattern.bodyAlphabet,
				})
				searchFrom = bodyEnd
			} else {
				searchFrom = idx + 1
			}
		}
	}

	if len(hits) == 0 {
		return text, nil
	}

	sort.Slice(hits, func(i, j int) bool {
		return hits[i].start < hits[j].start
	})

	var parts []string
	cursor := 0
	for _, h := range hits {
		if h.start < cursor {
			continue
		}
		parts = append(parts, text[cursor:h.start])
		tweak := makeTweak(h.patternName, extraTweak)
		decrypted, err := e.transformBody(h.body, h.alphabet, false, tweak)
		if err != nil {
			return "", err
		}
		parts = append(parts, decrypted)
		cursor = h.end
	}
	parts = append(parts, text[cursor:])
	return strings.Join(parts, ""), nil
}
