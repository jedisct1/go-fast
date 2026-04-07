package tokens

// SimpleTokenPattern matches tokens with a fixed prefix followed by a body
// drawn from a known alphabet.
type SimpleTokenPattern struct {
	name          string
	prefix        string
	bodyRegex     string
	bodyAlphabet  *Alphabet
	minBodyLength int
}

func (p SimpleTokenPattern) Kind() string   { return "simple" }
func (p SimpleTokenPattern) Name() string   { return p.name }
func (p SimpleTokenPattern) Prefix() string { return p.prefix }

// StructuredTokenPattern matches tokens with a prefix and an internal
// structure (e.g. dash-separated or dot-separated segments).
type StructuredTokenPattern struct {
	name             string
	prefix           string
	fullRegex        string
	trailingAlphabet *Alphabet
	parseFn          func(body string) *StructuredParse
	formatFn         func(segments []string) string
}

// StructuredParse holds the result of parsing a structured token body.
type StructuredParse struct {
	Segments  []string
	Alphabets []*Alphabet
}

func (p StructuredTokenPattern) Kind() string   { return "structured" }
func (p StructuredTokenPattern) Name() string   { return p.name }
func (p StructuredTokenPattern) Prefix() string { return p.prefix }

// Parse splits a token body (without prefix) into segments and their alphabets.
// Returns nil if the body does not match the expected structure.
func (p StructuredTokenPattern) Parse(body string) *StructuredParse {
	return p.parseFn(body)
}

// Format reassembles segments into a token body (without prefix).
func (p StructuredTokenPattern) Format(segments []string) string {
	return p.formatFn(segments)
}

// HeuristicTokenPattern matches tokens without a prefix, using entropy
// and character-class analysis.
type HeuristicTokenPattern struct {
	name           string
	bodyAlphabet   *Alphabet
	minLength      int
	maxLength      int
	minEntropy     float64
	minCharClasses int
}

func (p HeuristicTokenPattern) Kind() string   { return "heuristic" }
func (p HeuristicTokenPattern) Name() string   { return p.name }
func (p HeuristicTokenPattern) Prefix() string { return "" }

// TokenPattern is a union of all pattern types.
type TokenPattern interface {
	Kind() string
	Name() string
	Prefix() string
}

// Span describes a matched token's location and encryption result within text.
type Span struct {
	Start       int
	End         int
	Original    string
	Encrypted   string
	PatternName string
}

// EncryptResult holds the full encrypted text and per-token span details.
type EncryptResult struct {
	Text  string
	Spans []Span
}

// Mapping records one plaintext-to-ciphertext token substitution.
type Mapping struct {
	Plaintext   string
	Ciphertext  string
	PatternName string
}

// MinSegmentLength is the minimum segment length for structured token
// encryption. Segments shorter than this pass through unchanged.
const MinSegmentLength = 4
