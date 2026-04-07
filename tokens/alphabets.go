package tokens

// Alphabet represents an ordered character set used by format-preserving encryption.
// Each character maps to a unique index in [0, Radix).
type Alphabet struct {
	name      string
	chars     string
	charToIdx [256]int // -1 means not in alphabet
}

func newAlphabet(name, chars string) *Alphabet {
	a := &Alphabet{
		name:  name,
		chars: chars,
	}
	for i := range a.charToIdx {
		a.charToIdx[i] = -1
	}
	for i := 0; i < len(chars); i++ {
		if a.charToIdx[chars[i]] >= 0 {
			panic("tokens: duplicate character '" + string(chars[i]) + "' in alphabet " + name)
		}
		a.charToIdx[chars[i]] = i
	}
	return a
}

// Name returns the alphabet's canonical name.
func (a *Alphabet) Name() string { return a.name }

// Chars returns the ordered character string.
func (a *Alphabet) Chars() string { return a.chars }

// Radix returns the alphabet size.
func (a *Alphabet) Radix() int { return len(a.chars) }

// Contains reports whether c is in the alphabet.
func (a *Alphabet) Contains(c byte) bool {
	return a.charToIdx[c] >= 0
}

// ContainsAll reports whether every byte of s is in the alphabet.
func (a *Alphabet) ContainsAll(s string) bool {
	for i := 0; i < len(s); i++ {
		if a.charToIdx[s[i]] < 0 {
			return false
		}
	}
	return true
}

// Index returns the index of c in the alphabet, or -1 if not present.
func (a *Alphabet) Index(c byte) int {
	return a.charToIdx[c]
}

// Char returns the character at index i. Panics if i is out of range.
func (a *Alphabet) Char(i int) byte {
	return a.chars[i]
}

var (
	Digits            = newAlphabet("digits", "0123456789")
	HexLower          = newAlphabet("hex-lower", "0123456789abcdef")
	AlphanumericUpper = newAlphabet("alphanumeric-upper", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	AlphanumericLower = newAlphabet("alphanumeric-lower", "0123456789abcdefghijklmnopqrstuvwxyz")
	Alphanumeric      = newAlphabet("alphanumeric", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	Base64            = newAlphabet("base64", "+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	Base64URL         = newAlphabet("base64url", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-")
)
