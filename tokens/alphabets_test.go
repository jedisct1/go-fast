package tokens

import (
	"testing"
)

func TestAlphabetChars(t *testing.T) {
	tests := []struct {
		alphabet *Alphabet
		name     string
		chars    string
		radix    int
	}{
		{Digits, "digits", "0123456789", 10},
		{HexLower, "hex-lower", "0123456789abcdef", 16},
		{AlphanumericUpper, "alphanumeric-upper", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 36},
		{AlphanumericLower, "alphanumeric-lower", "0123456789abcdefghijklmnopqrstuvwxyz", 36},
		{Alphanumeric, "alphanumeric", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 62},
		{Base64, "base64", "+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 64},
		{Base64URL, "base64url", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-", 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.alphabet.Name() != tt.name {
				t.Errorf("Name() = %q, want %q", tt.alphabet.Name(), tt.name)
			}
			if tt.alphabet.Chars() != tt.chars {
				t.Errorf("Chars() = %q, want %q", tt.alphabet.Chars(), tt.chars)
			}
			if tt.alphabet.Radix() != tt.radix {
				t.Errorf("Radix() = %d, want %d", tt.alphabet.Radix(), tt.radix)
			}
		})
	}
}

func TestAlphabetUniqueness(t *testing.T) {
	alphabets := []*Alphabet{Digits, HexLower, AlphanumericUpper, AlphanumericLower, Alphanumeric, Base64, Base64URL}
	for _, a := range alphabets {
		t.Run(a.Name(), func(t *testing.T) {
			seen := make(map[byte]bool)
			for i := 0; i < len(a.Chars()); i++ {
				c := a.Chars()[i]
				if seen[c] {
					t.Errorf("duplicate character %q at index %d", c, i)
				}
				seen[c] = true
			}
		})
	}
}

func TestAlphabetLookupRoundTrip(t *testing.T) {
	alphabets := []*Alphabet{Digits, HexLower, AlphanumericUpper, AlphanumericLower, Alphanumeric, Base64, Base64URL}
	for _, a := range alphabets {
		t.Run(a.Name(), func(t *testing.T) {
			for i := 0; i < a.Radix(); i++ {
				c := a.Char(i)
				idx := a.Index(c)
				if idx != i {
					t.Errorf("Index(Char(%d)) = %d, want %d", i, idx, i)
				}
			}
		})
	}
}

func TestAlphabetContains(t *testing.T) {
	if !Digits.Contains('5') {
		t.Error("Digits should contain '5'")
	}
	if Digits.Contains('a') {
		t.Error("Digits should not contain 'a'")
	}
	if !HexLower.Contains('a') {
		t.Error("HexLower should contain 'a'")
	}
	if HexLower.Contains('A') {
		t.Error("HexLower should not contain 'A'")
	}
	if !Base64URL.Contains('-') {
		t.Error("Base64URL should contain '-'")
	}
	if !Base64URL.Contains('_') {
		t.Error("Base64URL should contain '_'")
	}
	if !Base64.Contains('+') {
		t.Error("Base64 should contain '+'")
	}
	if !Base64.Contains('/') {
		t.Error("Base64 should contain '/'")
	}
}

func TestAlphabetContainsAll(t *testing.T) {
	if !Digits.ContainsAll("0123456789") {
		t.Error("Digits should contain all digits")
	}
	if Digits.ContainsAll("012a") {
		t.Error("Digits should not contain 'a'")
	}
	if !Digits.ContainsAll("") {
		t.Error("empty string should be contained in any alphabet")
	}
}

func TestAlphabetIndexNotInAlphabet(t *testing.T) {
	if Digits.Index('z') != -1 {
		t.Error("Digits.Index('z') should be -1")
	}
	if AlphanumericUpper.Index('a') != -1 {
		t.Error("AlphanumericUpper.Index('a') should be -1")
	}
}
