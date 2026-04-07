// Package tokens provides format-preserving encryption for API keys, secrets,
// and other structured tokens found in text.
//
// It scans text for 28 built-in token patterns (GitHub PATs, Stripe keys,
// Slack tokens, AWS credentials, etc.) and encrypts the sensitive portions
// while preserving the token format -- prefixes, lengths, and character sets
// remain intact. The encrypted output is indistinguishable from a valid token
// in the same format.
//
// The package produces ciphertext identical to the JavaScript and Python FAST
// implementations, enabling cross-language interoperability.
//
// # Quick Start
//
//	enc, _ := tokens.New(key)
//	encrypted, _ := enc.Encrypt("my token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789")
//	decrypted, _ := enc.Decrypt(encrypted)
//
// # Pattern Kinds
//
// Simple patterns match a fixed prefix followed by a body drawn from a known
// alphabet (e.g. "ghp_" + 36 alphanumeric characters for GitHub PATs).
//
// Structured patterns match a prefix plus an internal structure with multiple
// segments (e.g. Slack tokens with dash-separated numeric and alphanumeric
// parts, or SendGrid tokens with dot-separated Base64URL segments). Each
// segment is encrypted independently; segments shorter than MinSegmentLength
// pass through unchanged.
//
// Heuristic patterns have no prefix and rely on entropy thresholds and
// character-class analysis to detect likely secrets. During encryption they
// are wrapped with a marker like [ENCRYPTED:fastly] so that decryption can
// find them unambiguously.
//
// # Tweaks
//
// Tweaks provide domain separation. The same plaintext encrypted under
// different tweaks produces different ciphertext:
//
//	ct1, _ := enc.Encrypt(text, tokens.WithCallTweak([]byte("prod")))
//	ct2, _ := enc.Encrypt(text, tokens.WithCallTweak([]byte("staging")))
//
// A default tweak can be set at construction time with WithTweak.
//
// # Thread Safety
//
// An Encryptor is safe for concurrent use from multiple goroutines. Cipher
// instances are cached per (radix, wordLength) pair using sync.Map.
package tokens
