// Package fast implements the FAST (Format-preserving encryption And Secure Tokenization)
// algorithm for format-preserving encryption over arbitrary alphabets.
//
// FAST encrypts data while preserving its format and length. A 16-byte input
// encrypts to 16 bytes, a sequence of decimal digits stays decimal, and so on.
// It supports any alphabet from radix 2 (binary) to 256 (raw bytes), producing
// ciphertext identical to the JavaScript and Python FAST implementations.
//
// # Two Modes of Operation
//
// Byte mode (radix 256) accepts data of any length:
//
//	cipher, _ := fast.NewCipher(key)
//	ct := cipher.Encrypt([]byte("sensitive data"), nil)
//
// Parameterized mode operates over a specific alphabet and word length:
//
//	params, _ := fast.CalculateRecommendedParams(10, 16) // radix 10, 16 digits
//	cipher, _ := fast.NewCipherFromParams(params, key)
//	ct := cipher.Encrypt([]byte{4,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, nil)
//
// # Tweaks
//
// Tweaks provide domain separation, allowing the same key to produce different
// ciphertexts for different contexts:
//
//	ct1 := cipher.Encrypt(data, []byte("user-context"))
//	ct2 := cipher.Encrypt(data, []byte("admin-context"))
//
// # Thread Safety
//
// Cipher instances are safe for concurrent use. The S-box pool is initialized
// once using sync.Once, making it safe to encrypt/decrypt from multiple goroutines.
//
// # References
//
// Based on "FAST: Secure and High Performance Format-Preserving Encryption
// and Tokenization" (https://eprint.iacr.org/2021/1171.pdf).
package fast
