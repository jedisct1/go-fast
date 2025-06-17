// Package fast implements the FAST (Format-preserving encryption And Secure Tokenization)
// algorithm, providing secure format-preserving encryption for arbitrary byte sequences.
//
// FAST is a cryptographic scheme that encrypts data while preserving its format and length.
// For example, a 16-byte string encrypts to another 16-byte string, maintaining the same
// structure as the original data. This makes FAST ideal for encrypting structured data
// like database fields, tokens, or identifiers without changing their format.
//
// # Features
//
//   - Format-preserving: Output length always equals input length
//   - Secure: Based on AES with 128-bit security guarantees
//   - Deterministic: Same (plaintext, key, tweak) always produces the same ciphertext
//   - Fast: Optimized with pre-computed S-boxes and efficient buffer management
//   - Tweak support: Optional domain separation for different contexts
//
// # Security
//
// FAST provides 128-bit security when used with AES-128. The algorithm is based on
// the research paper "FAST: Secure and High Performance Format-Preserving Encryption
// and Tokenization" (https://eprint.iacr.org/2021/1171.pdf).
//
// Key security properties:
//   - Provable security reduction to AES
//   - Statistical indistinguishability from random permutations
//   - Resistance to known cryptographic attacks
//
// # Basic Usage
//
//	key := make([]byte, 16) // AES-128 key
//	// Fill key with cryptographically secure random bytes
//
//	cipher, err := fast.NewCipher(key)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	plaintext := []byte("sensitive data")
//	ciphertext := cipher.Encrypt(plaintext, nil)
//
//	// Decrypt
//	decrypted := cipher.Decrypt(ciphertext, nil)
//
// # Using Tweaks
//
// Tweaks provide domain separation, allowing the same key to be used for different
// purposes without compromising security:
//
//	// Different tweaks produce different ciphertexts
//	userData := cipher.Encrypt(data, []byte("user-context"))
//	adminData := cipher.Encrypt(data, []byte("admin-context"))
//
//	// Must use the same tweak for decryption
//	decrypted := cipher.Decrypt(userData, []byte("user-context"))
//
// # Performance
//
// FAST is optimized for performance with:
//   - Pre-computed and cached S-boxes
//   - Efficient buffer management to minimize allocations
//   - Optimized AES-CMAC implementation
//   - Bulk operations for improved cache locality
//
// Typical throughput on modern hardware:
//   - Small data (16 bytes): ~50 MB/s
//   - Medium data (256 bytes): ~100 MB/s
//   - Large data (4KB+): ~150+ MB/s
//
// # Thread Safety
//
// Cipher instances are safe for concurrent use. The S-box pool is initialized
// once using sync.Once, making it safe to encrypt/decrypt from multiple goroutines.
package fast
