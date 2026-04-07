# go-fast

A Go implementation of the FAST (Format-preserving encryption And Secure Tokenization) algorithm.

FAST is a format-preserving encryption (FPE) scheme that encrypts data while preserving its format. A 16-byte input encrypts to a 16-byte output, a sequence of decimal digits stays decimal, and so on. It supports arbitrary alphabets (radix 2--256), making it suitable both for raw byte encryption and for encrypting structured tokens like credit card numbers, API keys, or identifiers over restricted character sets.

## Features

- **Format-preserving encryption**: Output has the same length and alphabet as input
- **Arbitrary radix**: Supports alphabets from radix 2 (binary) to 256 (bytes)
- **Cross-language parity**: Produces identical ciphertext as the JavaScript and Python FAST implementations
- **Secure**: Based on AES with provable security guarantees
- **Fast**: Optimized implementation with pre-computed S-boxes and efficient diffusion
- **Deterministic**: Same plaintext + key + tweak always produces the same ciphertext
- **Tweak support**: Domain separation through optional tweak parameter

## Installation

```bash
go get github.com/jedisct1/go-fast
```

## Usage

### Basic Example

```go
package main

import (
    "fmt"
    "github.com/jedisct1/go-fast"
)

func main() {
    // Create a new FAST cipher with a 16-byte key (AES-128)
    key := []byte("0123456789abcdef")
    cipher, err := fast.NewCipher(key)
    if err != nil {
        panic(err)
    }

    // Encrypt some data
    plaintext := []byte("Hello, World!")
    ciphertext := cipher.Encrypt(plaintext, nil)
    
    fmt.Printf("Plaintext:  %s\n", plaintext)
    fmt.Printf("Ciphertext: %x\n", ciphertext)
    
    // Decrypt it back
    decrypted := cipher.Decrypt(ciphertext, nil)
    fmt.Printf("Decrypted:  %s\n", decrypted)
}
```

### Using Tweaks for Domain Separation

```go
// Different tweaks produce different ciphertexts for the same plaintext
data := []byte("sensitive data")
tweak1 := []byte("domain1")
tweak2 := []byte("domain2")

ciphertext1 := cipher.Encrypt(data, tweak1)
ciphertext2 := cipher.Encrypt(data, tweak2)

// ciphertext1 != ciphertext2

// Must use the same tweak to decrypt
decrypted1 := cipher.Decrypt(ciphertext1, tweak1) // ✓ Correct
decrypted2 := cipher.Decrypt(ciphertext1, tweak2) // ✗ Wrong result
```

### Key Sizes

FAST supports AES-128, AES-192, and AES-256:

```go
// AES-128 (recommended)
key128 := make([]byte, 16)
cipher128, _ := fast.NewCipher(key128)

// AES-192
key192 := make([]byte, 24)
cipher192, _ := fast.NewCipher(key192)

// AES-256
key256 := make([]byte, 32)
cipher256, _ := fast.NewCipher(key256)
```

### Arbitrary Radix (Non-Byte Alphabets)

For encrypting data over smaller alphabets -- decimal digits, hex, alphanumeric characters, base64 -- use `NewCipherFromParams` with parameters computed for the target radix and word length. Each element in the input slice must be in `[0, radix)`.

```go
package main

import (
    "fmt"
    "github.com/jedisct1/go-fast"
)

func main() {
    key := []byte("0123456789abcdef")

    // Encrypt a 16-digit number using radix 10
    params, err := fast.CalculateRecommendedParams(10, 16)
    if err != nil {
        panic(err)
    }
    cipher, err := fast.NewCipherFromParams(params, key)
    if err != nil {
        panic(err)
    }

    // Input: digits 0-9 as byte values (not ASCII)
    digits := []byte{4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
    encrypted := cipher.Encrypt(digits, nil)

    fmt.Printf("Original:  %v\n", digits)
    fmt.Printf("Encrypted: %v\n", encrypted) // still 16 digits, each in [0,9]

    decrypted := cipher.Decrypt(encrypted, nil)
    fmt.Printf("Decrypted: %v\n", decrypted)
}
```

The parameterized cipher is fixed to a single `(radix, wordLength)` pair. Create one cipher per combination and reuse it across calls. Different radixes produce completely independent S-box pools and round schedules, so a radix-10 cipher and a radix-62 cipher sharing the same key will produce unrelated outputs.

### Token Encryption

The `tokens` subpackage scans text for API keys and secrets, encrypts them in place while preserving format, and decrypts them back. It recognizes 28 built-in token patterns from GitHub, Stripe, OpenAI, AWS, Slack, SendGrid, and others.

```go
package main

import (
    "fmt"
    "log"

    "github.com/jedisct1/go-fast/tokens"
)

func main() {
    key := []byte("0123456789abcdef") // AES-128

    enc, err := tokens.New(key)
    if err != nil {
        log.Fatal(err)
    }

    text := "GitHub PAT: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789"

    encrypted, err := enc.Encrypt(text)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(encrypted) // "GitHub PAT: ghp_<encrypted-body>"

    decrypted, err := enc.Decrypt(encrypted)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(decrypted == text) // true
}
```

Per-call options let you filter by token type or override the tweak:

```go
// Encrypt only GitHub tokens, leave others unchanged
encrypted, _ := enc.Encrypt(text, tokens.WithTypes("github-pat"))

// Use a per-call tweak for domain separation
encrypted, _ := enc.Encrypt(text, tokens.WithCallTweak([]byte("production")))
```

`EncryptWithSpans` returns per-token metadata, and `EncryptWithMappings` returns deduplicated plaintext/ciphertext pairs. Token names, alphabets, and ordering match the JavaScript and Python FAST implementations exactly.

## Algorithm Details

FAST is based on the research paper:
> "FAST: Secure and High Performance Format-Preserving Encryption and Tokenization"  
> https://eprint.iacr.org/2021/1171.pdf

### Key Properties

- **Security**: Provides 128-bit security when used with AES-128
- **Performance**: Optimized with cached S-boxes and efficient buffer management
- **Format preservation**: Input length = output length, values stay within the alphabet
- **Deterministic**: Reproducible encryption for the same inputs
- **Two construction modes**: `NewCipher(key)` for byte data of any length; `NewCipherFromParams(params, key)` for a fixed radix and word length

### Security Considerations

- Use a cryptographically secure random key
- Different applications should use different tweaks
- The same (plaintext, key, tweak) always produces the same ciphertext
- For probabilistic encryption, include random data in the tweak

### Benchmark Results

Benchmarks run on Apple M4:

#### Encryption Performance (nil tweak)
- 8 bytes: 18.28 MB/s (437.7 ns/op, 3 allocs)
- 16 bytes: 38.26 MB/s (418.2 ns/op, 3 allocs)
- 32 bytes: 69.17 MB/s (462.6 ns/op, 4 allocs)
- 64 bytes: 119.48 MB/s (535.7 ns/op, 4 allocs)
- 128 bytes: 164.01 MB/s (780.4 ns/op, 4 allocs)
- 256 bytes: 211.19 MB/s (1212 ns/op, 5 allocs)
- 512 bytes: 223.47 MB/s (2291 ns/op, 5 allocs)
- 1KB: 240.01 MB/s (4267 ns/op, 5 allocs)
- 4KB: 177.92 MB/s (23022 ns/op, 5 allocs)
- 8KB: 178.09 MB/s (46000 ns/op, 5 allocs)

#### Nil Tweak vs With Tweak Performance
The implementation includes optimizations for the common case of nil tweaks:

| Size | Nil Tweak                  | With Tweak                 | Improvement |
| ---- | -------------------------- | -------------------------- | ----------- |
| 16B  | 418.2 ns/op (38.26 MB/s)   | 580.0 ns/op (27.59 MB/s)   | 28% faster  |
| 64B  | 535.7 ns/op (119.48 MB/s)  | 713.7 ns/op (89.68 MB/s)   | 25% faster  |
| 256B | 1212 ns/op (211.19 MB/s)   | 1474 ns/op (173.69 MB/s)   | 18% faster  |
| 1KB  | 4267 ns/op (240.01 MB/s)   | N/A                        | N/A         |

Memory allocations are also significantly reduced (3-5 allocs vs 10 allocs).

## Testing

Run the comprehensive test suite:

```bash
go test -v ./...
```

For performance benchmarks:

```bash
go test -bench=. -benchtime=10s -run=^$
```

This implementation is based on the FAST specification and is provided for research and educational purposes.

## References

- [FAST Paper](https://eprint.iacr.org/2021/1171.pdf)
- [The Next Generation of Performant Data Protection: a New FPE Algorithm](https://insights.comforte.com/the-next-generation-of-performant-data-protection-a-new-fpe-algorithm)
- [Format-Preserving Encryption](https://en.wikipedia.org/wiki/Format-preserving_encryption)
