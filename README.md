# go-fast

A Go implementation of the FAST (Format-preserving encryption And Secure Tokenization) algorithm.

FAST is a format-preserving encryption (FPE) scheme that encrypts data while preserving its format. For example, a 16-byte string will encrypt to another 16-byte string, and numeric data maintains its numeric format.

## Features

- **Format-preserving encryption**: Output has the same length and format as input
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

## Algorithm Details

FAST is based on the research paper:
> "FAST: Secure and High Performance Format-Preserving Encryption and Tokenization"  
> https://eprint.iacr.org/2021/1171.pdf

### Key Properties

- **Security**: Provides 128-bit security when used with AES-128
- **Performance**: Optimized with cached S-boxes and efficient buffer management
- **Format preservation**: Input length = output length
- **Deterministic**: Reproducible encryption for the same inputs

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
go test -v
```

For performance benchmarks:

```bash
go test -bench=. -benchtime=10s -run=^$
```

This implementation is based on the FAST specification and is provided for research and educational purposes.

## References

- [FAST Paper](https://eprint.iacr.org/2021/1171.pdf)
- [Format-Preserving Encryption](https://en.wikipedia.org/wiki/Format-preserving_encryption)
