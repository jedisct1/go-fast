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

## Performance

The implementation is optimized for performance:

- S-boxes are pre-computed and cached
- Efficient buffer management reduces allocations
- Optimized AES-CMAC implementation
- Bulk operations for improved cache locality
- Hardcoded alphabet size (256) eliminates runtime checks and modulo operations

Typical performance on Apple M4:
- Small data (16 bytes): ~15 MB/s
- Small data (64 bytes): ~34 MB/s
- Medium data (128 bytes): ~41 MB/s
- Medium data (256 bytes): ~43 MB/s (peak performance)
- Large data (1KB): ~21 MB/s
- Large data (4KB): ~6 MB/s
- Large data (8KB): ~3.5 MB/s

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
