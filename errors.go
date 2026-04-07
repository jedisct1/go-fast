package fast

import "errors"

// ErrInvalidKeySize is returned when the provided key is not 16, 24, or 32 bytes.
var ErrInvalidKeySize = errors.New("fast: invalid key size, must be 16, 24, or 32 bytes")

// ErrInvalidRadix is returned when the radix is outside the supported range [2, 256].
var ErrInvalidRadix = errors.New("fast: invalid radix, must be between 2 and 256")

// ErrInvalidWordLength is returned when the word length is too small.
var ErrInvalidWordLength = errors.New("fast: invalid word length, must be >= 2")

// ErrInvalidParams is returned when cipher parameters are inconsistent.
var ErrInvalidParams = errors.New("fast: invalid parameters")

// MaxDataSize is the maximum supported data size for encryption/decryption.
// This limit ensures reasonable performance and memory usage.
const MaxDataSize = 1 << 20 // 1 MB
