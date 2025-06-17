package fast

import "errors"

var (
	// ErrInvalidKeySize is returned when the provided key is not 16, 24, or 32 bytes.
	ErrInvalidKeySize = errors.New("fast: invalid key size, must be 16, 24, or 32 bytes")

	// ErrNilCipher is returned when attempting to use a nil cipher instance.
	ErrNilCipher = errors.New("fast: cipher instance is nil")

	// ErrDataTooLarge is returned when the input data exceeds the maximum supported size.
	ErrDataTooLarge = errors.New("fast: input data exceeds maximum supported size")
)

// MaxDataSize is the maximum supported data size for encryption/decryption.
// This limit ensures reasonable performance and memory usage.
const MaxDataSize = 1 << 20 // 1 MB
