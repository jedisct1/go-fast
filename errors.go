package fast

import "errors"

// ErrInvalidKeySize is returned when the provided key is not 16, 24, or 32 bytes.
var ErrInvalidKeySize = errors.New("fast: invalid key size, must be 16, 24, or 32 bytes")

// MaxDataSize is the maximum supported data size for encryption/decryption.
// This limit ensures reasonable performance and memory usage.
const MaxDataSize = 1 << 20 // 1 MB
