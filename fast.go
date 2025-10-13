// Package fast provides the FAST algorithm implementation for format-preserving encryption.
// Based on: "FAST: Secure and High Performance Format-Preserving Encryption and Tokenization"
// https://eprint.iacr.org/2021/1171.pdf
package fast

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
)

// bufferPool manages a pool of byte slices to reduce allocations
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 16) // AES block size
		return &b
	},
}

// Cipher implements the FAST format-preserving encryption algorithm
type Cipher struct {
	cipher       cipher.Block
	m            int // pool size (number of S-boxes)
	sboxPool     [][]byte
	sboxPoolOnce sync.Once
	invSboxPool  [][]byte
	// Pre-allocated buffers for AES-CMAC to reduce allocations
	cmacK1   []byte
	cmacK2   []byte
	cmacOnce sync.Once
	// Cache for index sequence generation ciphers
	indexCipherCache map[string]cipher.Block
	indexCacheMu     sync.RWMutex
	// Cache for index sequences when tweak is nil
	noTweakSeqCache map[string][]byte
	noTweakSeqMu    sync.RWMutex
}

// leftShiftInPlace performs a left shift by one bit in-place to avoid allocation
func leftShiftInPlace(dst, src []byte) {
	carry := byte(0)
	for i := len(src) - 1; i >= 0; i-- {
		dst[i] = src[i]<<1 | carry
		carry = src[i] >> 7
	}
}

// initCMACKeys initializes the CMAC subkeys K1 and K2 once
func (f *Cipher) initCMACKeys() {
	f.cmacOnce.Do(func() {
		blockSize := f.cipher.BlockSize()
		f.cmacK1 = make([]byte, blockSize)
		f.cmacK2 = make([]byte, blockSize)

		// Generate subkeys K1 and K2
		L := make([]byte, blockSize)
		f.cipher.Encrypt(L, L) // L = AES(K, 0^128)

		leftShiftInPlace(f.cmacK1, L)
		if L[0]&0x80 != 0 {
			f.cmacK1[blockSize-1] ^= 0x87 // Rb for AES-128
		}

		leftShiftInPlace(f.cmacK2, f.cmacK1)
		if f.cmacK1[0]&0x80 != 0 {
			f.cmacK2[blockSize-1] ^= 0x87
		}
	})
}

// aesCMACOptimized implements AES-CMAC with pre-computed keys
func (f *Cipher) aesCMACOptimized(message []byte) []byte {
	f.initCMACKeys()
	blockSize := f.cipher.BlockSize()

	// Determine number of blocks
	msgLen := len(message)
	numBlocks := (msgLen + blockSize - 1) / blockSize
	if numBlocks == 0 {
		numBlocks = 1
	}

	// Get buffers from pool
	macPtr := bufferPool.Get().(*[]byte)
	mac := (*macPtr)[:blockSize]
	defer bufferPool.Put(macPtr)

	// Clear the buffer
	clear(mac)

	// Process all blocks except the last
	for i := 0; i < numBlocks-1; i++ {
		for j := 0; j < blockSize; j++ {
			mac[j] ^= message[i*blockSize+j]
		}
		f.cipher.Encrypt(mac, mac)
	}

	// Process last block - get another buffer from pool
	lastBlockPtr := bufferPool.Get().(*[]byte)
	lastBlock := (*lastBlockPtr)[:blockSize]
	defer bufferPool.Put(lastBlockPtr)

	// Clear the buffer
	clear(lastBlock)
	lastBlockComplete := msgLen > 0 && msgLen%blockSize == 0

	if lastBlockComplete {
		// Complete block: XOR with K1
		copy(lastBlock, message[(numBlocks-1)*blockSize:])
		subtle.XORBytes(lastBlock, lastBlock, f.cmacK1)
	} else {
		// Incomplete block: pad and XOR with K2
		remaining := msgLen % blockSize
		if msgLen > 0 {
			copy(lastBlock, message[(numBlocks-1)*blockSize:])
		}
		lastBlock[remaining] = 0x80 // 10* padding
		subtle.XORBytes(lastBlock, lastBlock, f.cmacK2)
	}

	// Final MAC computation
	subtle.XORBytes(mac, mac, lastBlock)
	f.cipher.Encrypt(mac, mac)

	// Return a copy since mac is from the pool
	result := make([]byte, blockSize)
	copy(result, mac)
	return result
}

// writeU32Be writes a uint32 in big-endian format
func writeU32Be(value uint32) [4]byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	return buf
}

// encodeParts encodes a list of byte slices into a structured format matching the Zig/C reference implementation.
// Format:
//   - 4 bytes: number of parts (big-endian u32)
//   - For each part:
//   - 4 bytes: length of part (big-endian u32)
//   - N bytes: part data
//
// This encoding ensures unambiguous parsing and proper domain separation for the PRF.
func encodeParts(parts [][]byte) []byte {
	// Calculate total size
	totalSize := 4 // part count
	for _, part := range parts {
		totalSize += 4 + len(part) // length + data
	}

	buffer := make([]byte, totalSize)
	pos := 0

	// Write part count
	count := writeU32Be(uint32(len(parts)))
	copy(buffer[pos:], count[:])
	pos += 4

	// Write each part
	for _, part := range parts {
		length := writeU32Be(uint32(len(part)))
		copy(buffer[pos:], length[:])
		pos += 4

		if len(part) > 0 {
			copy(buffer[pos:], part)
			pos += len(part)
		}
	}

	return buffer
}

// lemireRandomIndex returns an unbiased random index in [0, max) using Lemire's method
func lemireRandomIndex(rng func() uint32, max int) int {
	for {
		r := rng()
		prod := uint64(r) * uint64(max)
		if uint32(prod) >= uint32(prod%uint64(max)) {
			return int(prod >> 32)
		}
	}
}

// lemireUniformU32 returns an unbiased random number in [0, bound) using Lemire's method
// This is the single-shot version that takes one random u32 value.
// Returns the high bits of (r * bound), which gives uniform distribution.
func lemireUniformU32(r uint32, bound uint32) uint32 {
	if bound == 0 || bound == 1 {
		return 0
	}
	// Compute (r * bound) >> 32, which gives uniform distribution in [0, bound)
	prod := uint64(r) * uint64(bound)
	return uint32(prod >> 32)
}

// NewCipher creates a new FAST cipher instance with the given AES key.
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively.
func NewCipher(key []byte) (*Cipher, error) {
	// Validate key size
	switch len(key) {
	case 16, 24, 32:
		// Valid AES key sizes
	default:
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &Cipher{
		cipher: block,
		m:      256, // Pool size (number of S-boxes) - standard is 256 for byte alphabet
	}, nil
}

// Encrypt performs FAST format-preserving encryption on the input data.
// The output has the same length as the input. The optional tweak parameter
// provides domain separation - different tweaks produce different ciphertexts
// for the same plaintext.
//
// Returns nil if the cipher is nil or data exceeds MaxDataSize.
func (f *Cipher) Encrypt(data []byte, tweak []byte) []byte {
	if f == nil || f.cipher == nil {
		return nil
	}

	if len(data) == 0 {
		return data
	}

	if len(data) > MaxDataSize {
		return nil
	}

	// For 2-byte inputs, use a simple substitution cipher approach
	// The FAST construction with w=0 doesn't provide unique decryption for ell=2
	if len(data) == 2 {
		return f.encrypt2Byte(data, tweak)
	}

	// FAST parameters for byte-oriented data
	ell := len(data)
	n := f.computeRounds(ell)
	w, wPrime := f.computeBranchDistances(ell)

	// Setup phase 1: Generate S-box pool (independent of tweak)
	sboxes := f.getSBoxPool()

	// Setup phase 2: Generate index sequence
	seq := f.generateIndexSequence(n, ell, w, wPrime, tweak)

	// Core encryption - use workspace to avoid repeated allocations
	state := make([]byte, ell)
	copy(state, data)

	// Pre-allocate workspace for forwardLayer to avoid allocations in hot loop
	workspace := make([]byte, ell)

	// Apply all rounds at once
	result := f.forwardLayerAllRounds(state, workspace, sboxes, seq, n, w, wPrime)

	return result
}

// Decrypt performs FAST format-preserving decryption on the input data.
// The output has the same length as the input. The same tweak used for
// encryption must be provided for successful decryption.
//
// Returns nil if the cipher is nil or data exceeds MaxDataSize.
func (f *Cipher) Decrypt(data []byte, tweak []byte) []byte {
	if f == nil || f.cipher == nil {
		return nil
	}

	if len(data) == 0 {
		return data
	}

	if len(data) > MaxDataSize {
		return nil
	}

	// For 2-byte inputs, use a simple substitution cipher approach
	if len(data) == 2 {
		return f.decrypt2Byte(data, tweak)
	}

	// FAST parameters for byte-oriented data
	ell := len(data)
	n := f.computeRounds(ell)
	w, wPrime := f.computeBranchDistances(ell)

	// Setup phases
	sboxes := f.getSBoxPool()
	seq := f.generateIndexSequence(n, ell, w, wPrime, tweak)

	// Core decryption (reverse order) - use workspace to avoid repeated allocations
	state := make([]byte, ell)
	copy(state, data)

	// Pre-allocate workspace for inverseLayer to avoid allocations in hot loop
	workspace := make([]byte, ell)

	// Apply all rounds at once (in reverse)
	result := f.inverseLayerAllRounds(state, workspace, sboxes, seq, n, w, wPrime)

	return result
}

// forwardLayerAllRounds implements the E_S[i] operation for all n rounds
// This optimized version uses specialized implementations for common sizes.
func (f *Cipher) forwardLayerAllRounds(x, workspace []byte, sboxes [][]byte, seq []byte, n, w, wPrime int) []byte {
	ell := len(x)

	// Special case: single element
	if ell == 1 {
		// Apply S-box for each round
		for j := 0; j < n; j++ {
			x[0] = sboxes[seq[j]][x[0]]
		}
		return x
	}

	// Use specialized implementations for common power-of-2 sizes
	switch ell {
	case 16:
		return f.forwardLayerSimple(x, sboxes, seq, n, w, wPrime)
	case 32:
		return f.forwardLayerPowerOf2Specialized(x, workspace, sboxes, seq, n, 32, 31, 6, 5)
	case 64:
		return f.forwardLayerPowerOf2Unrolled(x, workspace, sboxes, seq, n, 64, 63, 8, 7, 2)
	case 128:
		return f.forwardLayerPowerOf2Unrolled(x, workspace, sboxes, seq, n, 128, 127, 12, 11, 4)
	case 256:
		return f.forwardLayerPowerOf2Specialized(x, workspace, sboxes, seq, n, 256, 255, 16, 15)
	case 512:
		return f.forwardLayerPowerOf2Specialized(x, workspace, sboxes, seq, n, 512, 511, 23, 22)
	case 1024:
		return f.forwardLayerPowerOf2Unrolled(x, workspace, sboxes, seq, n, 1024, 1023, 32, 31, 4)
	default:
		// Check if it's a power of 2
		if ell&(ell-1) == 0 {
			mask := ell - 1
			return f.forwardLayerPowerOf2Generic(x, workspace, sboxes, seq, n, ell, mask, w, wPrime)
		}
		// Fall back to general implementation
		return f.forwardLayerGeneral(x, workspace, sboxes, seq, n, w, wPrime)
	}
}

// forwardLayerSimple implements the forward layer with physical array shifts
// matching the Zig reference implementation. This is used for debugging to ensure
// identical behavior with the Zig implementation.
func (f *Cipher) forwardLayerSimple(x []byte, sboxes [][]byte, seq []byte, n, w, wPrime int) []byte {
	ell := len(x)

	for j := 0; j < n; j++ {
		sbox := sboxes[seq[j]]

		// Compute sum1 = x[0] + x[ell - wPrime]
		sum1 := x[0] + x[ell-wPrime]
		u := sbox[sum1]

		// Compute new_last
		var newLast byte
		if w > 0 {
			intermediate := u - x[w]
			newLast = sbox[intermediate]
		} else {
			newLast = sbox[u]
		}

		// Physical left shift: copy x[1:] to x[0:ell-1]
		copy(x[0:ell-1], x[1:ell])
		x[ell-1] = newLast
	}

	return x
}

// forwardLayerPowerOf2Specialized is optimized for specific power-of-2 sizes
func (f *Cipher) forwardLayerPowerOf2Specialized(x, workspace []byte, sboxes [][]byte, seq []byte, n, ell, mask, w, wPrime int) []byte {
	// Copy initial state to workspace
	copy(workspace, x)

	// Use masking for circular indexing
	startIdx := 0

	for j := 0; j < n; j++ {
		sbox := sboxes[seq[j]]

		// Use bitwise AND for fast modulo with power-of-2
		firstIdx := startIdx
		mixIdx := (startIdx - wPrime) & mask
		wIdx := (startIdx + w) & mask

		// Core operation
		t := workspace[firstIdx] + workspace[mixIdx]
		u := sbox[t]
		v := sbox[u-workspace[wIdx]]

		workspace[startIdx] = v
		startIdx = (startIdx + 1) & mask
	}

	// Copy final result back
	if startIdx == 0 {
		copy(x, workspace)
	} else {
		copy(x, workspace[startIdx:])
		copy(x[ell-startIdx:], workspace[:startIdx])
	}
	return x
}

// forwardLayerPowerOf2Unrolled is optimized with loop unrolling for better performance
func (f *Cipher) forwardLayerPowerOf2Unrolled(x, workspace []byte, sboxes [][]byte, seq []byte, n, ell, mask, w, wPrime, unroll int) []byte {
	// Copy initial state to workspace
	copy(workspace, x)

	// Use masking for circular indexing
	startIdx := 0

	// Process rounds with unrolling
	for j := 0; j < n; j += unroll {
		if unroll == 2 {
			sbox0 := sboxes[seq[j]]
			sbox1 := sboxes[seq[j+1]]

			// Round 0
			idx0 := startIdx
			t0 := workspace[idx0] + workspace[(idx0-wPrime)&mask]
			u0 := sbox0[t0]
			workspace[idx0] = sbox0[u0-workspace[(idx0+w)&mask]]

			// Round 1
			idx1 := (idx0 + 1) & mask
			t1 := workspace[idx1] + workspace[(idx1-wPrime)&mask]
			u1 := sbox1[t1]
			workspace[idx1] = sbox1[u1-workspace[(idx1+w)&mask]]

			startIdx = (idx1 + 1) & mask
		} else { // unroll == 4
			sbox0 := sboxes[seq[j]]
			sbox1 := sboxes[seq[j+1]]
			sbox2 := sboxes[seq[j+2]]
			sbox3 := sboxes[seq[j+3]]

			// Round 0
			idx0 := startIdx
			t0 := workspace[idx0] + workspace[(idx0-wPrime)&mask]
			u0 := sbox0[t0]
			workspace[idx0] = sbox0[u0-workspace[(idx0+w)&mask]]

			// Round 1
			idx1 := (idx0 + 1) & mask
			t1 := workspace[idx1] + workspace[(idx1-wPrime)&mask]
			u1 := sbox1[t1]
			workspace[idx1] = sbox1[u1-workspace[(idx1+w)&mask]]

			// Round 2
			idx2 := (idx1 + 1) & mask
			t2 := workspace[idx2] + workspace[(idx2-wPrime)&mask]
			u2 := sbox2[t2]
			workspace[idx2] = sbox2[u2-workspace[(idx2+w)&mask]]

			// Round 3
			idx3 := (idx2 + 1) & mask
			t3 := workspace[idx3] + workspace[(idx3-wPrime)&mask]
			u3 := sbox3[t3]
			workspace[idx3] = sbox3[u3-workspace[(idx3+w)&mask]]

			startIdx = (idx3 + 1) & mask
		}
	}

	// Copy final result back
	if startIdx == 0 {
		copy(x, workspace)
	} else {
		copy(x, workspace[startIdx:])
		copy(x[ell-startIdx:], workspace[:startIdx])
	}
	return x
}

// forwardLayerPowerOf2Generic handles any power-of-2 size
func (f *Cipher) forwardLayerPowerOf2Generic(x, workspace []byte, sboxes [][]byte, seq []byte, n, ell, mask, w, wPrime int) []byte {
	// Copy initial state to workspace
	copy(workspace, x)

	// Pre-compute conditions
	hasMixingPartnerWPrime := ell-wPrime >= 0
	hasMixingPartnerW := w < ell

	// Use masking for circular indexing
	startIdx := 0

	for j := 0; j < n; j++ {
		sbox := sboxes[seq[j]]

		// Use bitwise AND for modulo with power-of-2
		firstIdx := startIdx
		mixIdx := (startIdx + ell - wPrime) & mask
		wIdx := (startIdx + w) & mask

		// Step 1: Compute mixing value
		var t byte
		if hasMixingPartnerWPrime {
			t = workspace[firstIdx] + workspace[mixIdx]
		} else {
			t = workspace[firstIdx]
		}

		// Step 2: First S-box lookup
		u := sbox[t]

		// Step 3: Second S-box lookup
		var v byte
		if hasMixingPartnerW {
			v = sbox[u-workspace[wIdx]]
		} else {
			v = sbox[u]
		}

		// Step 4: Update circular buffer
		workspace[startIdx] = v
		startIdx = (startIdx + 1) & mask
	}

	// Copy final result back
	if startIdx == 0 {
		copy(x, workspace)
	} else {
		copy(x, workspace[startIdx:])
		copy(x[ell-startIdx:], workspace[:startIdx])
	}
	return x
}

// forwardLayerGeneral handles non-power-of-2 sizes without modulo operations
func (f *Cipher) forwardLayerGeneral(x, workspace []byte, sboxes [][]byte, seq []byte, n, w, wPrime int) []byte {
	ell := len(x)

	// Copy initial state to workspace
	copy(workspace, x)

	// Pre-compute conditions
	hasMixingPartnerWPrime := ell-wPrime >= 0
	hasMixingPartnerW := w < ell

	// Process rounds without modulo by handling wraparound explicitly
	pos := 0
	for round := 0; round < n; round++ {
		sbox := sboxes[seq[round]]

		// Calculate indices with explicit wraparound
		firstIdx := pos
		mixIdx := pos - wPrime
		if mixIdx < 0 {
			mixIdx += ell
		}
		wIdx := pos + w
		if wIdx >= ell {
			wIdx -= ell
		}

		// Step 1: Compute mixing value
		var t byte
		if hasMixingPartnerWPrime {
			t = workspace[firstIdx] + workspace[mixIdx]
		} else {
			t = workspace[firstIdx]
		}

		// Step 2: First S-box lookup
		u := sbox[t]

		// Step 3: Second S-box lookup
		var v byte
		if hasMixingPartnerW {
			v = sbox[u-workspace[wIdx]]
		} else {
			v = sbox[u]
		}

		// Step 4: Store result and advance position
		workspace[pos] = v
		pos++
		if pos >= ell {
			pos = 0
		}
	}

	// Copy final result back with correct ordering
	if pos == 0 {
		copy(x, workspace)
	} else {
		// Reorder from circular buffer
		copy(x, workspace[pos:])
		copy(x[ell-pos:], workspace[:pos])
	}

	return x
}

// inverseLayerAllRounds implements the D_S[i] operation for all n rounds (in reverse)
// This optimized version uses specialized implementations for common sizes.
func (f *Cipher) inverseLayerAllRounds(y, workspace []byte, sboxes [][]byte, seq []byte, n, w, wPrime int) []byte {
	ell := len(y)

	// Special case: single element
	if ell == 1 {
		// Apply inverse S-box for each round in reverse
		for j := n - 1; j >= 0; j-- {
			y[0] = f.invSboxPool[seq[j]][y[0]]
		}
		return y
	}

	// Use specialized implementations for common power-of-2 sizes
	switch ell {
	case 16:
		return f.inverseLayerPowerOf2Specialized(y, workspace, sboxes, seq, n, 16, 15, 4, 3)
	case 32:
		return f.inverseLayerPowerOf2Specialized(y, workspace, sboxes, seq, n, 32, 31, 6, 5)
	case 64:
		return f.inverseLayerPowerOf2Unrolled(y, workspace, sboxes, seq, n, 64, 63, 8, 7, 2)
	case 128:
		return f.inverseLayerPowerOf2Unrolled(y, workspace, sboxes, seq, n, 128, 127, 12, 11, 4)
	case 256:
		return f.inverseLayerPowerOf2Specialized(y, workspace, sboxes, seq, n, 256, 255, 16, 15)
	case 512:
		return f.inverseLayerPowerOf2Specialized(y, workspace, sboxes, seq, n, 512, 511, 23, 22)
	case 1024:
		return f.inverseLayerPowerOf2Unrolled(y, workspace, sboxes, seq, n, 1024, 1023, 32, 31, 4)
	default:
		// Check if it's a power of 2
		if ell&(ell-1) == 0 {
			mask := ell - 1
			return f.inverseLayerPowerOf2Generic(y, workspace, sboxes, seq, n, ell, mask, w, wPrime)
		}
		// Fall back to general implementation
		return f.inverseLayerGeneral(y, workspace, sboxes, seq, n, w, wPrime)
	}
}

// inverseLayerPowerOf2Specialized is optimized for specific power-of-2 sizes
func (f *Cipher) inverseLayerPowerOf2Specialized(y, workspace []byte, sboxes [][]byte, seq []byte, n, ell, mask, w, wPrime int) []byte {
	// Copy initial state to workspace
	copy(workspace, y)

	// Pre-compute conditions
	hasMixingPartnerW := w < ell
	hasMixingPartnerWPrime := ell-wPrime > 0
	isSpecialCaseW0 := w == 0 && hasMixingPartnerW

	// Start with circular index at 0 (matching forward operation's final state)
	endIdx := 0

	// Process all rounds in reverse
	for j := n - 1; j >= 0; j-- {
		sboxIdx := seq[j]
		sbox := sboxes[sboxIdx]
		invSbox := f.invSboxPool[sboxIdx]

		// Move endIdx backward using masking
		endIdx = (endIdx - 1) & mask

		// Extract v from current position
		v := workspace[endIdx]

		if isSpecialCaseW0 {
			// Special case for w=0
			firstIdx := endIdx
			secondIdx := (endIdx + 1) & mask

			// Try all possible x[0] values
			found := false
			for x0 := 0; x0 < 256; x0++ {
				t := byte(x0) + workspace[secondIdx]
				u := sbox[t]
				if sbox[u-byte(x0)] == v {
					workspace[firstIdx] = byte(x0)
					found = true
					break
				}
			}
			if !found {
				workspace[firstIdx] = 0
			}
		} else {
			// Normal case
			var u byte
			if hasMixingPartnerW {
				wIdx := (endIdx + w) & mask
				u = invSbox[v] + workspace[wIdx]
			} else {
				u = invSbox[v]
			}

			t := invSbox[u]

			if hasMixingPartnerWPrime {
				mixIdx := (endIdx - wPrime) & mask
				workspace[endIdx] = t - workspace[mixIdx]
			} else {
				workspace[endIdx] = t
			}
		}
	}

	// Copy final result back with correct ordering
	if endIdx == 0 {
		copy(y, workspace)
	} else {
		copy(y, workspace[endIdx:])
		copy(y[ell-endIdx:], workspace[:endIdx])
	}
	return y
}

// inverseLayerPowerOf2Unrolled is optimized with loop unrolling for better performance
func (f *Cipher) inverseLayerPowerOf2Unrolled(y, workspace []byte, sboxes [][]byte, seq []byte, n, ell, mask, w, wPrime, unroll int) []byte {
	// Copy initial state to workspace
	copy(workspace, y)

	// Pre-compute conditions
	hasMixingPartnerW := w < ell
	hasMixingPartnerWPrime := ell-wPrime > 0

	// Start with circular index at 0
	endIdx := 0

	// Process rounds with unrolling
	for j := n - unroll; j >= 0; j -= unroll {
		if unroll == 2 {
			invSbox1 := f.invSboxPool[seq[j+1]]
			invSbox0 := f.invSboxPool[seq[j]]

			// Round j+1 (second round in reverse)
			idx1 := (endIdx - 1) & mask
			v1 := workspace[idx1]
			var u1 byte
			if hasMixingPartnerW {
				u1 = invSbox1[v1] + workspace[(idx1+w)&mask]
			} else {
				u1 = invSbox1[v1]
			}
			t1 := invSbox1[u1]
			if hasMixingPartnerWPrime {
				workspace[idx1] = t1 - workspace[(idx1-wPrime)&mask]
			} else {
				workspace[idx1] = t1
			}

			// Round j (first round in reverse)
			idx0 := (idx1 - 1) & mask
			v0 := workspace[idx0]
			var u0 byte
			if hasMixingPartnerW {
				u0 = invSbox0[v0] + workspace[(idx0+w)&mask]
			} else {
				u0 = invSbox0[v0]
			}
			t0 := invSbox0[u0]
			if hasMixingPartnerWPrime {
				workspace[idx0] = t0 - workspace[(idx0-wPrime)&mask]
			} else {
				workspace[idx0] = t0
			}

			endIdx = idx0
		} else { // unroll == 4
			invSbox3 := f.invSboxPool[seq[j+3]]
			invSbox2 := f.invSboxPool[seq[j+2]]
			invSbox1 := f.invSboxPool[seq[j+1]]
			invSbox0 := f.invSboxPool[seq[j]]

			// Round j+3
			idx3 := (endIdx - 1) & mask
			v3 := workspace[idx3]
			var u3 byte
			if hasMixingPartnerW {
				u3 = invSbox3[v3] + workspace[(idx3+w)&mask]
			} else {
				u3 = invSbox3[v3]
			}
			t3 := invSbox3[u3]
			if hasMixingPartnerWPrime {
				workspace[idx3] = t3 - workspace[(idx3-wPrime)&mask]
			} else {
				workspace[idx3] = t3
			}

			// Round j+2
			idx2 := (idx3 - 1) & mask
			v2 := workspace[idx2]
			var u2 byte
			if hasMixingPartnerW {
				u2 = invSbox2[v2] + workspace[(idx2+w)&mask]
			} else {
				u2 = invSbox2[v2]
			}
			t2 := invSbox2[u2]
			if hasMixingPartnerWPrime {
				workspace[idx2] = t2 - workspace[(idx2-wPrime)&mask]
			} else {
				workspace[idx2] = t2
			}

			// Round j+1
			idx1 := (idx2 - 1) & mask
			v1 := workspace[idx1]
			var u1 byte
			if hasMixingPartnerW {
				u1 = invSbox1[v1] + workspace[(idx1+w)&mask]
			} else {
				u1 = invSbox1[v1]
			}
			t1 := invSbox1[u1]
			if hasMixingPartnerWPrime {
				workspace[idx1] = t1 - workspace[(idx1-wPrime)&mask]
			} else {
				workspace[idx1] = t1
			}

			// Round j
			idx0 := (idx1 - 1) & mask
			v0 := workspace[idx0]
			var u0 byte
			if hasMixingPartnerW {
				u0 = invSbox0[v0] + workspace[(idx0+w)&mask]
			} else {
				u0 = invSbox0[v0]
			}
			t0 := invSbox0[u0]
			if hasMixingPartnerWPrime {
				workspace[idx0] = t0 - workspace[(idx0-wPrime)&mask]
			} else {
				workspace[idx0] = t0
			}

			endIdx = idx0
		}
	}

	// Copy final result back with correct ordering
	if endIdx == 0 {
		copy(y, workspace)
	} else {
		copy(y, workspace[endIdx:])
		copy(y[ell-endIdx:], workspace[:endIdx])
	}
	return y
}

// inverseLayerPowerOf2Generic handles any power-of-2 size
func (f *Cipher) inverseLayerPowerOf2Generic(y, workspace []byte, sboxes [][]byte, seq []byte, n, ell, mask, w, wPrime int) []byte {
	// Copy initial state to workspace
	copy(workspace, y)

	// Pre-compute conditions
	hasMixingPartnerW := w < ell
	hasMixingPartnerWPrime := ell-wPrime > 0
	isSpecialCaseW0 := w == 0 && hasMixingPartnerW

	// Start with circular index at 0
	endIdx := 0

	// Process all rounds in reverse
	for j := n - 1; j >= 0; j-- {
		sboxIdx := seq[j]
		sbox := sboxes[sboxIdx]
		invSbox := f.invSboxPool[sboxIdx]

		// Move endIdx backward using masking
		endIdx = (endIdx + ell - 1) & mask

		// Extract v from current position
		v := workspace[endIdx]

		if isSpecialCaseW0 {
			// Special case for w=0
			firstIdx := endIdx
			secondIdx := (endIdx + 1) & mask

			// Try all possible x[0] values
			found := false
			for x0 := 0; x0 < 256; x0++ {
				t := byte(x0) + workspace[secondIdx]
				u := sbox[t]
				if sbox[u-byte(x0)] == v {
					workspace[firstIdx] = byte(x0)
					found = true
					break
				}
			}
			if !found {
				workspace[firstIdx] = 0
			}
		} else {
			// Normal case
			var u byte
			if hasMixingPartnerW {
				wIdx := (endIdx + w) & mask
				u = invSbox[v] + workspace[wIdx]
			} else {
				u = invSbox[v]
			}

			t := invSbox[u]

			if hasMixingPartnerWPrime {
				mixIdx := (endIdx + ell - wPrime) & mask
				workspace[endIdx] = t - workspace[mixIdx]
			} else {
				workspace[endIdx] = t
			}
		}
	}

	// Copy final result back with correct ordering
	if endIdx == 0 {
		copy(y, workspace)
	} else {
		// Reorder data from circular buffer
		for i := 0; i < ell; i++ {
			y[i] = workspace[(endIdx+i)&mask]
		}
	}
	return y
}

// inverseLayerGeneral handles non-power-of-2 sizes without modulo operations
func (f *Cipher) inverseLayerGeneral(y, workspace []byte, sboxes [][]byte, seq []byte, n, w, wPrime int) []byte {
	ell := len(y)

	// Copy initial state to workspace
	copy(workspace, y)

	// Pre-compute conditions
	hasMixingPartnerW := w < ell
	hasMixingPartnerWPrime := ell-wPrime > 0
	isSpecialCaseW0 := w == 0 && hasMixingPartnerW

	// Start with circular index at 0
	endIdx := 0

	// Process all rounds in reverse
	for j := n - 1; j >= 0; j-- {
		sboxIdx := seq[j]
		sbox := sboxes[sboxIdx]
		invSbox := f.invSboxPool[sboxIdx]

		// Move endIdx backward
		endIdx--
		if endIdx < 0 {
			endIdx = ell - 1
		}

		// Extract v from current position
		v := workspace[endIdx]

		if isSpecialCaseW0 {
			// Special case for w=0
			firstIdx := endIdx
			secondIdx := endIdx + 1
			if secondIdx >= ell {
				secondIdx = 0
			}

			// Try all possible x[0] values
			found := false
			for x0 := 0; x0 < 256; x0++ {
				t := byte(x0) + workspace[secondIdx]
				u := sbox[t]
				if sbox[u-byte(x0)] == v {
					workspace[firstIdx] = byte(x0)
					found = true
					break
				}
			}
			if !found {
				workspace[firstIdx] = 0
			}
		} else {
			// Normal case
			var u byte
			if hasMixingPartnerW {
				wIdx := endIdx + w
				if wIdx >= ell {
					wIdx -= ell
				}
				u = invSbox[v] + workspace[wIdx]
			} else {
				u = invSbox[v]
			}

			t := invSbox[u]

			if hasMixingPartnerWPrime {
				mixIdx := endIdx - wPrime
				if mixIdx < 0 {
					mixIdx += ell
				}
				workspace[endIdx] = t - workspace[mixIdx]
			} else {
				workspace[endIdx] = t
			}
		}
	}

	// Copy final result back with correct ordering
	if endIdx == 0 {
		copy(y, workspace)
	} else {
		// Reorder data from circular buffer
		for i := 0; i < ell; i++ {
			idx := endIdx + i
			if idx >= ell {
				idx -= ell
			}
			y[i] = workspace[idx]
		}
	}
	return y
}

// getSBoxPool returns the cached S-box pool, generating it once on first access.
func (f *Cipher) getSBoxPool() [][]byte {
	f.sboxPoolOnce.Do(func() {
		f.sboxPool = f.generateSBoxPool(nil)
		// Pre-compute all inverse S-boxes
		f.invSboxPool = make([][]byte, f.m)
		for i := 0; i < f.m; i++ {
			f.invSboxPool[i] = f.computeInverseSBox(f.sboxPool[i])
		}
	})
	return f.sboxPool
}

// generateSBoxPool generates m bijective S-boxes using Setup1 from the FAST specification.
// The S-boxes depend only on the master key and alphabet size, not on the tweak.
// This implementation matches the Zig/C reference implementation encoding.
func (f *Cipher) generateSBoxPool(_ []byte) [][]byte {
	sboxes := make([][]byte, f.m)

	// Build Setup1 input matching Zig reference implementation:
	// encodeParts([
	//   "instance1",
	//   radix (256 as 4-byte big-endian),
	//   sbox_count (m as 4-byte big-endian),
	//   "FPE Pool"
	// ])

	radix := writeU32Be(256)
	m := writeU32Be(uint32(f.m))

	parts := [][]byte{
		[]byte("instance1"),
		radix[:],
		m[:],
		[]byte("FPE Pool"), // Note: space not hyphen
	}

	input := encodeParts(parts)

	// Use AES-CMAC in counter mode to generate 256 bits (32 bytes)
	// This matches the Zig/C reference implementation: CMAC(counter || input)
	kseed := make([]byte, 32)

	// Prepare buffer: counter (4 bytes) || input
	buffer := make([]byte, 4+len(input))
	copy(buffer[4:], input)

	// Generate first 16 bytes: CMAC(0x00000000 || input)
	binary.BigEndian.PutUint32(buffer[0:4], 0)
	copy(kseed[:16], f.aesCMACOptimized(buffer))

	// Generate next 16 bytes: CMAC(0x00000001 || input)
	binary.BigEndian.PutUint32(buffer[0:4], 1)
	copy(kseed[16:], f.aesCMACOptimized(buffer))

	// Split K_S into AES key K₂ (first 128 bits) and IV₂ (last 128 bits)
	block2, err := aes.NewCipher(kseed[:16])
	if err != nil {
		panic("failed to create AES cipher for S-box generation: " + err.Error())
	}
	iv2 := kseed[16:]

	// Initialize CTR mode ONCE with IV as the initial counter
	// IMPORTANT: The Zig/C reference implementation increments the counter
	// BEFORE the first encryption. We need to match this behavior.
	// The PRNG starts with buffer_pos = AES_BLOCK_SIZE, which triggers:
	//   incrementCounter(&self.counter)
	//   encrypt(&self.buffer, &self.counter)
	// So the first block encrypted is (IV + 1), not IV.
	ctr := make([]byte, 16)
	copy(ctr, iv2)

	// Increment counter by 1 (big-endian) to match Zig's pre-increment
	for i := 15; i >= 0; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
	}

	// Create CTR stream ONCE and reuse it for all S-boxes
	// This matches the Zig implementation where a single PRNG state is used
	stream := cipher.NewCTR(block2, ctr)

	// Random byte buffer shared across all S-box generation
	const bufferSize = 4096
	randomBuf := make([]byte, bufferSize)
	bufPos := bufferSize // Force initial fill

	// Generate each S-box using the shared CTR stream
	for i := 0; i < f.m; i++ {
		sboxes[i] = f.generateSingleSBoxWithSharedStream(stream, randomBuf, &bufPos, bufferSize)
	}

	return sboxes
}

// generateSingleSBoxWithSharedStream generates a single S-box using a shared AES-CTR stream.
// The stream parameter is reused across all S-boxes to ensure each gets unique random bytes.
func (f *Cipher) generateSingleSBoxWithSharedStream(stream cipher.Stream, randomBuf []byte, bufPos *int, bufferSize int) []byte {
	sbox := make([]byte, 256)
	for i := range sbox {
		sbox[i] = byte(i)
	}

	getNext32 := func() uint32 {
		// Refill buffer if needed using CTR stream
		if *bufPos+4 > bufferSize {
			// Clear buffer to zeros before XORing with keystream
			clear(randomBuf)
			stream.XORKeyStream(randomBuf, randomBuf)
			*bufPos = 0
		}

		val := binary.BigEndian.Uint32(randomBuf[*bufPos:])
		*bufPos += 4
		return val
	}

	// Fisher-Yates shuffle using Lemire's method for unbiased selection
	for i := 255; i > 0; i-- {
		// Use Lemire's method for unbiased random selection
		j := lemireRandomIndex(getNext32, i+1)
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}

	return sbox
}

// generateIndexSequence generates the sequence of S-box indices using Setup2 from the FAST specification.
// The sequence depends on the instance parameters (ℓ, n, w, w') and the tweak.
// This implementation matches the Zig/C reference implementation encoding.
func (f *Cipher) generateIndexSequence(n, ell, w, wPrime int, tweak []byte) []byte {
	// Fast path: when tweak is nil, check if we've already cached the result
	if tweak == nil {
		return f.generateIndexSequenceNoTweak(n, ell, w, wPrime)
	}

	// Build Setup2 input matching Zig reference implementation:
	// encodeParts([
	//   "instance1",
	//   radix (256 as 4-byte big-endian),
	//   sbox_count (m as 4-byte big-endian),
	//   "instance2",
	//   word_length (ell as 4-byte big-endian),
	//   num_layers (n as 4-byte big-endian),
	//   branch_dist1 (w as 4-byte big-endian),
	//   branch_dist2 (wp as 4-byte big-endian),
	//   "FPE SEQ",
	//   "tweak",
	//   tweak_data
	// ])

	radix := writeU32Be(256)
	m := writeU32Be(uint32(f.m))
	ellBe := writeU32Be(uint32(ell))
	nBe := writeU32Be(uint32(n))
	wBe := writeU32Be(uint32(w))
	wpBe := writeU32Be(uint32(wPrime))

	parts := [][]byte{
		[]byte("instance1"),
		radix[:],
		m[:],
		[]byte("instance2"),
		ellBe[:],
		nBe[:],
		wBe[:],
		wpBe[:],
		[]byte("FPE SEQ"), // Note: space not hyphen
		[]byte("tweak"),
		tweak,
	}

	input := encodeParts(parts)

	// Use AES-CMAC in counter mode to generate 256 bits (32 bytes)
	// This matches the Zig/C reference implementation: CMAC(counter || input)
	kseq := make([]byte, 32)

	// Prepare buffer: counter (4 bytes) || input
	buffer := make([]byte, 4+len(input))
	copy(buffer[4:], input)

	// Generate first 16 bytes: CMAC(0x00000000 || input)
	binary.BigEndian.PutUint32(buffer[0:4], 0)
	copy(kseq[:16], f.aesCMACOptimized(buffer))

	// Generate next 16 bytes: CMAC(0x00000001 || input)
	binary.BigEndian.PutUint32(buffer[0:4], 1)
	copy(kseq[16:], f.aesCMACOptimized(buffer))

	// Create cache key from the first 16 bytes of kseq (the AES key)
	cacheKey := string(kseq[:16])

	// Check cache first
	f.indexCacheMu.RLock()
	block1, exists := f.indexCipherCache[cacheKey]
	f.indexCacheMu.RUnlock()

	if !exists {
		// Cache miss - create new cipher
		var err error
		block1, err = aes.NewCipher(kseq[:16])
		if err != nil {
			panic("failed to create AES cipher for sequence generation: " + err.Error())
		}

		// Store in cache
		f.indexCacheMu.Lock()
		if f.indexCipherCache == nil {
			f.indexCipherCache = make(map[string]cipher.Block)
		}
		f.indexCipherCache[cacheKey] = block1
		f.indexCacheMu.Unlock()
	}

	iv1 := make([]byte, 16)
	copy(iv1, kseq[16:])
	iv1[14], iv1[15] = 0, 0 // Force last two bytes to 0 (avoid slide attacks)

	// Increment counter by 1 (big-endian) to match Zig's pre-increment
	// The PRNG increments the counter BEFORE the first encryption
	for i := 15; i >= 0; i-- {
		iv1[i]++
		if iv1[i] != 0 {
			break
		}
	}

	// Generate n sequence elements using uniform distribution
	// The Zig reference uses uniform() which consumes 4 bytes per element with rejection sampling
	seq := make([]byte, n)

	// Use cipher.NewCTR for random byte generation
	stream := cipher.NewCTR(block1, iv1)

	// Calculate threshold for rejection sampling (Lemire's method)
	bound := uint32(f.m)
	threshold := uint32(((uint64(1) << 32) - uint64(bound)) % uint64(bound))

	// Generate sequence with rejection sampling
	// Allocate a buffer large enough to handle rejections (oversized)
	bufSize := n * 8 // 2x normal size to handle potential rejections
	randomBuf := make([]byte, bufSize)
	stream.XORKeyStream(randomBuf, randomBuf)

	seqIdx := 0
	bufIdx := 0
	for seqIdx < n {
		if bufIdx+4 > len(randomBuf) {
			// Need more random bytes
			stream.XORKeyStream(randomBuf, randomBuf)
			bufIdx = 0
		}

		// Read 4 bytes as big-endian u32
		r := binary.BigEndian.Uint32(randomBuf[bufIdx : bufIdx+4])
		bufIdx += 4

		// Apply Lemire's method with rejection sampling
		prod := uint64(r) * uint64(bound)
		low := uint32(prod)

		if low >= threshold {
			// Accept this value
			seq[seqIdx] = byte(prod >> 32)
			seqIdx++
		}
		// Else reject and try again
	}

	return seq
}

// generateIndexSequenceNoTweak is an optimized version for when tweak is nil.
// It caches the result since the same parameters will always produce the same sequence.
// This implementation matches the Zig/C reference implementation encoding.
func (f *Cipher) generateIndexSequenceNoTweak(n, ell, w, wPrime int) []byte {
	// Create cache key from parameters
	cacheKey := fmt.Sprintf("%d:%d:%d:%d", n, ell, w, wPrime)

	// Check cache first
	f.noTweakSeqMu.RLock()
	if seq, exists := f.noTweakSeqCache[cacheKey]; exists {
		f.noTweakSeqMu.RUnlock()
		return seq
	}
	f.noTweakSeqMu.RUnlock()

	// Cache miss - generate the sequence using same encoding as with tweak
	radix := writeU32Be(256)
	m := writeU32Be(uint32(f.m))
	ellBe := writeU32Be(uint32(ell))
	nBe := writeU32Be(uint32(n))
	wBe := writeU32Be(uint32(w))
	wpBe := writeU32Be(uint32(wPrime))

	parts := [][]byte{
		[]byte("instance1"),
		radix[:],
		m[:],
		[]byte("instance2"),
		ellBe[:],
		nBe[:],
		wBe[:],
		wpBe[:],
		[]byte("FPE SEQ"),
		[]byte("tweak"),
		[]byte{}, // empty tweak
	}

	input := encodeParts(parts)

	// Use AES-CMAC in counter mode to generate 256 bits (32 bytes)
	// This matches the Zig/C reference implementation: CMAC(counter || input)
	kseq := make([]byte, 32)

	// Prepare buffer: counter (4 bytes) || input
	buffer := make([]byte, 4+len(input))
	copy(buffer[4:], input)

	// Generate first 16 bytes: CMAC(0x00000000 || input)
	binary.BigEndian.PutUint32(buffer[0:4], 0)
	copy(kseq[:16], f.aesCMACOptimized(buffer))

	// Generate next 16 bytes: CMAC(0x00000001 || input)
	binary.BigEndian.PutUint32(buffer[0:4], 1)
	copy(kseq[16:], f.aesCMACOptimized(buffer))

	// Create cipher for sequence generation
	block1, err := aes.NewCipher(kseq[:16])
	if err != nil {
		panic("failed to create AES cipher for sequence generation: " + err.Error())
	}

	iv1 := make([]byte, 16)
	copy(iv1, kseq[16:])
	iv1[14], iv1[15] = 0, 0 // Force last two bytes to 0 (avoid slide attacks)

	// Increment counter by 1 (big-endian) to match Zig's pre-increment
	// The PRNG increments the counter BEFORE the first encryption
	for i := 15; i >= 0; i-- {
		iv1[i]++
		if iv1[i] != 0 {
			break
		}
	}

	// Generate n sequence elements using uniform distribution
	// The Zig reference uses uniform() which consumes 4 bytes per element with rejection sampling
	seq := make([]byte, n)

	// Use cipher.NewCTR for random byte generation
	stream := cipher.NewCTR(block1, iv1)

	// Calculate threshold for rejection sampling (Lemire's method)
	bound := uint32(f.m)
	threshold := uint32(((uint64(1) << 32) - uint64(bound)) % uint64(bound))

	// Generate sequence with rejection sampling
	// Allocate a buffer large enough to handle rejections (oversized)
	bufSize := n * 8 // 2x normal size to handle potential rejections
	randomBuf := make([]byte, bufSize)
	stream.XORKeyStream(randomBuf, randomBuf)

	seqIdx := 0
	bufIdx := 0
	for seqIdx < n {
		if bufIdx+4 > len(randomBuf) {
			// Need more random bytes
			stream.XORKeyStream(randomBuf, randomBuf)
			bufIdx = 0
		}

		// Read 4 bytes as big-endian u32
		r := binary.BigEndian.Uint32(randomBuf[bufIdx : bufIdx+4])
		bufIdx += 4

		// Apply Lemire's method with rejection sampling
		prod := uint64(r) * uint64(bound)
		low := uint32(prod)

		if low >= threshold {
			// Accept this value
			seq[seqIdx] = byte(prod >> 32)
			seqIdx++
		}
		// Else reject and try again
	}

	// Store in cache
	f.noTweakSeqMu.Lock()
	if f.noTweakSeqCache == nil {
		f.noTweakSeqCache = make(map[string][]byte)
	}
	f.noTweakSeqCache[cacheKey] = seq
	f.noTweakSeqMu.Unlock()

	return seq
}

// computeInverseSBox computes the inverse permutation of an S-box.
// For each i, inv[sbox[i]] = i.
func (f *Cipher) computeInverseSBox(sbox []byte) []byte {
	inv := make([]byte, 256)
	for i := 0; i < 256; i++ {
		inv[sbox[i]] = byte(i)
	}
	return inv
}

// Lookup tables for recommended rounds (from Zig/C reference implementation)
var (
	roundLValues = []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 32, 50, 64, 100}
	roundRadices = []int{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 100, 128, 256, 1000, 1024, 10000, 65536}
	roundTable   = [][]int{
		{165, 135, 117, 105, 96, 89, 83, 78, 74, 68, 59, 52, 52, 53, 57}, // a = 4
		{131, 107, 93, 83, 76, 70, 66, 62, 59, 54, 48, 46, 47, 48, 53},   // a = 5
		{113, 92, 80, 72, 65, 61, 57, 54, 51, 46, 44, 43, 44, 46, 52},    // a = 6
		{102, 83, 72, 64, 59, 55, 51, 48, 46, 43, 41, 41, 43, 45, 50},    // a = 7
		{94, 76, 66, 59, 54, 50, 47, 44, 42, 41, 39, 39, 42, 44, 50},     // a = 8
		{88, 72, 62, 56, 51, 47, 44, 42, 40, 39, 38, 38, 41, 43, 49},     // a = 9
		{83, 68, 59, 53, 48, 45, 42, 39, 39, 38, 37, 37, 40, 43, 49},     // a = 10
		{79, 65, 56, 50, 46, 43, 40, 38, 38, 37, 36, 37, 40, 42, 48},     // a = 11
		{76, 62, 54, 48, 44, 41, 38, 37, 37, 36, 35, 36, 39, 42, 48},     // a = 12
		{73, 60, 52, 47, 43, 39, 37, 36, 36, 35, 34, 36, 39, 41, 48},     // a = 13
		{71, 58, 50, 45, 41, 38, 36, 36, 35, 34, 34, 35, 39, 41, 47},     // a = 14
		{69, 57, 49, 44, 40, 37, 36, 35, 34, 34, 33, 35, 38, 41, 47},     // a = 15
		{67, 55, 48, 43, 39, 36, 35, 34, 34, 33, 33, 35, 38, 41, 47},     // a = 16
		{40, 33, 28, 27, 26, 26, 25, 25, 25, 26, 26, 30, 34, 37, 44},     // a = 100
		{38, 31, 27, 26, 25, 25, 25, 25, 25, 25, 26, 30, 34, 37, 44},     // a = 128
		{33, 27, 25, 24, 23, 23, 23, 23, 23, 24, 25, 29, 33, 37, 44},     // a = 256
		{32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43},     // a = 1000
		{32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43},     // a = 1024
		{32, 22, 18, 18, 18, 18, 19, 19, 19, 20, 21, 27, 32, 35, 42},     // a = 10000
		{32, 22, 17, 17, 17, 17, 17, 18, 18, 19, 21, 26, 31, 35, 42},     // a = 65536
	}
)

// interpolate performs linear interpolation
func interpolate(x, x0, x1, y0, y1 float64) float64 {
	if x1 == x0 {
		return y0
	}
	t := (x - x0) / (x1 - x0)
	if t <= 0.0 {
		return y0
	}
	if t >= 1.0 {
		return y1
	}
	return y0 + t*(y1-y0)
}

// roundsForRow gets recommended rounds for a specific row and word length
func roundsForRow(rowIndex int, ell float64) float64 {
	row := roundTable[rowIndex]
	lCount := len(roundLValues)

	if ell <= float64(roundLValues[0]) {
		return float64(row[0])
	}
	if ell >= float64(roundLValues[lCount-1]) {
		last := float64(row[lCount-1])
		ratio := math.Sqrt(ell / float64(roundLValues[lCount-1]))
		projected := last * ratio
		if projected < last {
			return last
		}
		return projected
	}

	for i := 1; i < lCount; i++ {
		lPrev := float64(roundLValues[i-1])
		lCurr := float64(roundLValues[i])
		if ell <= lCurr {
			rPrev := float64(row[i-1])
			rCurr := float64(row[i])
			return interpolate(ell, lPrev, lCurr, rPrev, rCurr)
		}
	}

	return float64(row[lCount-1])
}

// lookupRecommendedRounds looks up recommended rounds with radix interpolation
func lookupRecommendedRounds(radix int, ell float64) float64 {
	radixCount := len(roundRadices)

	if radix <= roundRadices[0] {
		return roundsForRow(0, ell)
	}
	if radix >= roundRadices[radixCount-1] {
		return roundsForRow(radixCount-1, ell)
	}

	for i := 1; i < radixCount; i++ {
		rPrev := roundRadices[i-1]
		rCurr := roundRadices[i]
		if radix <= rCurr {
			roundsPrev := roundsForRow(i-1, ell)
			roundsCurr := roundsForRow(i, ell)
			logPrev := math.Log(float64(rPrev))
			logCurr := math.Log(float64(rCurr))
			logRadix := math.Log(float64(radix))
			return interpolate(logRadix, logPrev, logCurr, roundsPrev, roundsCurr)
		}
	}

	return roundsForRow(radixCount-1, ell)
}

// ComputeRoundsDebug is exported for debugging
func (f *Cipher) ComputeRoundsDebug(ell int) int {
	return f.computeRounds(ell)
}

// ComputeBranchDistancesDebug is exported for debugging
func (f *Cipher) ComputeBranchDistancesDebug(ell int) (int, int) {
	return f.computeBranchDistances(ell)
}

// GetSBoxPoolDebug is exported for debugging
func (f *Cipher) GetSBoxPoolDebug() [][]byte {
	return f.getSBoxPool()
}

// GenerateIndexSequenceDebug is exported for debugging
func (f *Cipher) GenerateIndexSequenceDebug(n, ell, w, wPrime int, tweak []byte) []byte {
	return f.generateIndexSequence(n, ell, w, wPrime, tweak)
}

// AesCMACDebug is exported for debugging
func (f *Cipher) AesCMACDebug(message []byte) []byte {
	return f.aesCMACOptimized(message)
}

// computeRounds computes the number of rounds (layers) n based on lookup tables
// from the FAST specification. This matches the Zig/C reference implementation.
func (f *Cipher) computeRounds(ell int) int {
	const radix = 256 // byte alphabet

	// Use lookup table with interpolation
	rounds := lookupRecommendedRounds(radix, float64(ell))
	if rounds < 1.0 {
		rounds = 1.0
	}

	roundsU := int(math.Ceil(rounds))

	// Return num_layers = rounds_u * word_length
	// This matches the Zig implementation at fast.zig:224
	return roundsU * ell
}

// computeBranchDistances computes the branch distances w and w' that determine
// which positions are mixed in each round. These ensure good diffusion properties.
func (f *Cipher) computeBranchDistances(ell int) (w, wPrime int) {
	// From FAST spec:
	// w = min(⌈√ℓ⌉, ℓ-2)
	// w' = max(1, w-1)

	// Compute ceiling of square root
	sqrtEll := int(math.Ceil(math.Sqrt(float64(ell))))

	w = sqrtEll
	if w > ell-2 {
		w = ell - 2
	}
	if w < 0 {
		w = 0
	}

	wPrime = w - 1
	if wPrime < 1 {
		wPrime = 1
	}

	// Special case for ℓ=2
	if ell == 2 {
		w = 0
		wPrime = 1
	}

	return w, wPrime
}

// encrypt2Byte handles the special case of 2-byte encryption
// Uses a different approach since FAST with w=0 doesn't provide unique decryption
func (f *Cipher) encrypt2Byte(data []byte, tweak []byte) []byte {
	if len(data) != 2 {
		panic("encrypt2Byte called with wrong size")
	}

	// Generate S-boxes
	sboxes := f.getSBoxPool()

	// Use tweak to select starting S-box
	var tweakHash byte
	if len(tweak) > 0 {
		mac := f.aesCMACOptimized(tweak)
		tweakHash = mac[0]
	}

	// Apply 8 rounds of substitution for 128-bit security
	result := make([]byte, 2)
	copy(result, data)

	for round := 0; round < 8; round++ {
		// Select S-box based on round and tweak
		sboxIdx := (int(tweakHash) + round*37) % f.m
		sbox := sboxes[sboxIdx]

		// Apply S-box to each byte
		result[0] = sbox[result[0]]
		result[1] = sbox[result[1]]

		// Mix bytes
		result[0], result[1] = result[1], byte(int(result[0])+int(result[1]))
	}

	return result
}

// decrypt2Byte handles the special case of 2-byte decryption
func (f *Cipher) decrypt2Byte(data []byte, tweak []byte) []byte {
	if len(data) != 2 {
		panic("decrypt2Byte called with wrong size")
	}

	// Generate S-boxes and their inverses
	_ = f.getSBoxPool() // This initializes both sboxPool and invSboxPool

	// Use tweak to select starting S-box
	var tweakHash byte
	if len(tweak) > 0 {
		mac := f.aesCMACOptimized(tweak)
		tweakHash = mac[0]
	}

	result := make([]byte, 2)
	copy(result, data)

	// Apply inverse of 8 rounds
	for round := 7; round >= 0; round-- {
		// Unmix bytes
		temp := result[0]
		result[0] = byte(int(result[1])-int(temp)+256) & 0xFF
		result[1] = temp

		// Select S-box and compute inverse
		sboxIdx := (int(tweakHash) + round*37) % f.m
		invSbox := f.invSboxPool[sboxIdx]

		// Apply inverse S-box to each byte
		result[0] = invSbox[result[0]]
		result[1] = invSbox[result[1]]
	}

	return result
}
