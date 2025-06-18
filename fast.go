// Package fast provides the FAST algorithm implementation for format-preserving encryption.
// Based on: "FAST: Secure and High Performance Format-Preserving Encryption and Tokenization"
// https://eprint.iacr.org/2021/1171.pdf
package fast

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
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
	for i := range mac {
		mac[i] = 0
	}

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
	for i := range lastBlock {
		lastBlock[i] = 0
	}
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

// incrementCounter increments a 128-bit counter
func incrementCounter(ctr []byte) {
	for i := len(ctr) - 1; i >= 0; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
	}
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
// This optimized version uses circular indexing to avoid memory copying.
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

	// Copy initial state to workspace
	copy(workspace, x)

	// Pre-compute conditions that don't change across rounds
	hasMixingPartnerWPrime := ell-wPrime >= 0
	hasMixingPartnerW := w < ell

	// Use circular indexing to avoid copying
	startIdx := 0

	// Process all rounds
	for j := 0; j < n; j++ {
		sbox := sboxes[seq[j]]

		// Step 1: Compute mixing value t = (x₀ + x_{ℓ-w'}) mod 256
		var t byte
		firstIdx := startIdx
		if hasMixingPartnerWPrime {
			mixIdx := (startIdx + ell - wPrime) % ell
			// For bytes, addition is already modulo 256 due to byte overflow
			t = workspace[firstIdx] + workspace[mixIdx]
		} else {
			t = workspace[firstIdx] // No mixing partner
		}

		// Step 2: First S-box lookup
		u := sbox[t]

		// Step 3: Second S-box lookup v = S[u - x_w mod 256]
		var v byte
		if hasMixingPartnerW {
			wIdx := (startIdx + w) % ell
			// For bytes, subtraction wraps around naturally
			v = sbox[u-workspace[wIdx]]
		} else {
			v = sbox[u] // No mixing partner
		}

		// Step 4: Instead of shifting, update the circular buffer
		// The new state has x₁, x₂, ..., x_{ℓ-1}, v
		// We achieve this by moving startIdx forward and placing v at the old start position
		workspace[startIdx] = v
		startIdx = (startIdx + 1) % ell
	}

	// Copy final result back to x if needed
	if startIdx == 0 {
		// Data is already in correct order
		copy(x, workspace)
	} else {
		// Reorder data from circular buffer
		for i := 0; i < ell; i++ {
			x[i] = workspace[(startIdx+i)%ell]
		}
	}

	return x
}

// inverseLayerAllRounds implements the D_S[i] operation for all n rounds (in reverse)
// This optimized version uses circular indexing to avoid memory copying.
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

	// Copy initial state to workspace
	copy(workspace, y)

	// Pre-compute conditions that don't change across rounds
	hasMixingPartnerW := w < ell
	hasMixingPartnerWPrime := ell-wPrime > 0 && ell-wPrime <= ell
	isSpecialCaseW0 := w == 0 && hasMixingPartnerW

	// Start with circular index at 0 (matching forward operation's final state)
	endIdx := 0

	// Process all rounds in reverse
	for j := n - 1; j >= 0; j-- {
		sboxIdx := seq[j]
		sbox := sboxes[sboxIdx]
		invSbox := f.invSboxPool[sboxIdx]

		// Move endIdx backward to reconstruct previous state
		endIdx = (endIdx + ell - 1) % ell

		// Step 1: Extract v from what was the last position in forward operation
		v := workspace[endIdx]

		// Special handling for w=0 case
		if isSpecialCaseW0 {
			// When w=0, we have a circular dependency:
			// v = S[u - x[0]] and u = S[x[0] + x[1]]
			// We need to find x[0] such that these equations hold

			firstIdx := endIdx
			secondIdx := (endIdx + 1) % ell

			// Try all possible x[0] values
			found := false
			for x0 := 0; x0 < 256; x0++ {
				// Compute what t would be: t = x[0] + x[1]
				t := byte(x0) + workspace[secondIdx]
				// Compute what u would be: u = S[t]
				u := sbox[t]
				// Check if S[u - x[0]] = v
				if sbox[u-byte(x0)] == v {
					workspace[firstIdx] = byte(x0)
					found = true
					break
				}
			}
			if !found {
				// This shouldn't happen with a valid ciphertext
				workspace[firstIdx] = 0
			}
		} else {
			// Step 3: Recover u by inverting the second S-box operation
			// Find u such that S[u - x_w mod 256] = v
			var u byte
			if hasMixingPartnerW {
				wIdx := (endIdx + w) % ell
				// Use inverse S-box to find u directly
				// We need: S[u - x_w] = v, so u - x_w = S^(-1)[v], so u = S^(-1)[v] + x_w
				u = invSbox[v] + workspace[wIdx]
			} else {
				u = invSbox[v]
			}

			// Step 4: Recover t by inverting first S-box
			t := invSbox[u]

			// Step 5: Recover x₀ = t - x_{ℓ-w'} mod 256
			firstIdx := endIdx
			if hasMixingPartnerWPrime {
				mixIdx := (endIdx + ell - wPrime) % ell
				// For bytes, subtraction wraps around naturally
				workspace[firstIdx] = t - workspace[mixIdx]
			} else {
				workspace[firstIdx] = t
			}
		}
	}

	// Copy final result back to y with correct ordering
	if endIdx == 0 {
		// Data is already in correct order
		copy(y, workspace)
	} else {
		// Reorder data from circular buffer
		for i := 0; i < ell; i++ {
			y[i] = workspace[(endIdx+i)%ell]
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
func (f *Cipher) generateSBoxPool(_ []byte) [][]byte {
	sboxes := make([][]byte, f.m)

	// Derive S-box seed K_S using PRF₂(K ∥ "FPE-Pool" ∥ (256,m))
	// PRF₂ outputs L₂ = 2s = 256 bits for 128-bit security
	input := []byte("FPE-Pool")
	// Encode instance₁ = (256, m) as unambiguous byte string
	input = append(input, 1, 0)                    // 256 as 2 bytes
	input = append(input, byte(f.m>>8), byte(f.m)) // m as 2 bytes

	// Use AES-CMAC as PRF₂ to generate 256 bits (32 bytes)
	kseed := make([]byte, 32)
	copy(kseed[:16], f.aesCMACOptimized(input))
	copy(kseed[16:], f.aesCMACOptimized(append(input, 0x01)))

	// Split K_S into AES key K₂ (first 128 bits) and IV₂ (last 128 bits)
	block2, err := aes.NewCipher(kseed[:16])
	if err != nil {
		panic("failed to create AES cipher for S-box generation: " + err.Error())
	}
	iv2 := kseed[16:]

	// Generate each S-box using AES-CTR stream
	for i := 0; i < f.m; i++ {
		sboxes[i] = f.generateSingleSBoxWithCTR(block2, iv2, i)
	}

	return sboxes
}

// generateSingleSBoxWithCTR generates a single S-box using AES-CTR and Fisher-Yates.
func (f *Cipher) generateSingleSBoxWithCTR(block cipher.Block, iv []byte, sboxIndex int) []byte {
	sbox := make([]byte, 256)
	for i := range sbox {
		sbox[i] = byte(i)
	}

	// Initialize CTR mode with IV for this S-box
	// Each S-box uses a different starting counter value
	ctr := make([]byte, 16)
	copy(ctr, iv)
	// Add S-box index to counter to ensure different streams for each S-box
	binary.BigEndian.PutUint32(ctr[12:], uint32(sboxIndex)<<16)

	// Use Go's built-in CTR mode for better performance
	stream := cipher.NewCTR(block, ctr)

	// Random byte generator using AES-CTR with larger buffer for efficiency
	const bufferSize = 4096 // Increased buffer size
	randomBuf := make([]byte, bufferSize)
	bufPos := bufferSize // Force initial fill

	getNext32 := func() uint32 {
		// Refill buffer if needed using CTR stream
		if bufPos+4 > bufferSize {
			stream.XORKeyStream(randomBuf, randomBuf)
			bufPos = 0
		}

		val := binary.BigEndian.Uint32(randomBuf[bufPos:])
		bufPos += 4
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
func (f *Cipher) generateIndexSequence(n, ell, w, wPrime int, tweak []byte) []byte {
	// Derive index seed K_SEQ using PRF₁(K ∥ "FPE-SEQ" ∥ (instance₁, instance₂) ∥ tweak)
	// where instance₁ = (256, m) and instance₂ = (ℓ, n, w, w')
	// PRF₁ outputs L₁ = 2s = 256 bits for 128-bit security

	input := []byte("FPE-SEQ")

	// Add instance1: (256, m) as unambiguous encoding
	input = append(input, 1, 0)                    // 256 as 2 bytes
	input = append(input, byte(f.m>>8), byte(f.m)) // m as 2 bytes

	// Add instance2: (ℓ, n, w, w′) as unambiguous encoding
	input = append(input, byte(ell>>8), byte(ell)) // ℓ as 2 bytes
	input = append(input, byte(n>>8), byte(n))     // n as 2 bytes
	input = append(input, byte(w), byte(wPrime))   // w and w' as 1 byte each

	// Add tweak
	if tweak != nil {
		input = append(input, tweak...)
	}

	// Use AES-CMAC as PRF₁ to generate 256 bits (32 bytes)
	kseq := make([]byte, 32)
	copy(kseq[:16], f.aesCMACOptimized(input))
	copy(kseq[16:], f.aesCMACOptimized(append(input, 0x01)))

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

	// Generate n bytes using Go's built-in CTR mode
	seq := make([]byte, n)

	// Use cipher.NewCTR for better performance
	stream := cipher.NewCTR(block1, iv1)
	stream.XORKeyStream(seq, seq)

	// Map to [0, m-1]
	// When m=256, we don't need to do modulo since seq[i] is already a byte [0,255]
	if f.m > 0 && f.m < 256 {
		for i := range seq {
			seq[i] = seq[i] % byte(f.m)
		}
	}

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

// computeRounds computes the number of rounds n based on the FAST security analysis.
// The formula ensures statistical indistinguishability from a random permutation.
func (f *Cipher) computeRounds(ell int) int {
	// For 128-bit security with alphabet size 256 (bytes)
	// Based on FAST paper recommendations
	s := 128.0 // security parameter

	// From the FAST specification:
	// n = ℓ * ⌈2 * max(2s/(ℓ*log₂m), s/√ℓ*ln(255), s/√ℓ*log₂(255)+2/√ℓ)⌉
	// For byte data with m=256:
	const (
		log2m  = 8.0   // log₂(256)
		lnA1   = 5.541 // ln(255)
		log2A1 = 7.994 // log₂(255)
	)

	sqrtEll := math.Sqrt(float64(ell))

	factor1 := (2 * s) / (float64(ell) * log2m) // 2s/(ℓ*log₂m)
	factor2 := s / (sqrtEll * lnA1)             // s/√ℓ*ln(255)
	factor3 := s/(sqrtEll*log2A1) + 2/sqrtEll   // s/√ℓ*log₂(255)+2/√ℓ

	maxFactor := math.Max(factor1, math.Max(factor2, factor3))

	// Calculate rounds: n = ℓ * ⌈2 * maxFactor⌉
	rounds := ell * int(math.Ceil(2*maxFactor))

	// Apply minimum rounds for security guarantee
	minRounds := 64
	if ell > 32 {
		// For larger data, ensure we have at least 2 full diffusion cycles
		minRounds = ell * 4
	}

	if rounds < minRounds {
		rounds = minRounds
	}

	// FAST requires n to be a multiple of ℓ for the security analysis
	if rounds%ell != 0 {
		rounds = ((rounds / ell) + 1) * ell
	}

	return rounds
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
