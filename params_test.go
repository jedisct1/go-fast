package fast

import (
	"bytes"
	"testing"
)

func TestCalculateRecommendedParams(t *testing.T) {
	tests := []struct {
		name    string
		radix   int
		wordLen int
		wantErr bool
		wantW   int
		wantWP  int
		wantNL  int
	}{
		{"radix_10_len_16", 10, 16, false, 4, 3, 592},
		{"radix_36_len_36", 36, 36, false, 6, 5, 1224},
		{"radix_62_len_20", 62, 20, false, 5, 4, 580},
		{"radix_64_len_32", 64, 32, false, 6, 5, 1024},
		{"radix_256_len_16", 256, 16, false, 4, 3, 400},
		{"radix_too_low", 1, 16, true, 0, 0, 0},
		{"radix_too_high", 257, 16, true, 0, 0, 0},
		{"wordlen_too_low", 10, 1, true, 0, 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := CalculateRecommendedParams(tc.radix, tc.wordLen)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.BranchDist1 != tc.wantW {
				t.Errorf("BranchDist1: got %d, want %d", p.BranchDist1, tc.wantW)
			}
			if p.BranchDist2 != tc.wantWP {
				t.Errorf("BranchDist2: got %d, want %d", p.BranchDist2, tc.wantWP)
			}
			if p.NumLayers != tc.wantNL {
				t.Errorf("NumLayers: got %d, want %d", p.NumLayers, tc.wantNL)
			}
			if p.SBoxCount != 256 {
				t.Errorf("SBoxCount: got %d, want 256", p.SBoxCount)
			}
		})
	}
}

func TestNewCipherFromParams(t *testing.T) {
	key := []byte("0123456789abcdef")

	t.Run("valid_construction", func(t *testing.T) {
		params, err := CalculateRecommendedParams(62, 20)
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewCipherFromParams(params, key)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			t.Fatal("cipher is nil")
		}
	})

	t.Run("invalid_key_size", func(t *testing.T) {
		params, _ := CalculateRecommendedParams(62, 20)
		_, err := NewCipherFromParams(params, []byte("short"))
		if err != ErrInvalidKeySize {
			t.Fatalf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("invalid_radix", func(t *testing.T) {
		_, err := NewCipherFromParams(Params{Radix: 0, WordLength: 10, SBoxCount: 256, NumLayers: 100, BranchDist1: 3, BranchDist2: 2}, key)
		if err != ErrInvalidRadix {
			t.Fatalf("expected ErrInvalidRadix, got %v", err)
		}
	})

	t.Run("wrong_data_length_returns_nil", func(t *testing.T) {
		params, _ := CalculateRecommendedParams(62, 20)
		c, _ := NewCipherFromParams(params, key)
		result := c.Encrypt([]byte{1, 2, 3}, nil) // wrong length
		if result != nil {
			t.Fatal("expected nil for wrong data length")
		}
	})
}

func TestParamsCipherRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")

	tests := []struct {
		name    string
		radix   int
		wordLen int
		data    []byte
		tweak   []byte
	}{
		{"radix10_digits", 10, 16, []byte{4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, nil},
		{"radix10_with_tweak", 10, 16, []byte{4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("credit-card")},
		{"radix16_hex", 16, 32, func() []byte {
			d := make([]byte, 32)
			for i := range d {
				d[i] = byte(i % 16)
			}
			return d
		}(), nil},
		{"radix36_upper", 36, 36, func() []byte {
			d := make([]byte, 36)
			for i := range d {
				d[i] = byte(i)
			}
			return d
		}(), nil},
		{"radix62_alphanumeric", 62, 20, func() []byte {
			d := make([]byte, 20)
			for i := range d {
				d[i] = byte(i)
			}
			return d
		}(), []byte("github-pat")},
		{"radix64_base64url", 64, 32, make([]byte, 32), []byte("fastly")},
		{"radix64_all_max", 64, 32, func() []byte {
			d := make([]byte, 32)
			for i := range d {
				d[i] = 63
			}
			return d
		}(), nil},
		{"radix4_small", 4, 8, []byte{0, 1, 2, 3, 0, 1, 2, 3}, nil},
		{"radix2_binary", 2, 16, []byte{0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0}, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params, err := CalculateRecommendedParams(tc.radix, tc.wordLen)
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCipherFromParams(params, key)
			if err != nil {
				t.Fatal(err)
			}

			encrypted := c.Encrypt(tc.data, tc.tweak)
			if encrypted == nil {
				t.Fatal("encryption returned nil")
			}
			if len(encrypted) != len(tc.data) {
				t.Fatalf("length mismatch: got %d, want %d", len(encrypted), len(tc.data))
			}
			if bytes.Equal(encrypted, tc.data) {
				t.Error("encryption did not change the data")
			}

			// Verify all values in [0, radix)
			for i, v := range encrypted {
				if int(v) >= tc.radix {
					t.Errorf("encrypted[%d] = %d, exceeds radix %d", i, v, tc.radix)
				}
			}

			decrypted := c.Decrypt(encrypted, tc.tweak)
			if !bytes.Equal(decrypted, tc.data) {
				t.Errorf("roundtrip failed: got %v, want %v", decrypted, tc.data)
			}
		})
	}
}

func TestParamsCipherDeterministic(t *testing.T) {
	key := []byte("0123456789abcdef")
	params, _ := CalculateRecommendedParams(62, 20)
	c, _ := NewCipherFromParams(params, key)

	data := make([]byte, 20)
	for i := range data {
		data[i] = byte(i)
	}
	tweak := []byte("test-tweak")

	enc1 := c.Encrypt(data, tweak)
	enc2 := c.Encrypt(data, tweak)
	enc3 := c.Encrypt(data, tweak)

	if !bytes.Equal(enc1, enc2) || !bytes.Equal(enc2, enc3) {
		t.Error("encryption is not deterministic")
	}
}

func TestParamsCipherTweakSensitivity(t *testing.T) {
	key := []byte("0123456789abcdef")
	params, _ := CalculateRecommendedParams(10, 16)
	c, _ := NewCipherFromParams(params, key)

	data := []byte{4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	enc1 := c.Encrypt(data, nil)
	enc2 := c.Encrypt(data, []byte("tweak1"))
	enc3 := c.Encrypt(data, []byte("tweak2"))

	if bytes.Equal(enc1, enc2) {
		t.Error("nil tweak and tweak1 produced same result")
	}
	if bytes.Equal(enc2, enc3) {
		t.Error("tweak1 and tweak2 produced same result")
	}

	// Wrong tweak must not decrypt correctly
	dec := c.Decrypt(enc2, []byte("wrong-tweak"))
	if bytes.Equal(dec, data) {
		t.Error("decryption succeeded with wrong tweak")
	}
}

func TestNewCipherFromParamsRejectsInvalidParams(t *testing.T) {
	key := []byte("0123456789abcdef")

	tests := []struct {
		name   string
		params Params
	}{
		{"branch_dist1_exceeds_wordlen", Params{Radix: 10, WordLength: 4, SBoxCount: 256, NumLayers: 148, BranchDist1: 5, BranchDist2: 1}},
		{"branch_dist2_exceeds_wordlen", Params{Radix: 10, WordLength: 4, SBoxCount: 256, NumLayers: 148, BranchDist1: 2, BranchDist2: 5}},
		{"branch_dist2_zero", Params{Radix: 10, WordLength: 4, SBoxCount: 256, NumLayers: 148, BranchDist1: 2, BranchDist2: 0}},
		{"branch_dist1_negative", Params{Radix: 10, WordLength: 4, SBoxCount: 256, NumLayers: 148, BranchDist1: -1, BranchDist2: 1}},
		{"num_layers_not_multiple_of_wordlen", Params{Radix: 10, WordLength: 4, SBoxCount: 256, NumLayers: 149, BranchDist1: 2, BranchDist2: 1}},
		{"zero_sbox_count", Params{Radix: 10, WordLength: 4, SBoxCount: 0, NumLayers: 148, BranchDist1: 2, BranchDist2: 1}},
		{"zero_num_layers", Params{Radix: 10, WordLength: 4, SBoxCount: 256, NumLayers: 0, BranchDist1: 2, BranchDist2: 1}},
		{"wordlen_one", Params{Radix: 10, WordLength: 1, SBoxCount: 256, NumLayers: 10, BranchDist1: 0, BranchDist2: 1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCipherFromParams(tc.params, key)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParamsCipherRejectsOutOfRangeSymbols(t *testing.T) {
	key := []byte("0123456789abcdef")
	params, _ := CalculateRecommendedParams(10, 16)
	c, _ := NewCipherFromParams(params, key)

	// Value 10 is out of range for radix 10
	bad := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 4}
	if result := c.Encrypt(bad, nil); result != nil {
		t.Error("Encrypt should return nil for out-of-range symbol")
	}
	if result := c.Decrypt(bad, nil); result != nil {
		t.Error("Decrypt should return nil for out-of-range symbol")
	}

	// Value 255 is out of range for radix 10
	bad2 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 0, 1, 2, 3, 4}
	if result := c.Encrypt(bad2, nil); result != nil {
		t.Error("Encrypt should return nil for value 255 in radix 10")
	}

	// All valid values should work
	good := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}
	if result := c.Encrypt(good, nil); result == nil {
		t.Error("Encrypt should succeed for valid symbols")
	}
}

func TestParamsCipherRadix256AcceptsAllBytes(t *testing.T) {
	key := []byte("0123456789abcdef")
	params, _ := CalculateRecommendedParams(256, 16)
	c, _ := NewCipherFromParams(params, key)

	// All byte values should be valid for radix 256
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i * 17) // 0, 17, 34, ... 255
	}
	enc := c.Encrypt(data, nil)
	if enc == nil {
		t.Fatal("Encrypt returned nil for valid radix-256 data")
	}
	dec := c.Decrypt(enc, nil)
	if !bytes.Equal(dec, data) {
		t.Error("roundtrip failed for radix-256 parameterized cipher")
	}
}

func TestCrossLanguageParity(t *testing.T) {
	key := []byte("0123456789abcdef")

	tests := []struct {
		name    string
		radix   int
		wordLen int
		data    []byte
		tweak   []byte
		want    []byte
	}{
		{"radix10_cc_no_tweak", 10, 16, []byte{4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, nil, []byte{1, 8, 0, 1, 0, 6, 2, 7, 7, 6, 6, 1, 4, 0, 8, 6}},
		{"radix10_cc_tweak", 10, 16, []byte{4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, []byte("credit-card"), []byte{9, 3, 2, 2, 5, 8, 8, 5, 8, 4, 8, 4, 4, 9, 9, 3}},
		{"radix10_zeros", 10, 16, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil, []byte{0, 8, 0, 8, 7, 8, 0, 8, 5, 2, 2, 1, 3, 3, 9, 0}},
		{"radix10_nines", 10, 16, []byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}, nil, []byte{3, 4, 2, 7, 1, 8, 3, 7, 5, 5, 7, 1, 1, 0, 8, 8}},
		{"radix16_sequential", 16, 32, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, nil, []byte{6, 14, 10, 0, 7, 9, 2, 10, 9, 1, 4, 3, 12, 13, 13, 3, 15, 2, 10, 7, 15, 11, 6, 5, 1, 15, 8, 5, 10, 11, 12, 7}},
		{"radix16_sequential_tweak", 16, 32, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte("hex-tweak"), []byte{15, 10, 0, 3, 0, 14, 0, 3, 9, 0, 14, 3, 8, 9, 15, 1, 4, 2, 6, 6, 1, 6, 9, 10, 11, 14, 14, 12, 6, 10, 0, 15}},
		{"radix36_identity", 36, 36, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35}, nil, []byte{28, 16, 21, 3, 0, 1, 4, 15, 0, 21, 34, 11, 2, 4, 26, 20, 30, 28, 31, 6, 4, 35, 19, 10, 27, 19, 7, 0, 12, 10, 5, 25, 27, 6, 32, 34}},
		{"radix36_tweak", 36, 36, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35}, []byte("github-pat"), []byte{13, 4, 33, 14, 34, 5, 12, 22, 21, 22, 23, 16, 3, 35, 9, 26, 16, 1, 18, 22, 25, 13, 35, 9, 21, 14, 32, 6, 19, 8, 13, 35, 11, 17, 29, 27}},
		{"radix62_ghpat", 62, 20, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}, []byte("github-pat"), []byte{5, 31, 8, 12, 10, 47, 37, 58, 52, 12, 59, 0, 41, 23, 36, 60, 57, 9, 33, 5}},
		{"radix62_openai", 62, 48, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47}, []byte("openai"), []byte{48, 11, 44, 16, 0, 44, 12, 61, 18, 41, 37, 31, 18, 58, 35, 2, 16, 24, 47, 53, 21, 23, 1, 0, 18, 51, 42, 30, 39, 51, 30, 23, 54, 54, 45, 55, 12, 4, 10, 6, 51, 45, 15, 51, 5, 36, 0, 37}},
		{"radix62_zeros", 62, 36, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil, []byte{58, 49, 6, 25, 46, 34, 54, 23, 10, 53, 30, 8, 49, 0, 43, 19, 52, 21, 27, 33, 33, 49, 21, 33, 14, 28, 60, 24, 2, 28, 49, 4, 42, 17, 41, 35}},
		{"radix62_max", 62, 36, []byte{61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61}, nil, []byte{35, 3, 55, 8, 55, 0, 33, 55, 39, 46, 60, 2, 14, 29, 24, 23, 7, 21, 15, 10, 41, 2, 27, 45, 42, 55, 2, 13, 24, 49, 58, 32, 24, 11, 23, 3}},
		{"radix64_fastly", 64, 32, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte("fastly"), []byte{54, 46, 10, 57, 24, 5, 45, 39, 23, 41, 2, 15, 22, 34, 5, 46, 55, 43, 28, 58, 50, 37, 47, 43, 1, 27, 35, 32, 16, 56, 54, 34}},
		{"radix64_anthropic", 64, 80, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte("anthropic"), []byte{49, 62, 50, 39, 40, 55, 22, 24, 49, 7, 0, 57, 44, 18, 42, 12, 22, 11, 35, 27, 56, 18, 46, 8, 15, 48, 26, 44, 34, 55, 20, 15, 14, 46, 55, 63, 46, 7, 15, 6, 37, 51, 18, 55, 47, 29, 9, 14, 49, 51, 50, 27, 53, 46, 31, 33, 11, 35, 24, 35, 22, 2, 18, 6, 51, 0, 59, 35, 22, 34, 22, 49, 1, 49, 5, 39, 2, 14, 22, 25}},
		{"radix64_sendgrid", 64, 22, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}, []byte("sendgrid"), []byte{8, 63, 13, 37, 62, 57, 32, 34, 58, 6, 50, 0, 20, 29, 39, 46, 10, 38, 58, 17, 9, 45}},
		{"radix64_sendgrid43", 64, 43, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42}, []byte("sendgrid"), []byte{26, 3, 52, 35, 14, 6, 49, 12, 6, 56, 32, 14, 41, 28, 15, 26, 5, 55, 42, 26, 12, 39, 14, 4, 1, 31, 48, 40, 14, 57, 61, 19, 10, 6, 24, 62, 14, 54, 43, 47, 46, 19, 21}},
		{"radix256_sequential", 256, 16, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, nil, []byte{165, 207, 156, 159, 109, 253, 135, 241, 21, 51, 49, 131, 233, 26, 6, 97}},
		{"radix256_tweak", 256, 16, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte("test-tweak"), []byte{226, 118, 124, 188, 145, 136, 5, 229, 230, 50, 20, 163, 75, 148, 1, 229}},
		{"radix256_zeros32", 256, 32, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil, []byte{234, 80, 155, 34, 137, 48, 0, 241, 152, 47, 106, 45, 122, 205, 91, 51, 148, 138, 239, 111, 133, 131, 47, 52, 144, 134, 198, 114, 55, 24, 58, 48}},
		{"radix10_len2", 10, 2, []byte{3, 7}, nil, []byte{9, 0}},
		{"radix62_len2_tweak", 62, 2, []byte{0, 61}, []byte("edge"), []byte{21, 26}},
		{"radix64_len3", 64, 3, []byte{0, 32, 63}, nil, []byte{51, 46, 54}},
		{"radix10_empty_tweak", 10, 16, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}, nil, []byte{6, 5, 9, 9, 9, 9, 8, 0, 2, 8, 0, 7, 7, 0, 7, 7}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params, err := CalculateRecommendedParams(tc.radix, tc.wordLen)
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCipherFromParams(params, key)
			if err != nil {
				t.Fatal(err)
			}

			got := c.Encrypt(tc.data, tc.tweak)
			if !bytes.Equal(got, tc.want) {
				t.Errorf("ciphertext mismatch:\n  got:  %v\n  want: %v", got, tc.want)
			}

			dec := c.Decrypt(got, tc.tweak)
			if !bytes.Equal(dec, tc.data) {
				t.Errorf("roundtrip failed:\n  got:  %v\n  want: %v", dec, tc.data)
			}
		})
	}
}
