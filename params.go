package fast

// Params holds the FAST cipher parameters for a specific radix and word length.
// Use CalculateRecommendedParams to compute these from a radix and word length,
// or construct manually for advanced use cases.
type Params struct {
	Radix       int
	WordLength  int
	SBoxCount   int
	NumLayers   int
	BranchDist1 int
	BranchDist2 int
}

// CalculateRecommendedParams computes recommended FAST parameters for the given
// radix and word length using the lookup tables from the FAST specification.
// Radix must be in [2, 256] and wordLength must be >= 2.
func CalculateRecommendedParams(radix, wordLength int) (Params, error) {
	if radix < 2 || radix > 256 {
		return Params{}, ErrInvalidRadix
	}
	if wordLength < 2 {
		return Params{}, ErrInvalidWordLength
	}

	w, wPrime := branchDistances(wordLength)

	return Params{
		Radix:       radix,
		WordLength:  wordLength,
		SBoxCount:   256,
		NumLayers:   computeNumLayers(radix, wordLength),
		BranchDist1: w,
		BranchDist2: wPrime,
	}, nil
}
