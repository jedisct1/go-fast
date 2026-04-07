package tokens_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/jedisct1/go-fast/tokens"
)

func ExampleNew() {
	key := []byte("0123456789abcdef") // AES-128
	enc, err := tokens.New(key)
	if err != nil {
		log.Fatal(err)
	}

	text := "My GitHub PAT is ghp_ABCDEFghijklmnopqrstuvwxyz0123456789 and it works."
	encrypted, err := enc.Encrypt(text)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Prefix preserved:", strings.Contains(encrypted, "ghp_"))
	fmt.Println("Context preserved:", strings.HasPrefix(encrypted, "My GitHub PAT is ghp_"))
	fmt.Println("Context preserved:", strings.HasSuffix(encrypted, " and it works."))

	decrypted, err := enc.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Round trip:", decrypted == text)

	// Output:
	// Prefix preserved: true
	// Context preserved: true
	// Context preserved: true
	// Round trip: true
}

func ExampleEncryptor_EncryptWithSpans() {
	key := []byte("0123456789abcdef")
	enc, _ := tokens.New(key)

	text := "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789"
	result, err := enc.EncryptWithSpans(text)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Spans found:", len(result.Spans))
	for _, s := range result.Spans {
		fmt.Printf("Pattern: %s, Original: %s\n", s.PatternName, s.Original)
	}

	// Output:
	// Spans found: 1
	// Pattern: github-pat, Original: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789
}

func ExampleEncryptor_Encrypt_tweak() {
	key := []byte("0123456789abcdef")
	enc, _ := tokens.New(key)

	text := "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789"
	ct1, _ := enc.Encrypt(text, tokens.WithCallTweak([]byte("prod")))
	ct2, _ := enc.Encrypt(text, tokens.WithCallTweak([]byte("staging")))

	fmt.Println("Different tweaks, different output:", ct1 != ct2)

	dec, _ := enc.Decrypt(ct1, tokens.WithCallTweak([]byte("prod")))
	fmt.Println("Correct tweak decrypts:", dec == text)

	// Output:
	// Different tweaks, different output: true
	// Correct tweak decrypts: true
}

func ExampleEncryptor_Encrypt_types() {
	key := []byte("0123456789abcdef")
	enc, _ := tokens.New(key)

	text := "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789 sk_live_abcdefghijklmnopqrstuvwx"
	encrypted, _ := enc.Encrypt(text, tokens.WithTypes("github-pat"))

	fmt.Println("Stripe key unchanged:", strings.Contains(encrypted, "sk_live_abcdefghijklmnopqrstuvwx"))

	// Output:
	// Stripe key unchanged: true
}

func ExampleEncryptor_EncryptWithMappings() {
	key := []byte("0123456789abcdef")
	enc, _ := tokens.New(key)

	body := "ABCDEFghijklmnopqrstuvwxyz0123456789"
	text := "ghp_" + body + " then ghp_" + body + " again"

	_, mappings, _ := enc.EncryptWithMappings(text)
	fmt.Println("Unique mappings:", len(mappings))
	fmt.Println("Pattern:", mappings[0].PatternName)

	// Output:
	// Unique mappings: 1
	// Pattern: github-pat
}
