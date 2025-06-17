package fast_test

import (
	"fmt"

	"github.com/jedisct1/go-fast"
)

// ExampleNewCipher demonstrates basic usage of the FAST cipher
func ExampleNewCipher() {
	// Create a new FAST cipher with a 16-byte key (AES-128)
	key := []byte("0123456789abcdef")
	cipher, err := fast.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Encrypt some data
	plaintext := []byte("Hello, World!")
	ciphertext := cipher.Encrypt(plaintext, nil)

	// Decrypt it back
	decrypted := cipher.Decrypt(ciphertext, nil)

	fmt.Printf("Original length: %d\n", len(plaintext))
	fmt.Printf("Encrypted length: %d\n", len(ciphertext))
	fmt.Printf("Decrypted matches: %t\n", string(decrypted) == string(plaintext))

	// Output:
	// Original length: 13
	// Encrypted length: 13
	// Decrypted matches: true
}

// ExampleCipher_Encrypt demonstrates encryption with tweaks
func ExampleCipher_Encrypt() {
	key := []byte("0123456789abcdef")
	cipher, _ := fast.NewCipher(key)

	data := []byte("secret message")

	// Encrypt without tweak
	ciphertext1 := cipher.Encrypt(data, nil)

	// Encrypt with tweak
	tweak := []byte("domain1")
	ciphertext2 := cipher.Encrypt(data, tweak)

	fmt.Printf("Same length preserved: %t\n", len(ciphertext1) == len(data))
	fmt.Printf("Different tweaks produce different results: %t\n",
		string(ciphertext1) != string(ciphertext2))

	// Output:
	// Same length preserved: true
	// Different tweaks produce different results: true
}

// ExampleCipher_Decrypt demonstrates decryption with tweaks
func ExampleCipher_Decrypt() {
	key := []byte("0123456789abcdef")
	cipher, _ := fast.NewCipher(key)

	data := []byte("confidential")
	tweak := []byte("production")

	// Encrypt with tweak
	ciphertext := cipher.Encrypt(data, tweak)

	// Decrypt with correct tweak
	decrypted1 := cipher.Decrypt(ciphertext, tweak)

	// Decrypt with wrong tweak
	wrongTweak := []byte("testing")
	decrypted2 := cipher.Decrypt(ciphertext, wrongTweak)

	fmt.Printf("Correct tweak works: %t\n", string(decrypted1) == string(data))
	fmt.Printf("Wrong tweak fails: %t\n", string(decrypted2) == string(data))

	// Output:
	// Correct tweak works: true
	// Wrong tweak fails: false
}
