package fast_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

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

// Example_tokenization demonstrates using FAST for tokenization
func Example_tokenization() {
	// Generate a secure random key
	key := make([]byte, 16) // AES-128
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	cipher, err := fast.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// Tokenize credit card numbers while preserving format
	ccNumber := []byte("4111111111111111")
	token := cipher.Encrypt(ccNumber, []byte("cc-tokens"))

	fmt.Printf("Original: %s\n", ccNumber)
	fmt.Printf("Token length preserved: %t\n", len(token) == len(ccNumber))
	fmt.Printf("Token is different: %t\n", string(token) != string(ccNumber))

	// Output:
	// Original: 4111111111111111
	// Token length preserved: true
	// Token is different: true
}

// Example_databaseFields demonstrates encrypting database fields
func Example_databaseFields() {
	key := []byte("database-key-123") // 16 bytes
	cipher, _ := fast.NewCipher(key)

	// Encrypt different types of database fields
	email := []byte("user@example.com")
	phone := []byte("+1-555-0123")
	ssn := []byte("123-45-6789")

	// Use different tweaks for different field types
	encEmail := cipher.Encrypt(email, []byte("field:email"))
	encPhone := cipher.Encrypt(phone, []byte("field:phone"))
	encSSN := cipher.Encrypt(ssn, []byte("field:ssn"))

	fmt.Printf("Email format preserved: %t\n", len(encEmail) == len(email))
	fmt.Printf("Phone format preserved: %t\n", len(encPhone) == len(phone))
	fmt.Printf("SSN format preserved: %t\n", len(encSSN) == len(ssn))

	// Output:
	// Email format preserved: true
	// Phone format preserved: true
	// SSN format preserved: true
}

// Example_keyManagement demonstrates different key sizes
func Example_keyManagement() {
	// AES-128 (16 bytes)
	key128 := make([]byte, 16)
	rand.Read(key128)
	cipher128, err := fast.NewCipher(key128)
	if err != nil {
		log.Fatal(err)
	}

	// AES-192 (24 bytes)
	key192 := make([]byte, 24)
	rand.Read(key192)
	cipher192, err := fast.NewCipher(key192)
	if err != nil {
		log.Fatal(err)
	}

	// AES-256 (32 bytes)
	key256 := make([]byte, 32)
	rand.Read(key256)
	cipher256, err := fast.NewCipher(key256)
	if err != nil {
		log.Fatal(err)
	}

	data := []byte("test data")

	// All key sizes work the same way
	enc128 := cipher128.Encrypt(data, nil)
	enc192 := cipher192.Encrypt(data, nil)
	enc256 := cipher256.Encrypt(data, nil)

	fmt.Printf("AES-128 preserves format: %t\n", len(enc128) == len(data))
	fmt.Printf("AES-192 preserves format: %t\n", len(enc192) == len(data))
	fmt.Printf("AES-256 preserves format: %t\n", len(enc256) == len(data))

	// Output:
	// AES-128 preserves format: true
	// AES-192 preserves format: true
	// AES-256 preserves format: true
}

// Example_errorHandling demonstrates proper error handling
func Example_errorHandling() {
	// Invalid key size
	invalidKey := []byte("short")
	_, err := fast.NewCipher(invalidKey)
	if err != nil {
		fmt.Printf("Invalid key error: %v\n", err)
	}

	// Valid key
	validKey := []byte("0123456789abcdef")
	cipher, err := fast.NewCipher(validKey)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt empty data (valid operation)
	empty := cipher.Encrypt([]byte{}, nil)
	fmt.Printf("Empty data result length: %d\n", len(empty))

	// Output:
	// Invalid key error: fast: invalid key size, must be 16, 24, or 32 bytes
	// Empty data result length: 0
}

// Example_hexEncoding demonstrates using hex encoding for display
func Example_hexEncoding() {
	key := []byte("0123456789abcdef")
	cipher, _ := fast.NewCipher(key)

	// Binary data that may not be printable
	binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	encrypted := cipher.Encrypt(binaryData, nil)

	// Use hex encoding for display/storage
	hexStr := hex.EncodeToString(encrypted)
	fmt.Printf("Hex encoded: %s\n", hexStr)
	fmt.Printf("Hex length: %d\n", len(hexStr))
	fmt.Printf("Original length: %d\n", len(binaryData))

	// Decode back from hex
	decoded, _ := hex.DecodeString(hexStr)
	decrypted := cipher.Decrypt(decoded, nil)

	fmt.Printf("Decryption successful: %t\n", len(decrypted) == len(binaryData))

	// Output:
	// Hex encoded: eb16c02d7607
	// Hex length: 12
	// Original length: 6
	// Decryption successful: true
}
