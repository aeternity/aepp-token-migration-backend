package crypto

import (
	// "fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/blake2b"
	"encoding/hex"
)

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256 (data string) string{
	hash := crypto.Keccak256Hash([]byte(data))

	return string(hash.Hex())
}

// Blake2b calculates and returns the Blake2b hash of the input data.
func Blake2b (data string) string {
	hash := blake2b.Sum256([]byte(data))

	return hex.EncodeToString(hash[:])
}