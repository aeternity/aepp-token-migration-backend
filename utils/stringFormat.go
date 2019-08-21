package utils

import "fmt"

// PreHashFormat prepare string format before hashing
func PreHashFormat(address string, amount string) string {
	return fmt.Sprintf("%s:%s", address, amount)
}
