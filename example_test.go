package rfc6979_test

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/kklash/rfc6979"
)

func ExampleQ_Nonce() {
	q := rfc6979.NewQ(big.NewInt(31))
	privateKey := big.NewInt(14)
	messageHash := sha256.Sum256([]byte("this is a message to sign"))

	k := q.Nonce(privateKey, messageHash[:], sha256.New)
	fmt.Println("k:", k)

	// output:
	// k: 27
}
