package rfc6979

import (
	"crypto/sha256"
	"testing"
)

func BenchmarkNonceECDSA256(b *testing.B) {
	fieldFixture := fixtures[4] // ECDSA 256-bit
	q := NewQ(bigi(fieldFixture.Q))
	hashed := sha256.Sum256([]byte("whatever"))
	privKey := bigi(fieldFixture.Privkey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.Nonce(privKey, hashed[:], sha256.New)
	}
}
