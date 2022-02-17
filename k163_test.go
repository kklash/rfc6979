package rfc6979

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"testing"
)

// This tests the worked-out example from RFC6979's appendix:
//
// https://datatracker.ietf.org/doc/html/rfc6979#appendix-A.1
func TestK163Example(t *testing.T) {
	q := NewQ(bigi("0x4000000000000000000020108A2E0CC0D99F8A5EF"))
	if q.qlen != 163 {
		t.Errorf("Expected to receive qlen = 163")
		return
	}

	privkey := bigi("0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F")
	hashFn := sha256.New
	hashWriter := hashFn()
	io.WriteString(hashWriter, "sample")
	h := hashWriter.Sum(nil)

	t.Run("int2octets", func(t *testing.T) {
		actual := fmt.Sprintf("% X", q.int2octets(privkey))
		expected := "00 9A 4D 67 92 29 5A 7F 73 0F C3 F2 B4 9C BC 0F 62 E8 62 27 2F"

		if actual != expected {
			t.Errorf("int2octets failed to convert private key\nWanted %s\nGot    %s", expected, actual)
		}
	})

	t.Run("bits2octets", func(t *testing.T) {
		actual := fmt.Sprintf("% X", q.bits2octets(h))
		expected := "01 79 5E DF 0D 54 DB 76 0F 15 6D 0D AC 04 C0 32 2B 3A 20 42 24"

		if actual != expected {
			t.Errorf("bits2octets failed to convert hash\nWanted %s\nGot    %s", expected, actual)
		}
	})

	t.Run("nonce generation", func(t *testing.T) {
		k := q.Nonce(privkey, h, hashFn)

		actual := fmt.Sprintf("0x%X", k.Bytes())
		expected := "0x023AF4074C90A02B3FE61D286D5C87F425E6BDD81B"

		if actual != expected {
			t.Errorf("q.Nonce failed to derive expected nonce\nWanted %s\nGot    %s", expected, actual)
		}
	})
}

func bigi(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 0)
	return n
}
