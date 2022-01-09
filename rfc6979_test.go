package rfc6979

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"testing"
)

func bigi(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 0)
	return n
}

type FieldFixtureJSON struct {
	Privkey  string
	Q        string
	Messages []*MessageFixtureJSON
}

type MessageFixtureJSON struct {
	Message string
	HashFn  string
	K       string
}

var fixtures []*FieldFixtureJSON

func init() {
	fixtureData, err := os.ReadFile("fixtures.json")
	if err != nil {
		panic(fmt.Sprintf("failed to read fixture data: %s", err))
	}

	if err := json.Unmarshal(fixtureData, &fixtures); err != nil {
		panic(fmt.Sprintf("failed to decode fixture data: %s", err))
	}
}

func TestRFC6979(t *testing.T) {
	for _, fieldFixture := range fixtures {
		q := NewQ(bigi(fieldFixture.Q))

		for _, messageFixture := range fieldFixture.Messages {
			var hashFn func() hash.Hash
			switch messageFixture.HashFn {
			case "SHA1":
				hashFn = sha1.New
			case "SHA224":
				hashFn = sha256.New224
			case "SHA256":
				hashFn = sha256.New
			case "SHA384":
				hashFn = sha512.New384
			case "SHA512":
				hashFn = sha512.New
			}

			hashWriter := hashFn()

			io.WriteString(hashWriter, messageFixture.Message)
			h := hashWriter.Sum(nil)
			k := q.Nonce(bigi(fieldFixture.Privkey), h, hashFn)
			expectedK := bigi(messageFixture.K)

			if k.Cmp(expectedK) != 0 {
				t.Errorf("expected k value 0x%X - Got 0x%X", k.Bytes(), expectedK.Bytes())
			}
		}
	}
}
