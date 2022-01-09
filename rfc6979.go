// Package rfc6979 generates deterministic nonce values for digital signatures.
package rfc6979

import (
	"crypto/hmac"
	"hash"
	"math/big"
)

var bigOne = big.NewInt(1)

func computeHMAC(hashFn func() hash.Hash, key, message []byte) []byte {
	h := hmac.New(hashFn, key)
	h.Write(message)
	return h.Sum(nil)
}

func fillBytes(b byte, n int) []byte {
	data := make([]byte, n)
	for i := 0; i < n; i++ {
		data[i] = b
	}
	return data
}

// Q represents a finite field order Q.
type Q struct {
	q    *big.Int
	qlen int
	rlen int
}

func NewQ(q *big.Int) *Q {
	qlen := q.BitLen()
	return &Q{
		q:    q,
		qlen: qlen,
		rlen: (qlen + 7) / 8 * 8,
	}
}

func (q *Q) submod(x *big.Int) *big.Int {
	n := new(big.Int).Sub(x, q.q)
	if n.Sign() < 0 {
		return x
	}
	return n
}

func (q *Q) bits2int(bits []byte) *big.Int {
	n := new(big.Int).SetBytes(bits)
	blen := len(bits) * 8
	if q.qlen < blen {
		n.Rsh(n, uint(blen-q.qlen))
	}
	return n
}

// x should be less than q
func (q *Q) int2octets(x *big.Int) []byte {
	bytes := x.Bytes()
	output := make([]byte, q.rlen/8)
	cutoff := len(output) - len(bytes)
	copy(output[cutoff:], bytes)
	return output
}

func (q *Q) bits2octets(bits []byte) []byte {
	z1 := q.bits2int(bits)
	z1 = q.submod(z1)
	return q.int2octets(z1)
}

// Nonce calculates a deterministic value for K, to be used for digitally signing the given hash h1.
func (q *Q) Nonce(privkey *big.Int, h1 []byte, hashFn func() hash.Hash) *big.Int {
	hlen := len(h1)
	if hlen != hashFn().Size() {
		panic("must use same hashFn for rfc6979 as was used to hash message for signing")
	}

	if privkey.Cmp(q.q) >= 0 {
		panic("private key is larger than Q")
	}

	v := fillBytes(0x01, hlen)
	k := make([]byte, hlen)

	keyPlusHash := append(q.int2octets(privkey), q.bits2octets(h1)...)

	k = computeHMAC(hashFn, k, append(append(v, 0x00), keyPlusHash...))

	v = computeHMAC(hashFn, k, v)

	k = computeHMAC(hashFn, k, append(append(v, 0x01), keyPlusHash...))

	v = computeHMAC(hashFn, k, v)

	for {
		var t []byte
		for len(t)*8 < q.qlen {
			v = computeHMAC(hashFn, k, v)
			t = append(t, v...)
		}

		nonce := q.bits2int(t)
		if nonce.Cmp(bigOne) >= 0 && nonce.Cmp(q.q) < 0 {
			return nonce
		}
		k = computeHMAC(hashFn, k, append(v, 0x00))
		v = computeHMAC(hashFn, k, v)
	}
}
