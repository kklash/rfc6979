# RFC6979

This package implements [RFC6979](https://datatracker.ietf.org/doc/html/rfc6979), titled:

> Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)

This RFC provides a way to make digital signatures deterministic instead of random. In the traditional DSA or ECDSA protocols, crafting signatures would involve selecting a random nonce value, called `k`. If selection of `k` is not perfectly random, then _"slight biases in that process may be turned into attacks on the signature schemes."_

RFC6979 specifies a procedure for generating `k` values deterministically, while still providing perfectly uniform distribution (apparent randomness). The `k` values are determined by four factors:

- The finite field order, `q` ('order' means the number of numbers in the finite field). This is usually some very large constant value.
- The private key being used to sign
- The hash of the message which the caller wants to sign
- The hash algorithm used to hash the message

This package provides a Golang implementation of the specification which passes all [test vectors](./fixtures.json) included in the RFC document.

## Usage

To add this package to your Go module:

```
go get github.com/kklash/rfc6979
```

First instantiate a `Q` struct using the order of your finite field, and call its `Nonce` method to generate `k` values when signing data.

```go
package main

import "github.com/kklash/rfc6979"

func main() {
  q := rfc6979.NewQ(big.NewInt(31))
  privateKey := big.NewInt(14)
  messageHash := sha256.Sum256([]byte("this is a message to sign"))

  k := q.Nonce(privateKey, messageHash[:], sha256.New)
  fmt.Println(k) // 27
}
```

## Contributing

Tests can be run with

```
go test
```

To run benchmarks as well:

```
go test -bench=.
```
