package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

func main() {
	curve := elliptic.P256()
	by:=make([]byte, 32) // randomly generated secret
	rand.Read(by)
	fmt.Println(curve.ScalarBaseMult(by))
}