package main

import (
	"crypto/elliptic"

	"fmt"
	"math/big"
)
type aa interface {
	Add(x1, y1, x2, y2 *big.Int) (x3, y3 *big.Int)
	ScalarMult(x1, y1 *big.Int, k []byte) (x2, y2 *big.Int)
	ScalarBaseMult(k []byte) (x, y *big.Int)
	IsOnCurve(x, y *big.Int) bool
}
func main() {
	curve:=elliptic.P224()
	X:=curve.Params().Gx
	Y:=curve.Params().Gy
	// fmt.Println(curve.IsOnCurve(X,Y))
	fmt.Println(curve.Add(X,Y,X,Y))
	x:=make([]byte, 32)
	x[0]=0x80
	x[1]=0x2f
	x[2]=0xe4
	x[3]=0xa3
	x[4]=0x09
	x[5]=0x66
	fmt.Println(curve.ScalarBaseMult(x))
}