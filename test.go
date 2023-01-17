package main

import (
	"elliptic"
	"fmt"
	"math/big"
	"crypto/rand"
)

// type cc interface{
// 	polynomial(x *big.Int) *big.Int
// }
type cd interface {
	IfOnCurve(cp*elliptic.CurvePoint) bool
	Mult(cp*elliptic.CurvePoint, k*big.Int) (ans*elliptic.CurvePoint)
	BaseMult(k*big.Int)(ans*elliptic.CurvePoint)
	Add(cp1,cp2 *elliptic.CurvePoint)(ans*elliptic.CurvePoint)
	Double(cp *elliptic.CurvePoint)(ans*elliptic.CurvePoint)
	polynomial(x *big.Int) *big.Int
	Init()
}
func main() {
	c:=new(elliptic.CurveDetail)
	c.Init()
	p:=new(elliptic.CurvePoint)
	p.X,_=new(big.Int).SetString("22028736331219291943367155846527801109411406",10)
	p.Y,_=new(big.Int).SetString("6527801109411406597894351932103802479900",10)
	bytes:=make([]byte,32)
	rand.Read(bytes)
	fmt.Println(c.BaseMult(bytes))
}