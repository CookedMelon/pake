package main

import (
	"crypto/elliptic"
	"math/big"
	"elliptic2"
	"fmt"
	"crypto/rand"
)
// type cc interface{
// 	polynomial(x *big.Int) *big.Int
// }
type aa interface {
	Add(x1, y1, x2, y2 *big.Int) (x3, y3 *big.Int)
	ScalarMult(x1, y1 *big.Int, k []byte) (x2, y2 *big.Int)
	ScalarBaseMult(k []byte) (x, y *big.Int)
	IsOnCurve(x, y *big.Int) bool
}
func main() {
	curve:=elliptic.P224()
	// fmt.Println(curve.IsOnCurve(X,Y))
	a:=new(elliptic2.CurveDetail)
	a.Init()
	p:=new(elliptic2.CurvePoint)
	q:=new(elliptic2.CurvePoint)
	p.X,_ = new(big.Int).SetString("6928285845320246561921755843131266604243482872721656094860805659742",10)
	p.Y,_ = new(big.Int).SetString("8854598089645493368842078308809000091133805937879389817742984611761",10)
	q.X,_ = new(big.Int).SetString("9932447698367082640257483044363349348872996515059959157560457878187",10)
	q.Y,_ = new(big.Int).SetString("8388720915886119779160748420876218981755600630586628957892069627840",10)
	k:=make([]byte, 32)
	rand.Read(k)
	k[7]=0x80
	k[30]=0x80
	// fmt.Println(a.IfOnCurve(p))
	// fmt.Println(a.Double(p))
	fmt.Println(curve.Double(p.X,p.Y))
	fmt.Println(a.Double(p))
	// fmt.Println(a.Mult(p,k))

}