package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
)
type Point struct {
	X, Y *big.Int
}
type EllipticCurve interface {
	Add(x1, y1, x2, y2 *big.Int) (x3, y3 *big.Int)
	ScalarMult(x1, y1 *big.Int, k []byte) (x2, y2 *big.Int)
	ScalarBaseMult(k []byte) (x, y *big.Int)
	IsOnCurve(x, y *big.Int) bool
}
type MyPake struct {
	//Public
	character int//0 for Alice, 1 for Bob
	PubKey1,PubKey2 Point//椭圆曲线上两点
	//Private
	curve   EllipticCurve
	mod    *big.Int//椭圆曲线的阶
	pw      string//pin码
	RandInt []byte//随机数
	SendP,RecvP Point
	w	  Point//g^ab
	Session_key []byte//会话密钥
}
func (p*MyPake)initPake(cha int,pw string) (err error) {
	p.character=cha
	p.pw=pw
	p.curve=elliptic.P256()
	p.mod=elliptic.P256().Params().P
	p.RandInt=make([]byte,32)
	_,err=rand.Read(p.RandInt)
	if err!=nil{
		err=fmt.Errorf("rand.Read failed:%v",err)
		return
	}
	p.PubKey1.X,_=new(big.Int).SetString("58731067273573857778279948794057417392601156383472860786093400685735140761651",0)
	p.PubKey1.Y,_=new(big.Int).SetString("93386138870050199662691817665795322475134119398187949273982911861062556881179",0)
	if p.curve.IsOnCurve(p.PubKey1.X,p.PubKey1.Y)==false{
		err=fmt.Errorf("PubKey1 is not on curve")
		return
	}
	p.PubKey2.X,_=new(big.Int).SetString("103420669720391795230273066371051314480768113876393771228169739831565483091666",0)
	p.PubKey2.Y,_=new(big.Int).SetString("55370253487829929306938359725045466094283998540384556311325748840724747949635",0)
	if p.curve.IsOnCurve(p.PubKey2.X,p.PubKey2.Y)==false{
		err=fmt.Errorf("PubKey2 is not on curve")
		return
	}
	return
}
func GetPakes(pw string)(p1,p2 *MyPake,err error) {
	p1=new(MyPake)
	p2=new(MyPake)
	err=p1.initPake(0,pw)
	if err!=nil{
		return
	}
	err=p2.initPake(1,pw)
	if err!=nil{
		return
	}
	bytes:=make([]byte,32)
	rand.Read(bytes)
	
	return
}
func (p*MyPake)UpdateSelf()(err error){
	var temp1,temp2,PublicKey Point
	if p.character!=0{
		PublicKey.X=p.PubKey1.X
		PublicKey.Y=p.PubKey1.Y
	}else{
		PublicKey.X=p.PubKey2.X
		PublicKey.Y=p.PubKey2.Y
	}

	temp1.X,temp1.Y=p.curve.ScalarMult(PublicKey.X,PublicKey.Y,[]byte(p.pw))
	temp2.X,temp2.Y=p.curve.ScalarBaseMult(p.RandInt)
	p.SendP.X,p.SendP.Y=p.curve.Add(temp1.X,temp1.Y,temp2.X,temp2.Y)
	return 
}
func (p*MyPake)UpdateOther(bytes []byte)(err error){
	var qSend *Point
	err=json.Unmarshal(bytes,&qSend)
	if err!=nil{
		err=fmt.Errorf("json.Unmarshal failed:%v",err)
		return
	}
	p.RecvP.X=qSend.X
	p.RecvP.Y=qSend.Y
	if p.curve.IsOnCurve(p.RecvP.X,p.RecvP.Y)==false{
		err=fmt.Errorf("RecvP is not on curve")
		return
	}
	var PubKey Point
	if p.character==0{
		PubKey.X=p.PubKey1.X
		PubKey.Y=p.PubKey1.Y
	}else{
		PubKey.X=p.PubKey2.X
		PubKey.Y=p.PubKey2.Y
	}	
	var temp1,temp2,temp3 Point
	temp1.X=qSend.X
	temp1.Y=new(big.Int).Mod(new(big.Int).Neg(qSend.Y),p.mod)
	temp2.X,temp2.Y=p.curve.ScalarMult(PubKey.X,PubKey.Y,[]byte(p.pw))
	temp3.X,temp3.Y=p.curve.Add(temp2.X,temp2.Y,temp1.X,temp1.Y)
	p.w.X,p.w.Y=p.curve.ScalarMult(temp3.X,temp3.Y,p.RandInt)
	
	Session:=sha256.New()
	Session.Write(p.PubKey1.X.Bytes())
	Session.Write(p.PubKey1.Y.Bytes())
	Session.Write(p.PubKey2.X.Bytes())
	Session.Write(p.PubKey2.Y.Bytes())
	Session.Write(p.w.X.Bytes())
	Session.Write(p.w.Y.Bytes())
	Session.Write([]byte(p.pw))
	p.Session_key=Session.Sum(nil)
	return 
}
func main(){
	p1,p2,_:=GetPakes("123456")
	err:=p1.UpdateSelf()
	if err!=nil{
		fmt.Println(err)
		return
	}
	err=p2.UpdateSelf()
	if err!=nil{
		fmt.Println(err)
		return
	}
	bytes,_:=json.Marshal(p1.SendP)
	err=p2.UpdateOther(bytes)
	if err!=nil{
		fmt.Println(err)
		return
	}
	bytes,err=json.Marshal(p2.SendP)
	fmt.Println(err)
	err=p1.UpdateOther(bytes)
	if err!=nil{
		fmt.Println(err)
		return
	}
	if p1.w.X.Cmp(p2.w.X)==0{
		fmt.Println("success")
	}else{
		fmt.Println("fail")
	}
	fmt.Println("p1密钥",p1.Session_key)
	fmt.Println("p2密钥",p2.Session_key)
	return
}