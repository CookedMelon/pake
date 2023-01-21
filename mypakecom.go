package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/CookedMelon/pake/src/aes"
	"github.com/CookedMelon/pake/src/elliptic"
)

type cd interface {
	IfOnCurve(cp*elliptic.CurvePoint) bool
	Mult(cp*elliptic.CurvePoint, k*big.Int) (ans*elliptic.CurvePoint)
	BaseMult(k*big.Int)(ans*elliptic.CurvePoint)
	Add(cp1,cp2 *elliptic.CurvePoint)(ans*elliptic.CurvePoint)
	Double(cp *elliptic.CurvePoint)(ans*elliptic.CurvePoint)
	polynomial(x *big.Int) *big.Int
	Init()
}

type MyPake struct {
	//Public
	character int//0 for Alice, 1 for Bob
	PubKey1,PubKey2 *elliptic.CurvePoint//椭圆曲线上两点
	//Private
	curve   *elliptic.CurveDetail
	mod    *big.Int//椭圆曲线的阶
	pw      string//pin码
	RandInt []byte//随机数
	SendP,RecvP *elliptic.CurvePoint
	w	  *elliptic.CurvePoint//g^ab
	KeyPack []byte//密钥包
	Session_key []byte//会话密钥
}
func (p*MyPake)initPake(cha int,pw string) (err error) {
	p.character=cha
	p.pw=pw
	p.curve=new(elliptic.CurveDetail)
	p.curve.Init()
	p.mod=new(big.Int).Set(p.curve.P)
	p.RandInt=make([]byte,32)
	_,err=rand.Read(p.RandInt)
	if err!=nil{
		err=fmt.Errorf("rand.Read failed:%v",err)
		return
	}
	p.PubKey1=new(elliptic.CurvePoint)
	p.PubKey1.X,_=new(big.Int).SetString("9932447698367082640257483044363349348872996515059959157560457878187",10)
	p.PubKey1.Y,_=new(big.Int).SetString("8388720915886119779160748420876218981755600630586628957892069627840",10)
	if p.curve.IfOnCurve(p.PubKey1)==false {
		err=fmt.Errorf("PubKey1 is not on curve")
		return
	}
	p.PubKey2=new(elliptic.CurvePoint)
	p.PubKey2.X,_=new(big.Int).SetString("18768295268253505552656947459233887712743899097505888838490343948275",10)
	p.PubKey2.Y,_=new(big.Int).SetString("1984358974232747532252704275995517270897127169579808754393510872439",10)
	if p.curve.IfOnCurve(p.PubKey2)==false {
		err=fmt.Errorf("PubKey2 is not on curve")
		return
	}
	p.SendP=new(elliptic.CurvePoint)
	p.RecvP=new(elliptic.CurvePoint)
	p.w=new(elliptic.CurvePoint)
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
	var temp1,temp2,PublicKey *elliptic.CurvePoint
	PublicKey=new(elliptic.CurvePoint)
	if p.character!=0{
		PublicKey.X=p.PubKey1.X
		PublicKey.Y=p.PubKey1.Y
	}else{
		PublicKey.X=p.PubKey2.X
		PublicKey.Y=p.PubKey2.Y
	}

	temp1=p.curve.Mult(PublicKey,[]byte(p.pw))
	temp2=p.curve.BaseMult(p.RandInt)
	data,err:=json.Marshal(p.curve.Add(temp1,temp2))
	if err!=nil{
		return
	}
	json.Unmarshal(data,&p.SendP)
	return 
}
func (p*MyPake)getKeyPack()(err error){
	p.KeyPack=make([]byte,16)
	copy(p.KeyPack,p.w.X.Bytes())
	return
}
func (p*MyPake)UpdateOther(bytes []byte)(err error){
	var qSend *elliptic.CurvePoint
	err=json.Unmarshal(bytes,&qSend)
	if err!=nil{
		err=fmt.Errorf("json.Unmarshal failed:%v",err)
		return
	}
	p.RecvP.X=qSend.X
	p.RecvP.Y=qSend.Y
	if p.curve.IfOnCurve(p.RecvP)==false{
		err=fmt.Errorf("RecvP is not on curve")
		return
	}
	var PubKey = new(elliptic.CurvePoint)
	if p.character==0{
		PubKey.X=p.PubKey1.X
		PubKey.Y=p.PubKey1.Y
	}else{
		PubKey.X=p.PubKey2.X
		PubKey.Y=p.PubKey2.Y
	}	
	var temp1,temp2,temp3 = new(elliptic.CurvePoint), new(elliptic.CurvePoint), new(elliptic.CurvePoint)
	temp1.X=qSend.X
	temp1.Y=new(big.Int).Mod(new(big.Int).Neg(qSend.Y),p.mod)
	temp2=p.curve.Mult(PubKey,[]byte(p.pw))
	temp3=p.curve.Add(temp2,temp1)
	data,err:=json.Marshal(p.curve.Mult(temp3,p.RandInt))
	json.Unmarshal(data,p.w)
	p.getKeyPack()
	buf := getNewBuf()
	buf.Write([]byte(p.pw))
	buf.Write(p.w.X.Bytes())
	buf.Write(p.w.Y.Bytes())
	buf.Write(p.PubKey1.X.Bytes())
	buf.Write(p.PubKey1.Y.Bytes())
	buf.Write(p.PubKey2.X.Bytes())
	buf.Write(p.PubKey2.Y.Bytes())
	n:=0
	p.Session_key , n , err = getSessionKey(buf)
	// fmt.Println("n:",n,p.Session_key)
	AES, Iv := getAES()
	aes.AES_init_ctx_iv(AES,p.KeyPack,Iv[:])
	aes.AES_CBC_decrypt_buffer(AES,p.Session_key[:],n)


	return 
}
func getSessionKey(buf*bytes.Buffer)(session_key []byte,n int,err error){
	session_key=make([]byte,200)
	n,err = buf.Read(session_key)
	return
}
func getNewBuf()*bytes.Buffer{
	return new(bytes.Buffer)
}
func getAES()(AES * aes.AES_KEY , Iv [16]byte){
	Iv = [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	AES = new(aes.AES_KEY)
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