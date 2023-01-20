package main

import (
"aes"
"fmt"
)

func main() {
	// key:=make([]byte,16)
	// AES_KEY:=aes.AES_KEY{}
	// AES_KEY.roundKey=aes.ExternKey(key)
	
	// AES_CBC_encrypt_buffer(key, key)
	key:=new(aes.AES_KEY)
	
	// key.roundKey[0]=0x2b
	fmt.Printf("%#v",key)
}