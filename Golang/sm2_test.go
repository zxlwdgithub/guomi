package Golang

import (
	"testing"

	"github.com/tjfoc/gmsm/sm2"
)

func TestEncrypt(t *testing.T) {
	message:=[]byte("abcdefg")
	t.Logf("Text message:%s",string(message))
	prvKey,pubKey:=initKey()
	t.Logf("Private Key:%x,Public Key:%x",prvKey,pubKey)
	cryptedData,_:=Encrypt(pubKey,message)
	t.Logf("Ecrypt data:%x",cryptedData)
	decryptData,_:=Decrypt(prvKey,cryptedData)
	t.Logf("Decrypt data:%s",string(decryptData))
}
func initKey() ([]byte,[]byte){
	prvKey,_:= sm2.GenerateKey()
	pubKey:=prvKey.PublicKey
	return sm2FromECDSA(prvKey), sm2.Compress(&pubKey)
}