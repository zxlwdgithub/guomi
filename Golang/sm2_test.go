package Golang

import (
	"encoding/hex"
	"testing"
)

func TestEncrypt(t *testing.T) {
	message := []byte("hello world")
	t.Logf("Text message:%s", string(message))
	prvKey, pubKey := initKey()
	t.Logf("Private Key:%x", prvKey)
	t.Logf("Public Key:%x", pubKey)
	cryptedData, _ := Encrypt(pubKey, message)
	t.Logf("Ecrypt data:%x", cryptedData)
	decryptData, _ := Decrypt(prvKey, cryptedData)
	t.Logf("Decrypt data:%s", string(decryptData))
}
func initKey() ([]byte, []byte) {
	prvKey, _ := hex.DecodeString("2c4b9600224612effa2461c5d37bca68dba83f256a4b8830742fce0cca8a9115")
	pubKey, _ := hex.DecodeString("02ab645aa3ecac7845a5fcf6d68953ea613b2d586e2cddd7026ef9ac87d2996e10")
	return prvKey, pubKey
	//prvKey,_:= sm2.GenerateKey()
	//pubKey:=prvKey.PublicKey
	//return sm2FromECDSA(prvKey), sm2.Compress(&pubKey)
}

//func TestPubKeyCompress(t *testing.T){
//	prvKey, _ := hex.DecodeString("8329b263c4d6dc458346bee1cc7c20d03a449816532ff7e8463c112205d0a4b4")
//
//	privateKey, err := sm2ToECDSA(prvKey)
//	if err!=nil{
//		t.Log(err.Error())
//		return
//	}
//	pubKey:=privateKey.PublicKey
//	publicKey:=sm2.Compress(&pubKey)
//	t.Logf("compress pubkey:%x",publicKey)
//}
