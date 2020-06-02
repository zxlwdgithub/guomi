package Golang

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)
const (
	// number of bits in a big.Word
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes = wordBits / 8
)
func Encrypt(pubKey []byte , data []byte) ([]byte, error) {
	publicKey := sm2.Decompress(pubKey)
	return sm2.Encrypt(publicKey,data)
}
func Decrypt(prvKey []byte , cryptedData []byte) ([]byte, error) {
	privateKey, err := sm2ToECDSA(prvKey)
	if err != nil {
		return nil, err
	}
	return sm2.Decrypt(privateKey,cryptedData)
}
func sm2ToECDSA(d []byte) (*sm2.PrivateKey, error) {
	strict := false
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = sm2.P256Sm2()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}
func sm2FromECDSA(priv *sm2.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}
func PaddedBigBytes(bigint *big.Int, n int) []byte {
	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	ReadBits(bigint, ret)
	return ret
}
func ReadBits(bigint *big.Int, buf []byte) {
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}
