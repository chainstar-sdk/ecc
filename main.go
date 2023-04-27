package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
)

var (
	n = flag.Int("n", 1, "生成密钥对数量")
)

type EccKey struct {
	PrivateKey string
	PublicKey  string
}

func main() {
	flag.Parse()
	for i := 1; i <= *n; i++ {
		keyPair, _ := GenerateEccKeyBase64()
		fmt.Println(keyPair.PrivateKey)
		fmt.Println(keyPair.PublicKey)
	}
}

func GenerateEccKeyBase64() (EccKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EccKey{}, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return EccKey{}, err
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return EccKey{}, err
	}
	return EccKey{
		PrivateKey: base64.StdEncoding.EncodeToString(privateBytes),
		PublicKey:  base64.StdEncoding.EncodeToString(publicBytes),
	}, nil
}
