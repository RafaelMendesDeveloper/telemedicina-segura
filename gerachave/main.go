package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
)

func main() {
	privada, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	jwkPrivada := jose.JSONWebKey{
		Key:       privada,
		KeyID:     "servidor-prontuarios-ecdh-rafael",
		Algorithm: string(jose.ECDH_ES),
		Use:       "enc",
	}
	jwkPublica := jwkPrivada.Public()

	privJSON, err := json.MarshalIndent(jwkPrivada, "", "  ")
	if err != nil {
		panic(err)
	}
	pubJSON, err := json.MarshalIndent(jwkPublica, "", "  ")
	if err != nil {
		panic(err)
	}

	os.MkdirAll("chaves", 0o755)
	os.WriteFile("chaves/servidor_privada.json", privJSON, 0o600)
	os.WriteFile("chaves/servidor_publica.json", pubJSON, 0o644)

	fmt.Println("Chave pública do servidor:")
	fmt.Println(string(pubJSON))
}