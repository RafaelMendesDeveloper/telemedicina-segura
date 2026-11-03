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
	// Par de chaves do médico na curva P-256
	privada, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	jwkPrivada := jose.JSONWebKey{
		Key:       privada,
		KeyID:     "dr.silva-assinatura",
		Algorithm: string(jose.ES256),
		Use:       "sig",
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
	os.WriteFile("chaves/medico_privada.json", privJSON, 0o600)
	os.WriteFile("chaves/medico_publica.json", pubJSON, 0o644)

	fmt.Println("Chave pública do médico:")
	fmt.Println(string(pubJSON))
}