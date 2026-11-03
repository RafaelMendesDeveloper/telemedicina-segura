package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const urlJWKSServidor = "http://localhost:8081/.well-known/jwks.json"
const kidServidor = "servidor-prontuarios-ecdh-rafael"

// Baixa o JWK Set do servidor e escolhe a chave pelo kid
func buscarChaveServidor() (*jose.JSONWebKey, error) {
	resp, err := http.Get(urlJWKSServidor)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	chaves := jwks.Key(kidServidor)
	if len(chaves) == 0 {
		return nil, fmt.Errorf("chave %s não encontrada", kidServidor)
	}
	return &chaves[0], nil
}


// NOVO: login no Keycloak (OIDC) e retorno do Access Token
func obterTokenKeycloak() (string, error) {
	resp, err := http.PostForm(
		"http://localhost:8080/realms/Telemedicina-Realm/protocol/openid-connect/token",
		url.Values{
			"grant_type": {"password"},
			"client_id":  {"portal-medico-app"},
			"username":   {"dr.silva"},
			"password":   {"admin"},
			"scope":      {"openid"},
		},
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var resposta struct {
		AccessToken string `json:"access_token"`
		Erro        string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&resposta); err != nil {
		return "", err
	}
	if resposta.AccessToken == "" {
		return "", fmt.Errorf("Keycloak recusou o login: %s", resposta.Erro)
	}
	return resposta.AccessToken, nil
}

// NOVO: lê a chave privada do médico e assina o laudo (JWS)
func assinarLaudo() (string, error) {
	dados, err := os.ReadFile("chaves/medico_privada.json")
	if err != nil {
		return "", err
	}
	var chaveMedico jose.JSONWebKey
	if err := json.Unmarshal(dados, &chaveMedico); err != nil {
		return "", err
	}

	// Payload com os dados médicos
	laudo := map[string]any{
		"medico":      "dr.silva",
		"paciente_id": "PAC-2026-0042",
		"diagnostico": "Hipertensao arterial estagio 1",
		"prescricao":  "Losartana 50mg, 1x ao dia",
		"iat":         time.Now().Unix(),
	}
	payload, err := json.Marshal(laudo)
	if err != nil {
		return "", err
	}

	// Assinador ES256 com a chave privada do médico
	assinador, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: &chaveMedico},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}

	objeto, err := assinador.Sign(payload)
	if err != nil {
		return "", err
	}
	return objeto.CompactSerialize()
}

// NOVO: decodifica um pedaço base64url e imprime como JSON formatado
func mostrarJSON(titulo, parteB64 string) {
	bruto, _ := base64.RawURLEncoding.DecodeString(parteB64)
	var bonito map[string]any
	json.Unmarshal(bruto, &bonito)
	formatado, _ := json.MarshalIndent(bonito, "", "  ")
	fmt.Println(titulo)
	fmt.Println(string(formatado))
}

func main() {
	accessToken, err := obterTokenKeycloak()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Login no Keycloak OK. Access Token (início):", accessToken[:40]+"...")
	fmt.Println("\n==============================================\n")

	// ===== ETAPA 3, PASSO 1: ASSINATURA JWS =====
	jws, err := assinarLaudo()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("JWS compacto (laudo assinado):")
	fmt.Println(jws)

	partesJWS := strings.Split(jws, ".")
	fmt.Println("\nPartes do JWS:")
	fmt.Println("  1. Header    =", partesJWS[0])
	fmt.Println("  2. Payload   =", partesJWS[1])
	fmt.Println("  3. Signature =", partesJWS[2])
	fmt.Println()
	mostrarJSON("Header do JWS:", partesJWS[0])
	mostrarJSON("Payload do JWS:", partesJWS[1])

	fmt.Println("\n==============================================\n")

	// ===== CIFRAGEM (ainda com a mensagem de teste) =====
	chaveServidor, err := buscarChaveServidor()
	if err != nil {
		log.Fatal(err)
	}

	cifrador, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: chaveServidor},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		log.Fatal(err)
	}

	objeto, err := cifrador.Encrypt([]byte(jws))
	if err != nil {
		log.Fatal(err)
	}

	jwe, err := objeto.CompactSerialize()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("JWE compacto:")
	fmt.Println(jwe)

	partes := strings.Split(jwe, ".")
	nomes := []string{"ProtectedHeader", "EncryptedKey", "IV", "Ciphertext", "AuthTag"}
	fmt.Println("\nPartes do JWE:")
	for i, p := range partes {
		fmt.Printf("  %d. %-15s = %s\n", i+1, nomes[i], p)
	}
	fmt.Println()
	mostrarJSON("Cabeçalho do JWE:", partes[0])

	// Envia o JWE para o servidor
		// Envia o JWE para o servidor, com o Access Token no cabeçalho
		req, err := http.NewRequest("POST", "http://localhost:8081/api/prontuarios",
		strings.NewReader(jwe))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/jose")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	resposta, _ := io.ReadAll(resp.Body)
	fmt.Println("\nResposta do servidor:", resp.Status)
	fmt.Println(string(resposta))
}