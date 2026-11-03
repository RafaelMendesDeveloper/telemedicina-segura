package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	keycloakIssuer  = "http://localhost:8080/realms/Telemedicina-Realm"
	keycloakJWKS    = keycloakIssuer + "/protocol/openid-connect/certs"
	clienteEsperado = "portal-medico-app"
)

// Campos do Access Token que interessam ao servidor
type ClaimsKeycloak struct {
	Azp       string           `json:"azp"`
	Usuario   string           `json:"preferred_username"`
	MedicoJWK *jose.JSONWebKey `json:"medico_jwk"`
}

// Lê um JWK de um arquivo
func carregarChave(caminho string) jose.JSONWebKey {
	dados, err := os.ReadFile(caminho)
	if err != nil {
		log.Fatal(err)
	}
	var chave jose.JSONWebKey
	if err := json.Unmarshal(dados, &chave); err != nil {
		log.Fatal(err)
	}
	return chave
}

// Baixa o JWK Set do Keycloak (chaves públicas que assinam os tokens)
func buscarJWKSKeycloak() jose.JSONWebKeySet {
	resp, err := http.Get(keycloakJWKS)
	if err != nil {
		log.Fatal("não consegui falar com o Keycloak: ", err)
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		log.Fatal(err)
	}
	return jwks
}

// Valida o Access Token do cabeçalho Authorization
func validarAccessToken(r *http.Request, jwks jose.JSONWebKeySet) (*ClaimsKeycloak, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("cabeçalho Authorization ausente")
	}
	bruto := strings.TrimPrefix(auth, "Bearer ")

	// O token é um JWS assinado pelo Keycloak com RS256
	token, err := jwt.ParseSigned(bruto, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("token mal formado: %w", err)
	}

	// Escolhe no JWK Set a chave indicada pelo kid do token
	kid := token.Headers[0].KeyID
	chaves := jwks.Key(kid)
	if len(chaves) == 0 {
		return nil, fmt.Errorf("kid %s não está no JWK Set do Keycloak", kid)
	}

	// Verifica a assinatura e lê os campos
	var padrao jwt.Claims
	var extras ClaimsKeycloak
	if err := token.Claims(&chaves[0], &padrao, &extras); err != nil {
		return nil, fmt.Errorf("assinatura do token inválida: %w", err)
	}

	// Confere emissor e validade
	if err := padrao.Validate(jwt.Expected{Issuer: keycloakIssuer, Time: time.Now()}); err != nil {
		return nil, fmt.Errorf("token rejeitado: %w", err)
	}

	// Confere para qual cliente o token foi emitido
	if extras.Azp != clienteEsperado {
		return nil, fmt.Errorf("token emitido para outro cliente: %s", extras.Azp)
	}

	if extras.MedicoJWK == nil {
		return nil, fmt.Errorf("token sem medico_jwk")
	}
	return &extras, nil
}

func main() {
	chavePublica := carregarChave("chaves/servidor_publica.json")
	chavePrivada := carregarChave("chaves/servidor_privada.json") // nB
	jwksKeycloak := buscarJWKSKeycloak()
	log.Println("JWK Set do Keycloak carregado:", len(jwksKeycloak.Keys), "chave(s)")

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{chavePublica}}

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	http.HandleFunc("/api/prontuarios", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}

		// 0) Valida o Access Token do Keycloak
		claims, err := validarAccessToken(r, jwksKeycloak)
		if err != nil {
			log.Println("[X] Token rejeitado:", err)
			http.Error(w, "não autorizado: "+err.Error(), http.StatusUnauthorized)
			return
		}
		log.Println("[0] Access Token válido (Keycloak). usuário =", claims.Usuario)

		corpo, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "erro lendo corpo", http.StatusBadRequest)
			return
		}

		// 1) Decifra o JWE (ECDH-ES + A128GCM)
		objeto, err := jose.ParseEncrypted(string(corpo),
			[]jose.KeyAlgorithm{jose.ECDH_ES},
			[]jose.ContentEncryption{jose.A128GCM})
		if err != nil {
			http.Error(w, "JWE inválido: "+err.Error(), http.StatusBadRequest)
			return
		}

		textoClaro, err := objeto.Decrypt(&chavePrivada)
		if err != nil {
			http.Error(w, "falha ao decifrar: "+err.Error(), http.StatusBadRequest)
			return
		}
		log.Println("[1] JWE decifrado com sucesso (ECDH-ES)")

		// 2) Confere se o conteúdo é um JWT aninhado
		cty := fmt.Sprint(objeto.Header.ExtraHeaders[jose.HeaderContentType])
		if cty != "JWT" {
			http.Error(w, "cty esperado JWT, recebido: "+cty, http.StatusBadRequest)
			return
		}
		log.Println("[2] cty = JWT -> conteúdo é um JWS aninhado")

		// 3) Verifica o JWS com a chave do médico VINDA DO KEYCLOAK
		assinado, err := jose.ParseSigned(string(textoClaro),
			[]jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			http.Error(w, "JWS inválido: "+err.Error(), http.StatusBadRequest)
			return
		}

		payload, err := assinado.Verify(claims.MedicoJWK)
		if err != nil {
			log.Println("[X] ASSINATURA INVÁLIDA:", err)
			http.Error(w, "assinatura inválida", http.StatusUnauthorized)
			return
		}
		log.Println("[3] Assinatura JWS válida com a chave do Keycloak. kid =", claims.MedicoJWK.KeyID)

		// 4) O médico do laudo tem que ser quem fez login
		var laudo map[string]any
		json.Unmarshal(payload, &laudo)
		if fmt.Sprint(laudo["medico"]) != claims.Usuario {
			log.Println("[X] Médico do laudo diferente do usuário logado")
			http.Error(w, "laudo não pertence ao usuário autenticado", http.StatusForbidden)
			return
		}
		log.Println("[4] Laudo recebido:", string(payload))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "prontuario recebido",
			"assinatura":  "valida",
			"medico":      laudo["medico"],
			"paciente_id": laudo["paciente_id"],
		})
	})

	log.Println("Servidor de Prontuários ouvindo em http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}