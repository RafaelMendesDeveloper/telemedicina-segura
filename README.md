# Telemedicina Segura: Keycloak (OIDC) + JWS + JWE + ECDH-ES

Atividade prática da disciplina **Segurança – Web, Identidades e Nuvem (INE410124)** – PPGCC/UFSC.

Mini aplicação de prontuários médicos em **Go** com:

- **Autenticação federada** via Keycloak (OAuth2/OIDC)
- **Assinatura do laudo** com JWS / ES256 (RFC 7515), garantindo integridade e não-repúdio
- **Acordo de chaves** ECDH-ES na curva P-256 (RFC 7518), com chave de sessão efêmera
- **Cifragem** JWE / A128GCM (RFC 7516) em **Nested JWT** (Sign-then-Encrypt, `cty: JWT`)
- **Distribuição de chaves** via JWK Set (RFC 7517)

## Arquitetura

```
Portal do Médico          Keycloak (IdP)          Servidor de Prontuários
  (cliente/)                                         (servidor/)
      |--- 1. login (OIDC) ----->|                         |
      |<-- 2. Access Token ------|                         |
      |                                                    |
      |--- 3. GET /.well-known/jwks.json ----------------->|  chave pública ECDH
      |                                                    |
      |  assina laudo (JWS ES256) -> cifra (JWE ECDH-ES)   |
      |--- 4. POST /api/prontuarios (Bearer + JWE) ------->|
      |                                                    |  valida token (JWKS Keycloak)
      |                                                    |  decifra JWE: K = nB·PA
      |                                                    |  valida JWS com medico_jwk do token
      |<-- 5. confirmação ---------------------------------|
```

A chave pública do médico fica no Keycloak (atributo `medico_jwk` do usuário) e chega ao
servidor **dentro do Access Token**, que é assinado pelo Keycloak e validado pelo JWK Set do realm.

## Estrutura

| Pasta | Função |
|---|---|
| `cliente/` | Portal do Médico: login, assinatura JWS, cifragem JWE, envio |
| `servidor/` | Servidor de Prontuários (porta 8081): valida token, decifra, verifica assinatura |
| `atacante/` | Simulação de MiTM: laudo falso cifrado corretamente, mas com assinatura falsa |
| `gerachave/` | Gera o par estático ECDH-ES do servidor |
| `gerachave_medico/` | Gera o par ES256 de assinatura do médico |
| `chaves/` | Chaves **públicas** (as privadas não são versionadas) |
| `executar.sh` | Sobe o ambiente e executa a demonstração |

## Pré-requisitos

- Linux com Docker
- Go 1.22+
- `curl`

## 1. Keycloak

```bash
docker run -d --name keycloak_med --net=host \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

No console (http://localhost:8080, `admin`/`admin`):

1. **Realm:** criar `Telemedicina-Realm` (atenção: no seletor de realm, não configurar no `master`).
2. **Client:** criar `portal-medico-app` (OpenID Connect) com:
   - Client authentication: **Off**
   - Authentication flow: **Direct access grants** marcado
3. **Realm settings → General → Unmanaged Attributes:** **Enabled**
4. **Usuário `dr.silva`:**
   - preencher Email, First name e Last name; Email verified **On**
   - Required user actions: **vazio**
   - Credentials: definir senha com Temporary **Off**
5. **Gerar as chaves** (na raiz do projeto):
   ```bash
   go run ./gerachave
   go run ./gerachave_medico
   tr -d ' \n' < chaves/medico_publica.json; echo
   ```
6. **Atributo do usuário:** Users → dr.silva → Attributes → key `medico_jwk`,
   value = a linha JSON impressa no item 5.
7. **Mapper:** Clients → portal-medico-app → Client scopes → `portal-medico-app-dedicated`
   → Add mapper → By configuration → **User Attribute**:
   - User Attribute: `medico_jwk` / Token Claim Name: `medico_jwk`
   - Claim JSON Type: **JSON**
   - Add to access token: **On**

> Se a senha do dr.silva for diferente de `admin`, ajuste-a em `cliente/main.go` e `atacante/main.go`.

## 2. Executar

```bash
./executar.sh            # fluxo normal
./executar.sh --ataque   # fluxo normal + simulação de MiTM
```

Saída esperada no servidor:

```
[0] Access Token válido (Keycloak). usuário = dr.silva
[1] JWE decifrado com sucesso (ECDH-ES)
[2] cty = JWT -> conteúdo é um JWS aninhado
[3] Assinatura JWS válida com a chave do Keycloak. kid = dr.silva-assinatura
[4] Laudo recebido: {...}
```

## 3. Testes de segurança

| Ataque | Resultado |
|---|---|
| Requisição sem token | `401` – cabeçalho Authorization ausente |
| Token forjado | `401` – kid/assinatura não conferem com o JWKS do Keycloak |
| JWE adulterado (1 caractere do ciphertext) | `400` – falha na AuthTag do AES-GCM |
| Laudo falso cifrado com ECDH-ES válido (`./executar.sh --ataque`) | `401` – assinatura JWS inválida |

O último teste mostra que o ECDH-ES garante **sigilo**, mas não autentica o remetente
(qualquer um pode cifrar com a chave pública do servidor). A **autenticidade** vem da
assinatura JWS interna, que exige a chave privada do médico.

## Limitações (ambiente de laboratório)

- Tráfego em **HTTP**: a senha e o Access Token aparecem em claro na rede (ver captura
  `captura_telemedicina.pcapng`). O laudo continua protegido pelo JWE, mas em produção
  tudo deve usar **TLS**.
- Uso do *Resource Owner Password Grant* por simplicidade. Em produção, usar
  **Authorization Code + PKCE**.
- Sem proteção contra **replay** do mesmo JWE (poderia ser resolvido com `jti` + registro de IDs).
- Credenciais fixas no código apenas para fins didáticos.

## Autor

Rafael Mendes – PPGCC/UFSC
