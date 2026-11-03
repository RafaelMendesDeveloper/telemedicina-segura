#!/usr/bin/env bash
# executar.sh - sobe o ambiente e roda a demonstração
# Uso: ./executar.sh            (fluxo normal)
#      ./executar.sh --ataque   (fluxo normal + simulação de MiTM)
set -e
cd "$(dirname "$0")"

KC_URL="http://localhost:8080/realms/Telemedicina-Realm"

echo "==> 1. Keycloak"
if docker ps --format '{{.Names}}' | grep -q '^keycloak_med$'; then
  echo "    já está rodando"
elif docker ps -a --format '{{.Names}}' | grep -q '^keycloak_med$'; then
  docker start keycloak_med >/dev/null
  echo "    container iniciado"
else
  docker run -d --name keycloak_med --net=host \
    -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
    quay.io/keycloak/keycloak:latest start-dev >/dev/null
  echo "    container criado."
  echo "    ATENÇÃO: configure o realm conforme o README e rode o script de novo."
  exit 0
fi

echo "==> 2. Aguardando o Keycloak responder"
until curl -sf "$KC_URL/.well-known/openid-configuration" >/dev/null; do
  sleep 2; printf "."
done
echo "    ok"

echo "==> 3. Chaves"
if [ ! -f chaves/servidor_privada.json ]; then
  go run ./gerachave
fi
if [ ! -f chaves/medico_privada.json ]; then
  go run ./gerachave_medico
  echo
  echo "ATENÇÃO: foi gerada uma chave NOVA para o médico."
  echo "Atualize o atributo medico_jwk do usuário dr.silva no Keycloak com:"
  tr -d ' \n' < chaves/medico_publica.json; echo
  echo "Depois rode o script de novo."
  exit 0
fi
echo "    ok"

echo "==> 4. Compilando"
mkdir -p bin
go build -o bin/servidor ./servidor
go build -o bin/cliente  ./cliente
go build -o bin/atacante ./atacante

echo "==> 5. Servidor de Prontuários (porta 8081)"
./bin/servidor &
PID_SERVIDOR=$!
trap 'kill $PID_SERVIDOR 2>/dev/null' EXIT
until curl -sf http://localhost:8081/.well-known/jwks.json >/dev/null; do sleep 1; done

echo "==> 6. Portal do Médico"
./bin/cliente

if [ "$1" = "--ataque" ]; then
  echo
  echo "==> 7. Simulação de ataque MiTM"
  ./bin/atacante
fi
