#!/usr/bin/env bash
set -euo pipefail

# sshrest-setup: Wizard para configurar authorized_keys y reiniciar el servicio
# - Ubica/crea el archivo authorized_keys según la config
# - Permite elegir una clave existente (~/.ssh/*.pub) o pegar una nueva
# - Actualiza authorized_keys (dedup por base64)
# - Muestra el token derivado (hex sha256 de la pubkey decodificada)
# - Reinicia/arranca el servicio via Homebrew si está disponible

BREW_PREFIX=""
if command -v brew >/dev/null 2>&1; then
  BREW_PREFIX="$(brew --prefix)"
fi

ETC_DIR="${BREW_PREFIX:-}/etc/shellrest"
if [[ -z "$BREW_PREFIX" ]]; then
  # Fallback si no es Homebrew: usar /etc/shellrest en Linux (requiere permisos)
  ETC_DIR="/etc/shellrest"
fi

CONF="$ETC_DIR/sshrest.conf"
mkdir -p "$ETC_DIR"
if [[ ! -f "$CONF" ]]; then
  cat >"$CONF" <<EOF
# shellrest-go config
SRG_LISTEN_ADDR=:8080
SRG_AUTH_KEYS_PATH=$ETC_DIR/authorized_keys
SRG_EXEC_TIMEOUT=120s
EOF
fi

# Leer AUTH_KEYS_PATH desde config (o default)
AUTH_KEYS_PATH="$(grep -E '^SRG_AUTH_KEYS_PATH=' "$CONF" | head -n1 | cut -d= -f2- || true)"
if [[ -z "${AUTH_KEYS_PATH:-}" ]]; then
  AUTH_KEYS_PATH="$ETC_DIR/authorized_keys"
fi
# Expandir ~/
AUTH_KEYS_PATH="${AUTH_KEYS_PATH/#~\//$HOME/}"
mkdir -p "$(dirname "$AUTH_KEYS_PATH")"
touch "$AUTH_KEYS_PATH"

echo "shellrest-setup: Config archivo de claves: $AUTH_KEYS_PATH"
read -r -p "Directorio de claves públicas (.pub) [${HOME}/.ssh]: " KEY_DIR
KEY_DIR=${KEY_DIR:-"${HOME}/.ssh"}

# Listar claves ssh-ed25519
mapfile -t KEYS < <(ls -1 "$KEY_DIR"/*.pub 2>/dev/null | xargs -r grep -l "^ssh-ed25519" || true)

echo
PUB_LINE=""
if [[ ${#KEYS[@]} -gt 0 ]]; then
  echo "Claves ssh-ed25519 encontradas en $KEY_DIR:"
  i=1; for k in "${KEYS[@]}"; do echo "  [$i] $k"; i=$((i+1)); done
  echo "  [N] Ingresar una nueva clave pública manualmente"
  read -r -p "Elegí una opción (número o N): " SEL
  if [[ "$SEL" =~ ^[0-9]+$ ]] && (( SEL >= 1 && SEL <= ${#KEYS[@]} )); then
    PUB_FILE="${KEYS[$((SEL-1))]}"
    PUB_LINE="$(cat "$PUB_FILE")"
  else
    SEL="N"
  fi
else
  echo "No se encontraron claves .pub en $KEY_DIR"
  SEL="N"
fi

if [[ "$SEL" == "N" || "$SEL" == "n" ]]; then
  echo "Pegá la clave pública ssh-ed25519 (una línea):"
  read -r PUB_LINE
fi

echo "$PUB_LINE" | grep -q "^ssh-ed25519" || { echo "Clave inválida: debe empezar con ssh-ed25519" >&2; exit 1; }

# Deduplicar por segunda columna (base64)
B64="$(echo "$PUB_LINE" | awk '{print $2}')"
TMP=$(mktemp)
if [[ -s "$AUTH_KEYS_PATH" ]]; then
  grep -v "^ssh-ed25519 $B64" "$AUTH_KEYS_PATH" > "$TMP" || true
  mv "$TMP" "$AUTH_KEYS_PATH"
fi
echo "$PUB_LINE" >> "$AUTH_KEYS_PATH"

# Token derivado
TOKEN=$(echo "$B64" | base64 -d 2>/dev/null | openssl dgst -sha256 -binary | xxd -p -c 256)
echo
echo "Token derivado (hex sha256): $TOKEN"
echo "Config: $CONF"
echo "Authorized keys: $AUTH_KEYS_PATH"

# Reiniciar/arrancar servicio
if command -v brew >/dev/null 2>&1; then
  echo "Reiniciando servicio brew..."
  brew services restart shellrest-go || brew services start shellrest-go
else
  echo "brew no encontrado; iniciá el binario manualmente: shellrest-go --config $CONF"
fi

echo "Listo."
