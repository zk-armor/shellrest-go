# shellrest-go

Servicio REST que expone ejecución de comandos del sistema (stdin/stdout/stderr) con autenticación por Bearer basada en claves `ssh-ed25519` del archivo `/etc/ssh/authorized_keys`.

## Instalación y uso con Homebrew

La forma recomendada es vía Homebrew (macOS y Linux):

```bash
brew tap zk-armor/homebrew-tap
brew install shellrest-go
```

Arrancar como servicio en segundo plano:

```bash
brew services start shellrest-go
```

Config por defecto: `$(brew --prefix)/etc/shellrest/sshrest.conf`

Editar config y reiniciar el servicio:

```bash
$EDITOR "$(brew --prefix)/etc/shellrest/sshrest.conf"
brew services restart shellrest-go
```

Derivar TOKEN desde el `authorized_keys` configurado (ejemplo):

```bash
AUTH_KEYS="$(brew --prefix)/etc/shellrest/sshrest.conf" # archivo de config
AUTH_KEYS_PATH=$(grep '^SRG_AUTH_KEYS_PATH=' "$AUTH_KEYS" | cut -d= -f2)
TOKEN=$(awk '$1=="ssh-ed25519"{print $2}' "$AUTH_KEYS_PATH" | head -n1 | base64 -d | \
  openssl dgst -sha256 -binary | xxd -p -c 256)
echo "TOKEN=$TOKEN"
```

Probar health y un comando:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/healthz
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/exec \
  -d '{"cmd":"bash","args":["-lc","uname -a"],"timeout_seconds":15}' | jq .
```

Actualizar a la última versión:

```bash
brew update && brew upgrade shellrest-go
```

Detener servicio y desinstalar:

```bash
brew services stop shellrest-go
brew uninstall shellrest-go
```

Referencia OpenAPI: [`api/openapi.yaml`](api/openapi.yaml)

## Auth

- El header `Authorization: Bearer <TOKEN>` es obligatorio para `/api/v1/exec`.
- `<TOKEN>` debe ser el `hex(sha256(<pubkey_bytes>))` de la clave pública `ssh-ed25519` tal como figura en `authorized_keys`.
  - Se toma la porción base64 de la línea, se decodifica, y sobre esos bytes se calcula SHA-256.
  - Se aceptan varias líneas y se ignoran comentarios/opciones y tipos de clave distintos a `ssh-ed25519`.

## Endpoints

- `POST /healthz` (sin auth): simple healthcheck.
- `POST /api/v1/exec` (con auth): ejecuta un comando con stdin opcional embebido en JSON.
- `POST /api/v1/exec/pipe` (con auth): ejecuta un comando y conecta el cuerpo HTTP directamente al stdin del proceso (tamaño/longitud desconocidos).

Request JSON:
```json
{
  "cmd": "bash",
  "args": ["-lc", "echo hello && echo err >&2 && exit 3"],
  "stdin": "",          // opcional
  "stdin_b64": false,    // si true, interpreta stdin como base64
  "timeout_seconds": 30, // opcional
  "workdir": "/tmp",    // opcional
  "env": ["FOO=bar"]     // opcional, pares KEY=VALUE
}
```

## Docker Compose

Se recomienda usar Docker Compose con `sshrest.conf` para configuración por defecto.

Prerequisitos:
- Asegurá tener `./.test/auth/authorized_keys` con al menos una clave pública `ssh-ed25519` válida (Bearer se deriva de allí).

Arrancar servicio:
```bash
docker compose up -d --build
```

Ver logs:
```bash
docker compose logs -f
```

Config (por `env_file`): `sshrest.conf`
- `SRG_LISTEN_ADDR=:8080`
- `SRG_AUTH_KEYS_PATH=/etc/ssh/authorized_keys`
- `SRG_EXEC_TIMEOUT=120s`

Derivar TOKEN desde `authorized_keys`:
```bash
TOKEN=$(awk '$1=="ssh-ed25519"{print $2}' ./.test/auth/authorized_keys | head -n1 | base64 -d | \
  openssl dgst -sha256 -binary | xxd -p -c 256)
echo "TOKEN=$TOKEN"
```

Health:
```bash
curl -sS -H "Authorization: Bearer $TOKEN" -X POST http://localhost:8080/healthz
```

Luego podés seguir los ejemplos de endpoints más abajo.

## Docker: build & test

### 1) Compilar imagen (multi-stage)
```bash
docker build -t shellrest-go:latest .
```

### 2) Preparar authorized_keys
- El servidor valida Bearer tokens contra claves `ssh-ed25519` en `/etc/ssh/authorized_keys` (dentro del contenedor).
- Opción A: Usar tu `/etc/ssh/authorized_keys` del host (sólo si contiene una clave `ssh-ed25519`).
```bash
HOST_AUTH_KEYS=/etc/ssh/authorized_keys
```
- Opción B (demo): crear un archivo `authorized_keys` con una clave `ssh-ed25519` tuya.
```bash
# si ya tenés ~/.ssh/id_ed25519.pub, usalo
cp ~/.ssh/id_ed25519.pub /tmp/authorized_keys
HOST_AUTH_KEYS=/tmp/authorized_keys
```

### 3) Ejecutar contenedor
```bash
docker run --rm -p 8080:8080 \
  -v "$HOST_AUTH_KEYS":/etc/ssh/authorized_keys:ro \
  --name shellrest-go shellrest-go:latest
```

Variables opcionales:
- `-e SRG_LISTEN_ADDR=":8080"`
- `-e SRG_EXEC_TIMEOUT=120s` (usar `0s` para deshabilitar timeout por defecto)
- `-e SRG_AUTH_KEYS_PATH=/etc/ssh/authorized_keys`

### 4) Derivar TOKEN desde authorized_keys
```bash
TOKEN=$(awk '$1=="ssh-ed25519"{print $2}' "$HOST_AUTH_KEYS" | head -n1 | base64 -d | sha256sum | awk '{print $1}')
echo "TOKEN=$TOKEN"
```

### 5) Probar health
```bash
curl -sS -X POST http://localhost:8080/healthz
```

### 6) Probar /api/v1/exec
```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/exec \
  -d '{"cmd":"bash","args":["-lc","echo out; echo err >&2; exit 3"],"timeout_seconds":30}' | jq .
```

### 7) Probar /api/v1/exec/pipe (stdin streaming)
```bash
echo "hola streaming" | \
curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "http://localhost:8080/api/v1/exec/pipe?cmd=bash&arg=-lc&arg=cat" \
  --data-binary @- | jq .
```

### 8) Probar Jobs asíncronos con protocolo en dos fases (peek)

Start job:
```bash
JOB=$(curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/jobs/start \
  -d '{"cmd":"bash","args":["-lc","cat - | tr a-z A-Z"],"timeout_seconds":0}')
JOB_ID=$(echo "$JOB" | jq -r .job_id)
echo "JOB_ID=$JOB_ID"
```

Peek inicial (sin offsets):
```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/jobs/peek \
  -d '{"job_id":"'"$JOB_ID"'","stdout_offset":0,"stderr_offset":0}' | jq .
```

Enviar stdin parcial (no cerrar):
```bash
echo 'hola agente' | \
curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "http://localhost:8080/api/v1/jobs/stdin?job_id=$JOB_ID&close=0" --data-binary @-
```

Leer logs incrementales (offsets en 0):
```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/jobs/logs \
  -d '{"job_id":"'"$JOB_ID"'","stdout_offset":0,"stderr_offset":0}' | jq .
```

Cerrar stdin para que el proceso termine:
```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "http://localhost:8080/api/v1/jobs/stdin?job_id=$JOB_ID&close=1" -d ''
```

Consultar peek nuevamente (debería sugerir `read_stdout`/`exit_status` según offsets/estado):
```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/jobs/peek \
  -d '{"job_id":"'"$JOB_ID"'","stdout_offset":0,"stderr_offset":0}' | jq .
```

Consultar estado final:
```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/jobs/status \
  -d '{"job_id":"'"$JOB_ID"'"}' | jq .
```

Cancelar (si seguía corriendo):
```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/jobs/cancel \
  -d '{"job_id":"'"$JOB_ID"'"}' | jq .
```

### 9) Probar Filesystem (UTF-8)
```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/fs/write_file \
  -d '{"path":"/tmp/demo.txt","content":"hola docker\n"}' | jq .

curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/fs/read_file \
  -d '{"path":"/tmp/demo.txt"}' | jq .
```
## Ejecuciones largas

- Por request, usar `timeout_seconds=0` para deshabilitar el timeout.
- Globalmente, configurar `SRG_EXEC_TIMEOUT=0s` para no imponer límite por defecto.
- El servidor no define `ReadTimeout` para permitir cuerpos grandes/streams prolongados; tiene `IdleTimeout` de 5m y `WriteTimeout` sin límite.
- Si usás un proxy/cargador (nginx, traefik, cloud), ajustá sus timeouts para permitir sesiones largas y respuestas grandes (e.g., `proxy_read_timeout`, `client_body_timeout`).

Response JSON:
```json
{
  "stdout": "hello\n",
  "stderr": "err\n",
  "exit_code": 3,
  "timed_out": false,
  "duration_ms": 12,
  "stdout_b64": false,
  "stderr_b64": false
}
```

- Nota: si el proceso expira por tiempo, HTTP 408; de lo contrario 200 aún cuando `exit_code` sea no-cero.

### Endpoint streaming: `/api/v1/exec/pipe`

- Permite stdin de tamaño desconocido (streaming) tomando el body del request tal cual.
- Query params:
  - `cmd` (obligatorio): ejecutable.
  - `arg` (repetible): argumentos. Ej: `&arg=-lc&arg=cat`.
  - `timeout_seconds` (opcional): segundos (entero).
- Headers opcionales:
  - `X-Workdir`: directorio de trabajo.
  - `X-Env`: lista separada por coma de `KEY=VALUE` para variables de entorno.
- Respuesta: mismo JSON que el endpoint `/api/v1/exec`.

Ejemplos:

Enviar un archivo grande por stdin:
```bash
TOKEN=$(awk '$1=="ssh-ed25519"{print $2}' /etc/ssh/authorized_keys | head -n1 | base64 -d | sha256sum | awk '{print $1}')

# Envía un tar como stdin al proceso "tar -tzf -" para listar su contenido
tar -czf - /var/log | \
curl -sS -H "Authorization: Bearer $TOKEN" \
     -X POST "http://localhost:8080/api/v1/exec/pipe?cmd=bash&arg=-lc&arg=tar%20-tzf%20-" \
     --data-binary @- | jq .
```

Stream desde stdin interactivo (ejemplo con here-doc):
```bash
cat <<'EOF' | \
curl -sS -H "Authorization: Bearer $TOKEN" \
     -X POST "http://localhost:8080/api/v1/exec/pipe?cmd=bash&arg=-lc&arg=cat%20-%20|%20wc%20-c"
hola
mundo
EOF
```

## Variables de entorno

- `SRG_LISTEN_ADDR` (default `:8080`)
- `SRG_AUTH_KEYS_PATH` (default `/etc/ssh/authorized_keys`)
- `SRG_EXEC_TIMEOUT` (default `120s`) — poner `0s` deshabilita el timeout por defecto (sin límite).

## Ejecutar

```bash
# compilar
GO111MODULE=on go build -v .

# ejecutar
./shellrest-go
```

Probar health (POST):
```bash
curl -sS -X POST localhost:8080/healthz
```

Probar exec JSON (requiere TOKEN válido):
```bash
TOKEN="<hex_sha256_de_pubkey_ed25519>"
curl -sS -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -X POST localhost:8080/api/v1/exec \
     -d '{"cmd":"bash","args":["-lc","cat; echo done >&2; exit 2"],"stdin":"hola\n"}'
```

Probar exec streaming (stdin de longitud desconocida):
```bash
echo "hola streaming" | \
curl -sS -H "Authorization: Bearer $TOKEN" \
     -X POST "http://localhost:8080/api/v1/exec/pipe?cmd=bash&arg=-lc&arg=cat" \
     --data-binary @-
```

## Orquestación asíncrona de Jobs (tipo AsyncSSH)

Todos los endpoints son `POST` y requieren Bearer (excepto `/healthz`). Permite:
- Iniciar un job y obtener `job_id`.
- Consultar estado.
- Leer logs incrementales con offsets (`stdout`/`stderr`).
- Enviar más stdin (stream) y opcionalmente cerrar stdin.
- Cancelar con terminación graciosa (SIGTERM, luego SIGKILL tras 5s).

Endpoints:

- `POST /api/v1/jobs/start`
  Request JSON:
  ```json
  {
    "cmd": "bash",
    "args": ["-lc", "cat - | wc -c"],
    "stdin": "",           // opcional
    "stdin_b64": false,     // opcional
    "timeout_seconds": 0,   // 0 = sin límite
    "workdir": "/tmp",     // opcional
    "env": ["FOO=bar"]      // opcional
  }
  ```
  Response:
  ```json
  { "job_id": "<id>" }
  ```

- `POST /api/v1/jobs/status`
  Request: `{ "job_id": "<id>" }`
  Response:
  ```json
  {
    "job_id": "<id>",
    "state": "running|exited|canceled|failed",
    "exit_code": 0,
    "timed_out": false,
    "start_time_unix_ms": 0,
    "end_time_unix_ms": 0,
    "duration_ms": 0,
    "stdout_size": 0,
    "stderr_size": 0
  }
  ```

- `POST /api/v1/jobs/logs`
  - Body JSON o query params. Campos: `job_id`, `stdout_offset`, `stderr_offset`.
  - Devuelve los nuevos fragmentos desde esos offsets y los próximos offsets.
  Response:
  ```json
  {
    "job_id": "<id>",
    "stdout": "...",
    "stderr": "...",
    "stdout_offset": 0,
    "stderr_offset": 0,
    "stdout_next_offset": 123,
    "stderr_next_offset": 45,
    "done": false
  }
  ```

- `POST /api/v1/jobs/stdin?job_id=<id>&close=0|1`
  - Cuerpo del request se anexa a stdin del job.
  - `close=1` cierra stdin del proceso tras escribir.
  Response:
  ```json
  { "job_id": "<id>", "written": 42, "closed": false }
  ```

- `POST /api/v1/jobs/cancel`
  Request: `{ "job_id": "<id>" }`
  Response: `{ "job_id": "<id>", "state": "canceled|exited" }`

Ejemplo completo:
```bash
TOKEN=$(awk '$1=="ssh-ed25519"{print $2}' /etc/ssh/authorized_keys | head -n1 | base64 -d | sha256sum | awk '{print $1}')

# 1) Start
JOB=$(curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/jobs/start \
  -d '{"cmd":"bash","args":["-lc","cat - | tr a-z A-Z"],"timeout_seconds":0}')
JOB_ID=$(echo "$JOB" | jq -r .job_id)

# 2) Send stdin (no cerrar aún)
echo 'hola agente' | \
curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "http://localhost:8080/api/v1/jobs/stdin?job_id=$JOB_ID&close=0" --data-binary @-

# 3) Leer logs incrementales
curl -sS -H "Authorization: Bearer $TOKEN" -X POST \
  -H 'Content-Type: application/json' \
  -d "{\"job_id\":\"$JOB_ID\",\"stdout_offset\":0,\"stderr_offset\":0}" \
  http://localhost:8080/api/v1/jobs/logs | jq .

# 4) Cerrar stdin
curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "http://localhost:8080/api/v1/jobs/stdin?job_id=$JOB_ID&close=1" -d ''

# 5) Status
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/jobs/status -d "{\"job_id\":\"$JOB_ID\"}" | jq .
```

## Lectura y escritura de archivos (UTF-8)

Endpoints POST, autenticados por Bearer, para operar archivos de texto UTF-8.

- `POST /api/v1/fs/write_file`
  - Request JSON:
  ```json
  { "path": "/tmp/nota.txt", "content": "línea 1\nlínea 2\n" }
  ```
  - Response:
  ```json
  { "path": "/tmp/nota.txt", "bytes_written": 16 }
  ```
  - Crea directorios padres si no existen. Permisos de archivo: 0644.

- `POST /api/v1/fs/read_file`
  - Request JSON:
  ```json
  { "path": "/tmp/nota.txt" }
  ```
  - Response (si es UTF-8 válido):
  ```json
  { "path": "/tmp/nota.txt", "content": "línea 1\nlínea 2\n", "size": 16 }
  ```
  - Si el contenido no es UTF-8 válido: HTTP 415.

Ejemplos:
```bash
TOKEN=$(awk '$1=="ssh-ed25519"{print $2}' /etc/ssh/authorized_keys | head -n1 | base64 -d | sha256sum | awk '{print $1}')

# Escribir archivo
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/fs/write_file \
  -d '{"path":"/tmp/demo.txt","content":"hola mundo\n"}' | jq .

# Leer archivo
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST http://localhost:8080/api/v1/fs/read_file \
  -d '{"path":"/tmp/demo.txt"}' | jq .
```

## Seguridad

- Este servicio ejecuta comandos del sistema; se recomienda aislarlo (e.g., contenedor, chroot, usuario dedicado) y restringir red/ACL.
- Las claves válidas se leen en arranque. Cambios en `authorized_keys` requieren reinicio para que surtan efecto.
