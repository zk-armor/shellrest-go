#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AUTH_DIR="$ROOT_DIR/.test/auth"
AUTH_KEYS="$AUTH_DIR/authorized_keys"
IMG="shellrest-go:latest"
CONTAINER_NAME="shellrest-go"
PORT="8080"
API="http://localhost:${PORT}"

mkdir -p "$AUTH_DIR"

if [[ ! -f "$AUTH_DIR/id_ed25519" ]]; then
  echo "[e2e] Generating test ed25519 key in $AUTH_DIR" >&2
  ssh-keygen -t ed25519 -N "" -f "$AUTH_DIR/id_ed25519" >/dev/null
fi

cp "$AUTH_DIR/id_ed25519.pub" "$AUTH_KEYS"

echo "[e2e] Building docker image $IMG" >&2
( cd "$ROOT_DIR" && docker build -t "$IMG" . )

# Stop stale container if exists
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
  echo "[e2e] Removing existing container $CONTAINER_NAME" >&2
  docker rm -f "$CONTAINER_NAME" >/dev/null || true
fi

echo "[e2e] Running container $CONTAINER_NAME on port $PORT" >&2
docker run -d --rm \
  -p "${PORT}:8080" \
  -v "$AUTH_KEYS":/etc/ssh/authorized_keys:ro \
  --name "$CONTAINER_NAME" "$IMG" >/dev/null

# Wait for the server to be ready
for i in {1..30}; do
  if curl -sS -X POST "$API/healthz" >/dev/null; then
    break
  fi
  sleep 0.5
  if [[ $i -eq 30 ]]; then
    echo "[e2e] Server did not become ready in time" >&2
    docker logs "$CONTAINER_NAME" || true
    exit 1
  fi
done

echo "[e2e] Deriving TOKEN from $AUTH_KEYS" >&2
TOKEN=$(awk '$1=="ssh-ed25519"{print $2}' "$AUTH_KEYS" | head -n1 | base64 -d | sha256sum | awk '{print $1}')
if [[ -z "$TOKEN" ]]; then
  echo "[e2e] Failed to derive token (no ssh-ed25519 key?)" >&2
  exit 1
fi

echo "[e2e] Health check" >&2
curl -sS -X POST "$API/healthz" | sed 's/^/[health] /'

echo "[e2e] Exec JSON" >&2
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/exec" \
  -d '{"cmd":"bash","args":["-lc","echo out; echo err >&2; exit 3"],"timeout_seconds":30}' | jq .

echo "[e2e] Exec pipe (streaming)" >&2
echo "hola streaming" | \
  curl -sS -H "Authorization: Bearer $TOKEN" \
    -X POST "$API/api/v1/exec/pipe?cmd=bash&arg=-lc&arg=cat" \
    --data-binary @- | jq .

echo "[e2e] Start job (cat - | tr a-z A-Z)" >&2
JOB=$(curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/start" \
  -d '{"cmd":"bash","args":["-lc","cat - | tr a-z A-Z"],"timeout_seconds":0}')
JOB_ID=$(echo "$JOB" | jq -r .job_id)
echo "[e2e] JOB_ID=$JOB_ID" >&2

if [[ -z "$JOB_ID" || "$JOB_ID" == "null" ]]; then
  echo "[e2e] Failed to start job" >&2
  docker logs "$CONTAINER_NAME" || true
  exit 1
fi

echo "[e2e] Peek (initial)" >&2
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/peek" \
  -d '{"job_id":"'"$JOB_ID"'","stdout_offset":0,"stderr_offset":0}' | jq .

echo "[e2e] Send partial stdin (no close)" >&2
echo -ne 'hola agente\n' | \
  curl -sS -H "Authorization: Bearer $TOKEN" \
    -X POST "$API/api/v1/jobs/stdin?job_id=$JOB_ID&close=0" --data-binary @- | jq .

echo "[e2e] Logs (offsets 0/0)" >&2
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/logs" \
  -d '{"job_id":"'"$JOB_ID"'","stdout_offset":0,"stderr_offset":0}' | jq .

echo "[e2e] Close stdin" >&2
curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "$API/api/v1/jobs/stdin?job_id=$JOB_ID&close=1" -d '' | jq .

# Give process a moment to exit
sleep 0.5

echo "[e2e] Peek (after close)" >&2
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/peek" \
  -d '{"job_id":"'"$JOB_ID"'","stdout_offset":0,"stderr_offset":0}' | jq .

echo "[e2e] Status" >&2
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/status" \
  -d '{"job_id":"'"$JOB_ID"'"}' | jq .

echo "[e2e] FS write/read UTF-8" >&2
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/fs/write_file" \
  -d '{"path":"/tmp/demo.txt","content":"hola docker\n"}' | jq .

curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/fs/read_file" \
  -d '{"path":"/tmp/demo.txt"}' | jq .

echo "[e2e] Interactive install-like confirmation (read -p)" >&2
JOB2=$(curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/start" \
  -d '{"cmd":"bash","args":["-lc","read -p \"Proceed? [y/N] \" ans; if [ \"$ans\" = \"y\" ]; then echo OK; else echo NO; fi"],"timeout_seconds":60}')
JOB2_ID=$(echo "$JOB2" | jq -r .job_id)
echo "[e2e] JOB2_ID=$JOB2_ID" >&2

curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/peek" \
  -d '{"job_id":"'"$JOB2_ID"'","stdout_offset":0,"stderr_offset":0}' | jq .

echo -ne 'y\n' | \
  curl -sS -H "Authorization: Bearer $TOKEN" \
    -X POST "$API/api/v1/jobs/stdin?job_id=$JOB2_ID&close=0" --data-binary @- | jq .

curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/logs" \
  -d '{"job_id":"'"$JOB2_ID"'","stdout_offset":0,"stderr_offset":0}' | jq .

curl -sS -H "Authorization: Bearer $TOKEN" \
  -X POST "$API/api/v1/jobs/stdin?job_id=$JOB2_ID&close=1" -d '' | jq .

curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/api/v1/jobs/status" \
  -d '{"job_id":"'"$JOB2_ID"'"}' | jq .

echo "[e2e] Done. Stopping container" >&2
docker rm -f "$CONTAINER_NAME" >/dev/null || true
