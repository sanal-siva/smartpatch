#!/usr/bin/env bash
# Prepare an isolated service, credentials directory and TLS certificate; never listen.
set -euo pipefail
umask 077
SMART_PATCH_PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$SMART_PATCH_PROJECT_DIR"
SMART_PATCH_VENV_DIR=${SMART_PATCH_VENV_DIR:-"$SMART_PATCH_PROJECT_DIR/.venv"}
SMART_PATCH_STATE_DIR=${SMART_PATCH_STATE_DIR:-"$SMART_PATCH_PROJECT_DIR/.state"}
SMART_PATCH_BIND_HOST=${SMART_PATCH_BIND_HOST:-100.104.17.32}
SMART_PATCH_BIND_PORT=${SMART_PATCH_BIND_PORT:-8000}
[[ "${1:-}" == '--skip-scanner' || $# == 0 ]] || { echo 'Usage: scripts/prepare-local.sh [--skip-scanner]' >&2; exit 2; }
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ is required"'
python3 -m venv "$SMART_PATCH_VENV_DIR"
"$SMART_PATCH_VENV_DIR/bin/python" -m pip install --disable-pip-version-check -r requirements.lock
"$SMART_PATCH_VENV_DIR/bin/python" -m pip install --disable-pip-version-check --no-deps .
mkdir -p "$SMART_PATCH_STATE_DIR/tls" "$SMART_PATCH_STATE_DIR/grype-db"
chmod 700 "$SMART_PATCH_STATE_DIR" "$SMART_PATCH_STATE_DIR/tls"
if [[ "${1:-}" != '--skip-scanner' ]]; then
  "$SMART_PATCH_PROJECT_DIR/scripts/install-scanner.sh" "$SMART_PATCH_PROJECT_DIR/.tools"
fi
if [[ ! -e "$SMART_PATCH_STATE_DIR/tls/service.key" && ! -e "$SMART_PATCH_STATE_DIR/tls/service.crt" ]]; then
  python3 - "$SMART_PATCH_BIND_HOST" <<'PY'
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
PY
  if [[ ! -e "$SMART_PATCH_STATE_DIR/tls/ca.key" && ! -e "$SMART_PATCH_STATE_DIR/tls/ca.crt" ]]; then
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
      -keyout "$SMART_PATCH_STATE_DIR/tls/ca.key" -out "$SMART_PATCH_STATE_DIR/tls/ca.crt" \
      -subj '/CN=SONiC Smart Patch local deployment CA' \
      -addext 'basicConstraints=critical,CA:TRUE' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
  fi
  [[ -s "$SMART_PATCH_STATE_DIR/tls/ca.key" && -s "$SMART_PATCH_STATE_DIR/tls/ca.crt" ]] || { echo 'Existing CA key/certificate pair is incomplete.' >&2; exit 1; }
  openssl req -new -newkey rsa:3072 -sha256 -nodes \
    -keyout "$SMART_PATCH_STATE_DIR/tls/service.key" -out "$SMART_PATCH_STATE_DIR/tls/service.csr" \
    -subj '/CN=SONiC Smart Patch hackathon service' >/dev/null 2>&1
  printf 'subjectAltName=IP:%s,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$SMART_PATCH_BIND_HOST" > "$SMART_PATCH_STATE_DIR/tls/server-extensions.cnf"
  openssl x509 -req -sha256 -days 30 -in "$SMART_PATCH_STATE_DIR/tls/service.csr" \
    -CA "$SMART_PATCH_STATE_DIR/tls/ca.crt" -CAkey "$SMART_PATCH_STATE_DIR/tls/ca.key" -CAcreateserial \
    -extfile "$SMART_PATCH_STATE_DIR/tls/server-extensions.cnf" -out "$SMART_PATCH_STATE_DIR/tls/service.crt" >/dev/null 2>&1
  rm "$SMART_PATCH_STATE_DIR/tls/service.csr"
  chmod 600 "$SMART_PATCH_STATE_DIR/tls/ca.key"
  chmod 644 "$SMART_PATCH_STATE_DIR/tls/ca.crt"
fi
[[ -s "$SMART_PATCH_STATE_DIR/tls/service.key" && -s "$SMART_PATCH_STATE_DIR/tls/service.crt" ]] || { echo 'Both TLS key and certificate must exist.' >&2; exit 1; }
chmod 600 "$SMART_PATCH_STATE_DIR/tls/service.key"
chmod 644 "$SMART_PATCH_STATE_DIR/tls/service.crt"
if [[ ! -e .env ]]; then
  "$SMART_PATCH_VENV_DIR/bin/python" - "$SMART_PATCH_PROJECT_DIR" "$SMART_PATCH_STATE_DIR" "$SMART_PATCH_BIND_HOST" "$SMART_PATCH_BIND_PORT" <<'PY'
import json, os, pathlib, sys
project, state, host, port = sys.argv[1:]
values = dict(HOST=host, PORT=port, STATE_DIR=state,
 DATABASE_URL='sqlite:///'+str(pathlib.Path(state)/'smart_patch.db'),
 TLS_CERT=str(pathlib.Path(state)/'tls/service.crt'), TLS_KEY=str(pathlib.Path(state)/'tls/service.key'),
 SCANNER_BINARY=str(pathlib.Path(project)/'.tools/grype'), SCANNER_DB_DIR=str(pathlib.Path(state)/'grype-db'),
 WORKER_COUNT='1', JOBS_ENABLED='true', AI_ENABLED='false', SOURCE_ROOTS='[]')
fd=os.open('.env', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
 for key, value in values.items(): output.write(key+'='+json.dumps(value)+'\n')
PY
else
  echo 'Existing .env preserved. Verify its bind address, TLS paths and state directory.'
fi
printf 'Prepared service in %s\nTLS certificate: %s\nStart explicitly with scripts/start-local.sh.\n' "$SMART_PATCH_PROJECT_DIR" "$SMART_PATCH_STATE_DIR/tls/service.crt"
