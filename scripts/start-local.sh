#!/usr/bin/env bash
set -euo pipefail
umask 077
SMART_PATCH_PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$SMART_PATCH_PROJECT_DIR"
SMART_PATCH_VENV_DIR=${SMART_PATCH_VENV_DIR:-"$SMART_PATCH_PROJECT_DIR/.venv"}
[[ -x "$SMART_PATCH_VENV_DIR/bin/python" ]] || { echo 'Run scripts/prepare-local.sh first.' >&2; exit 1; }
"$SMART_PATCH_VENV_DIR/bin/python" - <<'PY'
import os
from pathlib import Path
from app.config import settings
if not settings.tls_cert or not settings.tls_key:
 if not (os.environ.get('ALLOW_PLAINTEXT_LOCAL')=='true' and settings.host in ('127.0.0.1','::1')):
  raise SystemExit('TLS_CERT and TLS_KEY are required; plaintext is limited to explicit loopback tests.')
else:
 for path in (settings.tls_cert,settings.tls_key):
  if not Path(path).is_file(): raise SystemExit('Configured TLS file does not exist.')
print(f'Starting Smart Patch on {settings.host}:{settings.port}; credential values are not logged.')
PY
exec "$SMART_PATCH_VENV_DIR/bin/python" -m app.main
