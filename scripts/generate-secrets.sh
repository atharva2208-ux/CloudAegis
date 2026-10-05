#!/usr/bin/env bash
# Print fresh values for SECRET_KEY and CREDENTIAL_ENCRYPTION_KEY.
set -euo pipefail
python3 - <<'PY'
import base64, secrets
print(f"SECRET_KEY={secrets.token_urlsafe(48)}")
print(f"CREDENTIAL_ENCRYPTION_KEY={base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}")
PY
