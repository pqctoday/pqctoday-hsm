#!/usr/bin/env bash
# copy-to-hub.sh — Copy WASM artifacts to pqctoday-hub public/wasm/
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"      # openssh-pkcs11/
HSM_ROOT="$(cd "$ROOT/.." && pwd)"            # pqctoday-hsm/
HUB="${HUB:-$HSM_ROOT/../pqctoday-hub}"
DEST="$HUB/public/wasm"

for f in openssh-server.js openssh-server.wasm openssh-client.js openssh-client.wasm; do
    src="$ROOT/dist/$f"
    if [[ ! -f "$src" ]]; then
        echo "ERROR: $src not found — run build-wasm.sh first" >&2; exit 1
    fi
    cp "$src" "$DEST/$f"
    echo "copied $f → $DEST/"
done

echo "Done. Rebuild hub with: cd $HUB && npm run build"
