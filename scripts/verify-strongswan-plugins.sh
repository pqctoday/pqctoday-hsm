#!/usr/bin/env bash
# Verify that the strongSwan WASM artifact links every plugin the hub's
# strongswan.conf asks for at runtime. A missing plugin here means charon
# silently ignores it during plugin load and the IKE handshake stalls with
# no obvious diagnostic.
#
# Usage:
#   scripts/verify-strongswan-plugins.sh [path/to/strongswan-v2.wasm]
#
# Default path: build-strongswan-wasm-v2/dist/strongswan-v2.wasm
set -eu

WASM_PATH="${1:-build-strongswan-wasm-v2/dist/strongswan-v2.wasm}"
if [[ ! -f "$WASM_PATH" ]]; then
    echo "[verify] WASM artifact not found at $WASM_PATH" >&2
    echo "[verify] run scripts/build-strongswan-wasm-v2.sh first" >&2
    exit 2
fi

if ! command -v wasm-objdump >/dev/null 2>&1; then
    echo "[verify] wasm-objdump not in PATH (install via 'brew install wabt' or apt)" >&2
    exit 2
fi

# This list MUST match charon_wasm_main.c WASM_CHARON_PLUGINS and the hub's
# panel buildCharonConf pluginList. Update all three together.
REQUIRED_PLUGINS=(
    pem pkcs1 pkcs8 x509 pkcs11 nonce kdf openssl
    random constraints revocation socket-default
)

dump=$(wasm-objdump -x "$WASM_PATH")
missing=()
for p in "${REQUIRED_PLUGINS[@]}"; do
    if ! grep -q "${p//-/_}_plugin_create" <<<"$dump"; then
        missing+=("$p")
    fi
done

if (( ${#missing[@]} > 0 )); then
    echo "[verify] FAIL — missing plugins: ${missing[*]}" >&2
    echo "[verify] Add the matching --enable-* flag(s) to scripts/build-strongswan-wasm-v2.sh and rebuild." >&2
    exit 1
fi

echo "[verify] OK — all ${#REQUIRED_PLUGINS[@]} required plugins present in $(basename "$WASM_PATH")"
