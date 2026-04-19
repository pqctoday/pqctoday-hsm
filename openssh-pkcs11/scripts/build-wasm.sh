#!/usr/bin/env bash
# build-wasm.sh — Emscripten WASM build for the openssh-pkcs11 connector.
#
# Produces two artifacts:
#   dist/openssh-server.{js,wasm}  — sshd single-connection state machine
#   dist/openssh-client.{js,wasm}  — ssh client
#
# Both are statically linked against:
#   - OpenSSL 3.6.x WASM (from pqctoday-hsm deps/ or OPENSSL_WASM env)
#   - softhsmv3 static archive (SOFTHSM_WASM env or built by pqctoday-hsm root)
#
# Prerequisites:
#   emcc 3.x+ in PATH, autoconf, automake, python3
#   OPENSSL_WASM  — path to OpenSSL WASM install prefix (lib/libcrypto.a required)
#   SOFTHSM_WASM  — path to softhsmv3 static archive (libsofthsmv3.a)
#
# Usage (from pqctoday-hsm/ root):
#   bash openssh-pkcs11/scripts/build-wasm.sh
#   SKIP_OPENSSH_FETCH=1 bash openssh-pkcs11/scripts/build-wasm.sh   # reuse existing source

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"      # openssh-pkcs11/
HSM_ROOT="$(cd "$ROOT/.." && pwd)"            # pqctoday-hsm/
OPENSSH_VERSION="V_10_3_P1"
OPENSSH_SRC="$ROOT/build/openssh-src"
OUTPUT_DIR="$ROOT/dist"

# Resolve OpenSSL WASM prefix — default to in-tree pqctoday-hsm build
OPENSSL_WASM="${OPENSSL_WASM:-$HSM_ROOT/deps/openssl-wasm}"
# softhsmv3 static archive
SOFTHSM_WASM="${SOFTHSM_WASM:-$HSM_ROOT/build-wasm/src/lib/libsofthsmv3-static.a}"

if ! command -v emcc &>/dev/null; then
    echo "[openssh-pkcs11] ERROR: emcc not found" >&2; exit 1
fi
echo "[openssh-pkcs11] emcc: $(emcc --version 2>&1 | head -1)"

if [[ ! -f "$OPENSSL_WASM/lib/libcrypto.a" ]]; then
    echo "[openssh-pkcs11] ERROR: $OPENSSL_WASM/lib/libcrypto.a not found" >&2
    echo "  Build it: cd $HSM_ROOT && bash scripts/build-openssl-wasm.sh" >&2
    exit 1
fi
if [[ ! -f "$SOFTHSM_WASM" ]]; then
    echo "[openssh-pkcs11] ERROR: $SOFTHSM_WASM not found" >&2
    echo "  Build it: cd $HSM_ROOT && bash scripts/build-wasm.sh" >&2
    exit 1
fi

# ── Step 1: Fetch + patch OpenSSH source ─────────────────────────────────────
mkdir -p "$ROOT/build"
if [[ "${SKIP_OPENSSH_FETCH:-0}" != "1" || ! -d "$OPENSSH_SRC" ]]; then
    echo "[openssh-pkcs11] Cloning OpenSSH $OPENSSH_VERSION..."
    rm -rf "$OPENSSH_SRC"
    git clone --depth 1 --branch "$OPENSSH_VERSION" \
        https://github.com/openssh/openssh-portable.git "$OPENSSH_SRC"
fi

echo "[openssh-pkcs11] Applying ML-DSA-65 patches (draft-sfluhrer-ssh-mldsa-06)..."
cp "$ROOT/patches/ssh-mldsa.c" "$OPENSSH_SRC/"
(cd "$OPENSSH_SRC" && python3 "$ROOT/patches/apply_mldsa_patches.py")

echo "[openssh-pkcs11] Copying WASM shims..."
cp "$ROOT/wasm-shims/socket_wasm.c"   "$OPENSSH_SRC/"
cp "$ROOT/wasm-shims/pkcs11_static.c" "$OPENSSH_SRC/"
cp "$ROOT/wasm-shims/sshd_wasm_main.c" "$OPENSSH_SRC/"

# ── Step 2: autoconf ──────────────────────────────────────────────────────────
echo "[openssh-pkcs11] Running autoreconf..."
(cd "$OPENSSH_SRC" && autoreconf -i 2>/dev/null)

# ── Step 3: emconfigure ───────────────────────────────────────────────────────
SOFTHSM_INCLUDE="$HSM_ROOT/src/lib"
SOFTHSM_PKCS11_H="$HSM_ROOT/src/lib/pkcs11"

SHARED_LDFLAGS=(
    "-s" "MODULARIZE=1"
    "-s" "ALLOW_MEMORY_GROWTH=1"
    "-s" "SHARED_MEMORY=1"
    "-s" "PTHREAD_POOL_SIZE=2"
    "-s" "INITIAL_MEMORY=67108864"
    "-s" "EXPORTED_RUNTIME_METHODS=['cwrap','ccall','UTF8ToString','stringToUTF8','getValue','setValue']"
    "-s" "ASYNCIFY=1"
    "-s" "ASYNCIFY_IMPORTS=['__wasm_read_sab','__wasm_write_sab']"
    "--no-entry"
)

COMMON_CFLAGS="-O2 -Wno-error -DWASM_OPENSSH -DSOFTHSM_STATIC_LINKED \
    -I${OPENSSL_WASM}/include \
    -I${SOFTHSM_INCLUDE} \
    -I${SOFTHSM_PKCS11_H}"

COMMON_LIBS="${SOFTHSM_WASM} \
    ${OPENSSL_WASM}/lib/libcrypto.a \
    ${OPENSSL_WASM}/lib/libssl.a"

echo "[openssh-pkcs11] Configuring (sshd)..."
mkdir -p "$ROOT/build/sshd-wasm"
(cd "$ROOT/build/sshd-wasm" && \
    emconfigure "$OPENSSH_SRC/configure" \
        --disable-shared --enable-static \
        --with-ssl-dir="$OPENSSL_WASM" \
        --without-pam --without-selinux --without-zlib \
        --without-shadow --without-audit --without-libedit \
        --disable-strip \
        CFLAGS="$COMMON_CFLAGS -DWASM_SSHD_MAIN" \
        LDFLAGS="${SHARED_LDFLAGS[*]} -s EXPORT_NAME=createSshdModule ${COMMON_LIBS}")

echo "[openssh-pkcs11] Configuring (ssh client)..."
mkdir -p "$ROOT/build/ssh-wasm"
(cd "$ROOT/build/ssh-wasm" && \
    emconfigure "$OPENSSH_SRC/configure" \
        --disable-shared --enable-static \
        --with-ssl-dir="$OPENSSL_WASM" \
        --without-pam --without-selinux --without-zlib \
        --without-shadow --without-audit --without-libedit \
        --disable-strip \
        CFLAGS="$COMMON_CFLAGS -DWASM_SSH_CLIENT" \
        LDFLAGS="${SHARED_LDFLAGS[*]} -s EXPORT_NAME=createSshModule ${COMMON_LIBS}")

# ── Step 4: Build ─────────────────────────────────────────────────────────────
NCPU=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo "[openssh-pkcs11] Building sshd WASM with ${NCPU} jobs..."
(cd "$ROOT/build/sshd-wasm" && emmake make -j"$NCPU" sshd)

echo "[openssh-pkcs11] Building ssh WASM with ${NCPU} jobs..."
(cd "$ROOT/build/ssh-wasm" && emmake make -j"$NCPU" ssh)

# ── Step 5: Copy outputs ──────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
cp "$ROOT/build/sshd-wasm/sshd"      "$OUTPUT_DIR/openssh-server.js"
cp "$ROOT/build/sshd-wasm/sshd.wasm" "$OUTPUT_DIR/openssh-server.wasm"
cp "$ROOT/build/ssh-wasm/ssh"        "$OUTPUT_DIR/openssh-client.js"
cp "$ROOT/build/ssh-wasm/ssh.wasm"   "$OUTPUT_DIR/openssh-client.wasm"

echo ""
echo "[openssh-pkcs11] Build complete."
ls -lh "$OUTPUT_DIR/"
echo ""
echo "Copy to hub:  bash openssh-pkcs11/scripts/copy-to-hub.sh"
