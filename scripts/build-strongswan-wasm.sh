#!/bin/bash
# build-strongswan-wasm.sh — End-to-end Emscripten WASM build for strongSwan charon.
#
# ⚠️  STATUS: UNVERIFIED — produces a non-functional WASM binary.
# ⚠️  See ../strongswan-wasm-shims/STATUS.md for details.
# ⚠️  ALWAYS run with SKIP_INSTALL_TO_HUB=1 until Phase 3 rewrite lands.
# ⚠️  Running without the guard will overwrite the working 12 MB baseline
# ⚠️  in pqctoday-hub/public/wasm/strongswan.wasm and break the VPN simulator.
#
# Pipeline:
#   1. Fetch upstream strongSwan 6.0.5 tarball (if not cached)
#   2. Unpack into /tmp/strongswan-build/
#   3. Apply strongswan-6.0.5-pqc.patch (core ML-DSA/ML-KEM enum + SPKI plumbing)
#   4. Regenerate ASN.1 OID tables from patched oid.txt
#   5. Overlay the pqctoday-hsm strongswan-pkcs11 plugin (our adapter)
#   6. Apply strongswan-6.0.5-wasm.patch (Emscripten/WASM plumbing — targets
#      both core strongSwan files AND the just-overlaid pkcs11_library.c)
#   7. Copy strongswan-wasm-shims/*.{c,h} into src/charon/
#   8. autoreconf → emconfigure → emmake
#   9. Copy charon.{js,wasm} to pqctoday-hub/public/wasm/strongswan.{js,wasm}
#
# Prerequisites:
#   - emcc 3.x+ in PATH (Emscripten SDK)
#   - autoreconf, make, curl, tar, bzip2, perl (for oid_maker.pl)
#   - Homebrew Python (for Emscripten's Python 3.10+ requirement on macOS)
#   - Static softhsmv3 library (set SOFTHSM_WASM_LIB to the .a path) —
#     provided as a link-time dependency that exports C_GetFunctionList.
#
# Env overrides:
#   SKIP_FETCH=1          skip tarball fetch/unpack (reuse existing tree)
#   SKIP_INSTALL_TO_HUB=1 don't overwrite the hub's strongswan.{js,wasm}
#                         (useful while iterating — set this whenever the
#                         build is not yet known-good)
#   BUILD_ROOT=...        override /tmp/strongswan-build
#   SOFTHSM_WASM_LIB=...  path to libsofthsmv3.a (or an .o/.bc) with
#                         C_GetFunctionList; defaults to
#                         $HSM_ROOT/build-wasm/src/lib/libsofthsmv3.a
#
# Output (unless SKIP_INSTALL_TO_HUB=1):
#   /Users/ericamador/antigravity/pqctoday-hub/public/wasm/strongswan.js
#   /Users/ericamador/antigravity/pqctoday-hub/public/wasm/strongswan.wasm

set -euo pipefail

# macOS: Emscripten requires Python 3.10+ (uses `match` syntax)
export PATH="/opt/homebrew/bin:$PATH"

HSM_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HUB_WASM_OUT="/Users/ericamador/antigravity/pqctoday-hub/public/wasm"
BUILD_ROOT="${BUILD_ROOT:-/tmp/strongswan-build}"
TARBALL="strongswan-6.0.5.tar.bz2"
TARBALL_URL="https://download.strongswan.org/${TARBALL}"
SRC_DIR="${BUILD_ROOT}/strongswan-6.0.5"
PQC_PATCH="${HSM_ROOT}/strongswan-6.0.5-pqc.patch"
WASM_PATCH="${HSM_ROOT}/strongswan-6.0.5-wasm.patch"
PLUGIN_SRC="${HSM_ROOT}/strongswan-pkcs11"
SHIMS_SRC="${HSM_ROOT}/strongswan-wasm-shims"
SOFTHSM_WASM_LIB="${SOFTHSM_WASM_LIB:-${HSM_ROOT}/build-wasm/src/lib/libsofthsmv3-static.a}"

# Preflight
command -v emcc       >/dev/null || { echo "[build] ERROR: emcc not in PATH — install emsdk" >&2; exit 1; }
command -v autoreconf >/dev/null || { echo "[build] ERROR: autoreconf not in PATH" >&2; exit 1; }
[[ -f "$PQC_PATCH"  ]] || { echo "[build] ERROR: PQC patch not found: $PQC_PATCH"   >&2; exit 1; }
[[ -f "$WASM_PATCH" ]] || { echo "[build] ERROR: WASM patch not found: $WASM_PATCH" >&2; exit 1; }
[[ -d "$PLUGIN_SRC" ]] || { echo "[build] ERROR: plugin source not found: $PLUGIN_SRC" >&2; exit 1; }
[[ -d "$SHIMS_SRC"  ]] || { echo "[build] ERROR: WASM shims not found: $SHIMS_SRC"   >&2; exit 1; }

echo "[build] emcc: $(emcc --version 2>&1 | head -1)"

# 1-2. Fetch + unpack (idempotent). Always rebuild from a pristine tree
#      so patches apply cleanly — wipe any previous unpacked dir.
if [[ "${SKIP_FETCH:-0}" != "1" ]]; then
    mkdir -p "$BUILD_ROOT"
    cd "$BUILD_ROOT"
    if [[ ! -f "$TARBALL" ]]; then
        echo "[build] Downloading $TARBALL_URL..."
        curl -sSfL -o "$TARBALL" "$TARBALL_URL"
    fi
    echo "[build] Wiping previous source tree for a clean rebuild..."
    rm -rf "$SRC_DIR"
    echo "[build] Extracting $TARBALL..."
    tar xjf "$TARBALL"
fi

[[ -d "$SRC_DIR" ]] || { echo "[build] ERROR: source tree missing: $SRC_DIR" >&2; exit 1; }
cd "$SRC_DIR"

# 3. Apply PQC core patch
echo "[build] Applying $PQC_PATCH..."
patch -p1 --no-backup-if-mismatch < "$PQC_PATCH"

# 4. Regenerate ASN.1 OID tables from patched oid.txt
echo "[build] Regenerating ASN.1 OID tables..."
cd src/libstrongswan/asn1
if [[ -f oid_maker.pl ]]; then
    perl oid_maker.pl oid.txt oid.h oid.c
else
    echo "[build] WARNING: oid_maker.pl not found — build will regenerate via make"
fi
cd "$SRC_DIR"

# 5. Overlay pqctoday pkcs11 plugin (must happen before the WASM patch
#    because the WASM patch targets pkcs11_library.c in this tree).
echo "[build] Overlaying pqctoday pkcs11 plugin from $PLUGIN_SRC..."
cp -R "$PLUGIN_SRC"/* src/libstrongswan/plugins/pkcs11/

# 6. Apply WASM patch (core emscripten plumbing + pkcs11_library static-link
#    hooks). Applied AFTER the plugin overlay so its pkcs11_library.c hunks
#    target the pqctoday version that's now in the tree.
echo "[build] Applying $WASM_PATCH..."
patch -p1 --no-backup-if-mismatch < "$WASM_PATCH"

# 7. Copy WASM shim sources into the charon source dir. These are
#    referenced by the Makefile.am hunk in the WASM patch; copying here
#    makes them available at build time.
echo "[build] Copying WASM shims from $SHIMS_SRC into src/charon/..."
cp "$SHIMS_SRC"/socket_wasm.c       src/charon/
cp "$SHIMS_SRC"/socket_wasm.h       src/charon/
cp "$SHIMS_SRC"/wasm_hsm_init.c     src/charon/
cp "$SHIMS_SRC"/wasm_backend.c      src/charon/
cp "$SHIMS_SRC"/pkcs11_wasm_rpc.c   src/charon/

# 8a. autoreconf (Makefile.am changes in our plugin + patch → need
#     regenerated Makefile.in)
echo "[build] Running autoreconf..."
autoreconf -i

# 8b. Emscripten configure — strip everything except charon + pkcs11
echo "[build] Running emconfigure..."
emconfigure ./configure \
    --host=wasm32-unknown-emscripten \
    --disable-shared \
    --enable-static \
    --disable-defaults \
    --enable-charon \
    --enable-monolithic \
    --enable-pkcs11 \
    --enable-nonce \
    --enable-random \
    --enable-sha1 \
    --enable-sha2 \
    --enable-aes \
    --enable-hmac \
    --enable-pem \
    --enable-pkcs1 \
    --enable-pkcs8 \
    --disable-kernel-netlink \
    --disable-socket-default

# 8c. Compile + link
NCPU=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo "[build] Running emmake (-j${NCPU})..."

# Extra link flags:
#  - Link the static softhsmv3 archive for C_GetFunctionList
#  - ALLOW_MEMORY_GROWTH: heap can grow past initial
#  - ALLOW_TABLE_GROWTH: JS can addFunction() pointers (used by worker.js
#    to register C_GetFunctionList for the dlsym fallback path)
#  - ERROR_ON_UNDEFINED_SYMBOLS=0: let env imports (wasm_net_*, pkcs11_*)
#    bind lazily in the worker
#  - EXPORTED_FUNCTIONS: explicitly export every symbol the worker calls
#  - EXPORTED_RUNTIME_METHODS: runtime helpers used by worker.js
EXPORTED_FUNCS='_main,_wasm_set_proposal_mode,_pkcs11_set_rpc_mode,_wasm_hsm_init,_wasm_net_set_sab,_wasm_setup_config,_wasm_initiate,_wasm_get_peer_by_name,_wasm_create_peer_enum,_wasm_create_ike_enum,_socket_wasm_create,_wasm_socket_destroy,_pkcs11_wasm_wrap_function_list,_pkcs11_wasm_rpc_function_list,_C_GetFunctionList,_malloc,_free'
EXPORTED_RUNTIME='stackAlloc,stackSave,stackRestore,addFunction,removeFunction,lengthBytesUTF8,stringToUTF8,UTF8ToString,FS,ENV'

# The softhsm static archive is linked ONLY into the final charon
# executable — not into libstrongswan.la (which emar can't swallow since
# it's an ar archive itself). We append it to charon_LDADD on the make
# command line. softhsmv3 depends on OpenSSL for RAND_bytes / EVP / BIGNUM
# primitives, so libcrypto.a must be linked alongside it — without this,
# C_Initialize aborts at wasm_hsm_init time with "missing function RAND_bytes".
OPENSSL_WASM_LIB_DIR="${OPENSSL_WASM_LIB_DIR:-${HSM_ROOT}/deps/openssl-wasm/lib}"
OPENSSL_CRYPTO_WASM="${OPENSSL_WASM_LIB_DIR}/libcrypto.a"
OPENSSL_SSL_WASM="${OPENSSL_WASM_LIB_DIR}/libssl.a"

CHARON_EXTRA_LDADD=""
if [[ -f "$SOFTHSM_WASM_LIB" ]]; then
    echo "[build] Linking softhsmv3 static lib into charon: $SOFTHSM_WASM_LIB"
    CHARON_EXTRA_LDADD="$SOFTHSM_WASM_LIB"
else
    echo "[build] WARNING: SOFTHSM_WASM_LIB not found ($SOFTHSM_WASM_LIB)"
    echo "[build]          Link step will likely fail with an unresolved"
    echo "[build]          C_GetFunctionList symbol. Build the softhsmv3"
    echo "[build]          WASM target first or set SOFTHSM_WASM_LIB."
fi
if [[ -f "$OPENSSL_CRYPTO_WASM" ]]; then
    echo "[build] Linking libcrypto.a into charon: $OPENSSL_CRYPTO_WASM"
    CHARON_EXTRA_LDADD="$CHARON_EXTRA_LDADD $OPENSSL_CRYPTO_WASM"
    if [[ -f "$OPENSSL_SSL_WASM" ]]; then
        CHARON_EXTRA_LDADD="$CHARON_EXTRA_LDADD $OPENSSL_SSL_WASM"
    fi
else
    echo "[build] WARNING: libcrypto.a not found ($OPENSSL_CRYPTO_WASM)"
    echo "[build]          charon will abort at C_Initialize (missing RAND_bytes)."
    echo "[build]          Run pqctoday-hsm/scripts/build-openssl-wasm.sh first."
fi

# LDFLAGS here apply to ALL link steps (libraries + charon). Library
# link steps use emar — Emscripten flags like -s ALLOW_MEMORY_GROWTH
# are ignored by emar so they're safe. EXPORTED_FUNCTIONS etc. only
# take effect on final-executable links.
LINK_FLAGS="-s ALLOW_MEMORY_GROWTH=1 \
    -s ALLOW_TABLE_GROWTH=1 \
    -s ERROR_ON_UNDEFINED_SYMBOLS=0 \
    -s EXPORTED_FUNCTIONS=[${EXPORTED_FUNCS}] \
    -s EXPORTED_RUNTIME_METHODS=[${EXPORTED_RUNTIME}] \
    -s INITIAL_MEMORY=67108864 \
    -s STACK_SIZE=5242880 \
    -s MODULARIZE=0 \
    -s ASSERTIONS=1 \
    -fexceptions \
    -s NO_DISABLE_EXCEPTION_CATCHING=1"

emmake make -j"$NCPU" \
    LDFLAGS="$LINK_FLAGS" \
    charon_LDADD="\$(top_builddir)/src/libstrongswan/libstrongswan.la \$(top_builddir)/src/libcharon/libcharon.la -lm \$(PTHREADLIB) \$(ATOMICLIB) \$(DLLIB) $CHARON_EXTRA_LDADD" \
    || { echo "[build] emmake failed — see /tmp/wasm-build.log"; exit 1; }

# 9. Copy outputs to hub (unless guarded)
CHARON_JS="src/charon/charon"
CHARON_WASM="src/charon/charon.wasm"
[[ -f "$CHARON_JS"   ]] || CHARON_JS="src/charon/charon.js"
[[ -f "$CHARON_JS"   ]] || { echo "[build] ERROR: $CHARON_JS not found"   >&2; exit 1; }
[[ -f "$CHARON_WASM" ]] || { echo "[build] ERROR: $CHARON_WASM not found" >&2; exit 1; }

echo "[build] Built: $CHARON_JS ($(stat -f%z "$CHARON_JS" 2>/dev/null || stat -c%s "$CHARON_JS") bytes)"
echo "[build] Built: $CHARON_WASM ($(stat -f%z "$CHARON_WASM" 2>/dev/null || stat -c%s "$CHARON_WASM") bytes)"

if [[ "${SKIP_INSTALL_TO_HUB:-0}" != "1" ]]; then
    echo "[build] Copying charon WASM artifacts to ${HUB_WASM_OUT}..."
    mkdir -p "$HUB_WASM_OUT"
    cp "$CHARON_JS"   "$HUB_WASM_OUT/strongswan.js"
    cp "$CHARON_WASM" "$HUB_WASM_OUT/strongswan.wasm"
    ls -lh "$HUB_WASM_OUT/strongswan.js" "$HUB_WASM_OUT/strongswan.wasm"
else
    echo "[build] SKIP_INSTALL_TO_HUB=1 — not overwriting baseline hub artifacts."
fi

echo "[build] Done."
