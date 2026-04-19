/*
 * charon_wasm_main.c — strongSwan charon entry point for the WASM build.
 *
 * Replaces the upstream src/charon/charon.c main() entirely.  The upstream
 * main:
 *   - forks into a daemon (no fork in WASM),
 *   - sets uid/capabilities (not applicable),
 *   - installs kernel-netlink / kernel-pfkey IPsec plugins (no kernel),
 *   - runs a multi-threaded dispatcher pool (no pthreads in our build).
 *
 * Our replacement, guarded by -DWASM_CHARON_MAIN:
 *   1. library_init() with the WASM-safe plugin list.
 *   2. Accept a JSON config blob from JS via wasm_vpn_configure_json().
 *   3. On wasm_vpn_initiate() — kick off a single IKE_SA_INIT + IKE_AUTH
 *      exchange as INITIATOR or RESPONDER, depending on the config.
 *   4. Emit events back to JS as the handshake progresses (via Module hooks).
 *   5. Clean up on wasm_vpn_shutdown().
 *
 * Single-threaded.  All blocking reads (socket, ATOMIC barriers) are
 * transparently unwound by Emscripten ASYNCIFY.
 *
 * This file is NOT compiled when CHARON native main is linked; see
 * build-strongswan-wasm-v2.sh for the link-line (charon.c is excluded).
 */

#ifdef WASM_CHARON_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emscripten.h>

#include <library.h>
#include <utils/debug.h>

/* softhsmv3 static entry point — resolved by pkcs11_static.c's dlsym shim */
#include "pkcs11.h"
extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);

/* ── JS event emitter ─────────────────────────────────────────────────────── */
EM_JS(void, wasm_vpn_emit, (const char *type, const char *payload), {
    if (typeof Module.onVpnEvent === 'function') {
        Module.onVpnEvent(UTF8ToString(type), UTF8ToString(payload));
    }
});

/* ── Minimal plugin list for IKEv2 + PKCS#11 + softhsmv3 ──────────────────── */
static const char *WASM_CHARON_PLUGINS =
    "charon pem pkcs1 pkcs8 x509 pkcs11 nonce kdf openssl random "
    "constraints revocation socket-default";

/* In-memory strongswan.conf content injected at init time.  `threads = 1`
 * keeps charon single-threaded; no kernel-ipsec plugin (WASM has no kernel). */
static const char *WASM_STRONGSWAN_CONF =
    "charon {\n"
    "  threads = 1\n"
    "  install_routes = no\n"
    "  install_virtual_ip = no\n"
    "  load = pem pkcs1 pkcs8 x509 pkcs11 nonce kdf openssl random "
    "         constraints revocation socket-default\n"
    "  plugins {\n"
    "    pkcs11 {\n"
    "      load_certs = no\n"
    "      use_pubkey = yes\n"
    "      use_dh = yes\n"
    "      use_ecc = yes\n"
    "      modules {\n"
    "        softhsm {\n"
    "          path = /wasm/libsofthsmv3-static  # resolved by pkcs11_static.c\n"
    "          load_certs = no\n"
    "        }\n"
    "      }\n"
    "    }\n"
    "  }\n"
    "}\n";

static int g_initialized = 0;

/* ── Exported: lifecycle ──────────────────────────────────────────────────── */

/* Write a minimal strongswan.conf to MEMFS at /tmp/strongswan.conf so
 * library_init has something to parse instead of erroring on the missing
 * compile-time default path.  This is the in-browser equivalent of the
 * install-step `make install` writes in a native build. */
static int write_memfs_conf(void)
{
    FILE *f = fopen("/tmp/strongswan.conf", "w");
    if (!f) return -1;
    fputs(WASM_STRONGSWAN_CONF, f);
    fclose(f);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int wasm_vpn_boot(void)
{
    if (g_initialized) {
        wasm_vpn_emit("warning", "already booted");
        return 0;
    }

    if (write_memfs_conf() != 0) {
        wasm_vpn_emit("error", "failed to write /tmp/strongswan.conf");
        return -1;
    }

    /* Pass the MEMFS path explicitly — NULL would use the compile-time
     * default which doesn't exist in the browser. */
    if (!library_init("/tmp/strongswan.conf", "strongswan-wasm-v2")) {
        wasm_vpn_emit("error", "library_init failed");
        library_deinit();
        return -1;
    }

    g_initialized = 1;
    wasm_vpn_emit("booted", "library_init succeeded");
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int wasm_vpn_shutdown(void)
{
    if (!g_initialized) return 0;
    library_deinit();
    g_initialized = 0;
    wasm_vpn_emit("shutdown", "library_deinit complete");
    return 0;
}

/* ── Exported: handshake (stubs for Phase 1; filled in Phase 3+) ───────────── */

EMSCRIPTEN_KEEPALIVE
int wasm_vpn_configure_json(const char *json)
{
    (void)json;
    /* TODO Phase 3: parse config, seed PKCS#11 keypair, write strongswan.conf
     * to MEMFS at /etc/strongswan.d/, initialize charon daemon, register peer
     * config via vici-internal API. */
    wasm_vpn_emit("configure_stub", "phase3 TODO");
    return 0;
}

EMSCRIPTEN_KEEPALIVE
int wasm_vpn_initiate(void)
{
    /* TODO Phase 3: drive the handshake state machine. */
    wasm_vpn_emit("initiate_stub", "phase3 TODO");
    return 0;
}

EMSCRIPTEN_KEEPALIVE
const char *wasm_vpn_get_result(void)
{
    /* TODO Phase 3: return JSON with handshake_established, timings, sizes. */
    return "{\"phase\":\"boot\",\"status\":\"stub\"}";
}

/* ── Satisfy the linker — Emscripten always calls main() ──────────────────── */

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;
    wasm_vpn_emit("main", "strongswan-wasm-v2 loaded; awaiting JS driver");
    /* Keep runtime alive so exported functions remain callable. */
    emscripten_exit_with_live_runtime();
    return 0;
}

#endif /* WASM_CHARON_MAIN */
