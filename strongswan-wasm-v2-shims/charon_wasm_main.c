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
#include <plugins/plugin_loader.h>
#include <crypto/key_exchange.h>
#include <sys/stat.h>
#include <sys/types.h>

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

/* Seed MEMFS with the config + token-dir layout both strongSwan and
 * softhsmv3 expect.  On a native install these are written by `make
 * install` and created by `softhsm2-util --init-token`.  In the browser
 * we fabricate them at boot. */
static int write_memfs_conf(void)
{
    /* strongswan.conf for library_init. */
    FILE *f = fopen("/tmp/strongswan.conf", "w");
    if (!f) return -1;
    fputs(WASM_STRONGSWAN_CONF, f);
    fclose(f);

    /* softhsm3.conf — points at an in-MEMFS token directory.  Required
     * because softhsmv3's C_Initialize reads SOFTHSM2_CONF (same env var
     * name the v3 fork kept) to locate the tokens. */
    mkdir("/tmp/softhsm-tokens", 0755);
    f = fopen("/tmp/softhsm.conf", "w");
    if (!f) return -1;
    fputs("directories.tokendir = /tmp/softhsm-tokens\n"
          "objectstore.backend = file\n"
          "log.level = INFO\n", f);
    fclose(f);
    setenv("SOFTHSM2_CONF", "/tmp/softhsm.conf", 1);
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

    /* Load crypto + PKCS#11 plugins.  pem/pkcs1/pkcs8/x509 handle key
     * serialization; openssl provides crypto primitives; pkcs11 wires
     * softhsmv3 through the static dlopen shim. */
    if (!lib->plugins->load(lib->plugins,
            "pem pkcs1 pkcs8 x509 pkcs11 nonce kdf openssl random "
            "constraints revocation")) {
        wasm_vpn_emit("error", "plugin load failed");
        library_deinit();
        return -1;
    }

    g_initialized = 1;
    wasm_vpn_emit("booted", "library_init + plugins loaded");
    return 0;
}

/* ── PKCS#11 probe ─────────────────────────────────────────────────────────
 * Enumerates slots from softhsmv3 via the statically-linked C_GetFunctionList.
 * Returns the slot count or -1 on error. */

EMSCRIPTEN_KEEPALIVE
int wasm_vpn_pkcs11_probe(void)
{
    CK_FUNCTION_LIST *p11 = NULL;
    CK_RV rv = C_GetFunctionList(&p11);
    if (rv != CKR_OK || !p11) {
        wasm_vpn_emit("error", "C_GetFunctionList failed");
        return -1;
    }

    CK_C_INITIALIZE_ARGS args = {
        .CreateMutex  = NULL,
        .DestroyMutex = NULL,
        .LockMutex    = NULL,
        .UnlockMutex  = NULL,
        .flags        = CKF_OS_LOCKING_OK,
        .pReserved    = NULL,
    };
    rv = p11->C_Initialize(&args);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        char msg[64];
        snprintf(msg, sizeof(msg), "C_Initialize rv=0x%lx", (unsigned long)rv);
        wasm_vpn_emit("error", msg);
        return -1;
    }

    CK_ULONG slot_count = 0;
    rv = p11->C_GetSlotList(CK_FALSE, NULL, &slot_count);
    if (rv != CKR_OK) {
        char msg[64];
        snprintf(msg, sizeof(msg), "C_GetSlotList rv=0x%lx", (unsigned long)rv);
        wasm_vpn_emit("error", msg);
        return -1;
    }

    char info[128];
    snprintf(info, sizeof(info), "softhsmv3 reports %lu slot(s)",
             (unsigned long)slot_count);
    wasm_vpn_emit("pkcs11_probe", info);
    return (int)slot_count;
}

/* ── Mechanism list — confirm ML-DSA + ML-KEM are available in WASM ─────── */

/* OIDs match strongswan-pkcs11/pkcs11.h exactly — same fork as the native
 * sandbox, so if the sandbox works these are the values softhsmv3
 * advertises. There is no separate ML-KEM keypair-gen OID in our fork;
 * CKM_ML_KEM covers both keygen and encap (strongswan-pkcs11/pkcs11_kem.c
 * line 247-248). ML-DSA uses a separate keypair-gen mechanism for legacy
 * PKCS#11 template compatibility. */
#define CKM_ML_DSA                 0x0000001DUL
#define CKM_ML_DSA_KEY_PAIR_GEN    0x0000001CUL
#define CKM_ML_KEM                 0x00001058UL

EMSCRIPTEN_KEEPALIVE
int wasm_vpn_list_pqc_mechanisms(void)
{
    CK_FUNCTION_LIST *p11 = NULL;
    if (C_GetFunctionList(&p11) != CKR_OK || !p11) return -1;

    /* Ensure initialized (Phase 2 probe already ran C_Initialize, but be
     * defensive if the caller reuses a fresh session). */
    CK_C_INITIALIZE_ARGS args = { 0 };
    args.flags = CKF_OS_LOCKING_OK;
    (void)p11->C_Initialize(&args);  /* idempotent via CKR_CRYPTOKI_ALREADY_INITIALIZED */

    CK_SLOT_ID slot_id;
    CK_ULONG slot_count = 1;
    if (p11->C_GetSlotList(CK_TRUE, &slot_id, &slot_count) != CKR_OK ||
        slot_count == 0) {
        wasm_vpn_emit("error", "no slots with token present");
        return -1;
    }

    CK_ULONG mech_count = 0;
    p11->C_GetMechanismList(slot_id, NULL, &mech_count);
    if (mech_count == 0) {
        wasm_vpn_emit("error", "token reports zero mechanisms");
        return -1;
    }

    CK_MECHANISM_TYPE *mechs = calloc(mech_count, sizeof(CK_MECHANISM_TYPE));
    if (!mechs) return -1;
    p11->C_GetMechanismList(slot_id, mechs, &mech_count);

    int have_mldsa = 0, have_mldsa_kg = 0, have_mlkem = 0;
    for (CK_ULONG i = 0; i < mech_count; i++) {
        if (mechs[i] == CKM_ML_DSA)              have_mldsa    = 1;
        if (mechs[i] == CKM_ML_DSA_KEY_PAIR_GEN) have_mldsa_kg = 1;
        if (mechs[i] == CKM_ML_KEM)              have_mlkem    = 1;
    }
    free(mechs);

    char info[256];
    snprintf(info, sizeof(info),
             "%lu mechanisms total; ML-DSA=%d (keygen=%d) ML-KEM=%d",
             (unsigned long)mech_count, have_mldsa, have_mldsa_kg, have_mlkem);
    wasm_vpn_emit("mechanisms", info);

    /* Bitmask: bit0 = ML-DSA sign, bit1 = ML-DSA keygen, bit2 = ML-KEM. */
    return (have_mldsa    ? 1 : 0)
         | (have_mldsa_kg ? 2 : 0)
         | (have_mlkem    ? 4 : 0);
}

/* ── ML-DSA-65 sign/verify round-trip via softhsmv3 in WASM ───────────── */

#define CKA_PARAMETER_SET_VAL     0x0000061DUL
#define CKK_ML_DSA_VAL            0x0000004AUL
#define CKP_ML_DSA_65_VAL         0x00000002UL

/* Run the full softhsmv3 PKCS#11 sign/verify sequence entirely within WASM:
 *   C_InitToken → C_InitPIN → C_GenerateKeyPair (ML-DSA-65) → C_SignInit /
 *   C_Sign → C_VerifyInit / C_Verify. Prove the HSM path is exercisable
 *   from the browser before we layer on IKE transport in Phase 3c.
 * Returns the signature length (~3293 B for ML-DSA-65) on success, -1 on err. */
EMSCRIPTEN_KEEPALIVE
int wasm_vpn_ml_dsa_selftest(void)
{
    CK_FUNCTION_LIST *p11 = NULL;
    if (C_GetFunctionList(&p11) != CKR_OK || !p11) return -1;

    CK_C_INITIALIZE_ARGS iargs = { 0 };
    iargs.flags = CKF_OS_LOCKING_OK;
    CK_RV rv = p11->C_Initialize(&iargs);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) return -1;

    CK_SLOT_ID slot_id;
    CK_ULONG   slot_count = 1;
    rv = p11->C_GetSlotList(CK_FALSE, &slot_id, &slot_count);
    if (rv != CKR_OK || slot_count == 0) return -1;

    /* Init token + PINs. Idempotent after first run. */
    const char *so_pin = "1234";
    const char *user_pin = "1234";
    CK_UTF8CHAR label[32];
    memset(label, ' ', sizeof(label));
    memcpy(label, "wasm-selftest", 13);
    p11->C_InitToken(slot_id, (CK_UTF8CHAR_PTR)so_pin, strlen(so_pin), label);

    CK_SESSION_HANDLE so_sess;
    if (p11->C_OpenSession(slot_id,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &so_sess) != CKR_OK)
        return -1;
    p11->C_Login(so_sess, CKU_SO, (CK_UTF8CHAR_PTR)so_pin, strlen(so_pin));
    p11->C_InitPIN(so_sess, (CK_UTF8CHAR_PTR)user_pin, strlen(user_pin));
    p11->C_Logout(so_sess);
    p11->C_CloseSession(so_sess);

    /* Normal user session — generate the ML-DSA keypair. */
    CK_SESSION_HANDLE sess;
    if (p11->C_OpenSession(slot_id,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sess) != CKR_OK)
        return -1;
    if (p11->C_Login(sess, CKU_USER,
                     (CK_UTF8CHAR_PTR)user_pin, strlen(user_pin)) != CKR_OK) {
        wasm_vpn_emit("error", "C_Login(user) failed");
        return -1;
    }

    CK_MECHANISM keygen_mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
    CK_OBJECT_CLASS pubclass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privclass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE ktype = CKK_ML_DSA_VAL;
    CK_ULONG paramset = CKP_ML_DSA_65_VAL;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_CLASS,            &pubclass, sizeof(pubclass) },
        { CKA_KEY_TYPE,         &ktype,    sizeof(ktype)    },
        { CKA_VERIFY,           &ck_true,  sizeof(ck_true)  },
        { CKA_PARAMETER_SET_VAL,&paramset, sizeof(paramset) },
        { CKA_TOKEN,            &ck_false, sizeof(ck_false) },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_CLASS,            &privclass,sizeof(privclass)},
        { CKA_KEY_TYPE,         &ktype,    sizeof(ktype)    },
        { CKA_SIGN,             &ck_true,  sizeof(ck_true)  },
        { CKA_PARAMETER_SET_VAL,&paramset, sizeof(paramset) },
        { CKA_TOKEN,            &ck_false, sizeof(ck_false) },
    };

    CK_OBJECT_HANDLE hpub, hpriv;
    rv = p11->C_GenerateKeyPair(sess, &keygen_mech,
                                pub_tmpl, sizeof(pub_tmpl)/sizeof(pub_tmpl[0]),
                                priv_tmpl, sizeof(priv_tmpl)/sizeof(priv_tmpl[0]),
                                &hpub, &hpriv);
    if (rv != CKR_OK) {
        char m[64]; snprintf(m, sizeof(m), "C_GenerateKeyPair rv=0x%lx", (unsigned long)rv);
        wasm_vpn_emit("error", m);
        return -1;
    }

    /* Sign. */
    const char *msg = "WASM ML-DSA selftest, 32 byte msg.";
    CK_MECHANISM sign_mech = { CKM_ML_DSA, NULL, 0 };
    if (p11->C_SignInit(sess, &sign_mech, hpriv) != CKR_OK) return -1;
    CK_BYTE sig[4096];
    CK_ULONG sig_len = sizeof(sig);
    rv = p11->C_Sign(sess, (CK_BYTE_PTR)msg, strlen(msg), sig, &sig_len);
    if (rv != CKR_OK) {
        char m[64]; snprintf(m, sizeof(m), "C_Sign rv=0x%lx", (unsigned long)rv);
        wasm_vpn_emit("error", m);
        return -1;
    }

    /* Verify. */
    if (p11->C_VerifyInit(sess, &sign_mech, hpub) != CKR_OK) return -1;
    rv = p11->C_Verify(sess, (CK_BYTE_PTR)msg, strlen(msg), sig, sig_len);
    if (rv != CKR_OK) {
        char m[64]; snprintf(m, sizeof(m), "C_Verify rv=0x%lx", (unsigned long)rv);
        wasm_vpn_emit("error", m);
        return -1;
    }

    char info[128];
    snprintf(info, sizeof(info),
             "ML-DSA-65 sign+verify round-trip OK (sig=%lu bytes)",
             (unsigned long)sig_len);
    wasm_vpn_emit("ml_dsa_selftest", info);

    p11->C_Logout(sess);
    p11->C_CloseSession(sess);
    return (int)sig_len;
}

/* ── ML-KEM-768 loopback through softhsmv3 in WASM ─────────────────────
 * Two pkcs11_kem_t instances (alice = initiator, bob = responder) are
 * created from strongSwan's key_exchange factory. Alice generates a
 * keypair, Bob encapsulates against Alice's pubkey, Alice decapsulates
 * Bob's ciphertext. If both derived secrets match, the softhsmv3 ML-KEM
 * path works end-to-end in WASM — same 10-bug-fix code path we
 * committed in pqctoday-hsm 236d9a4 for the native sandbox.
 * Returns 1 on secret match, 0 on mismatch, -1 on any error. */
EMSCRIPTEN_KEEPALIVE
int wasm_vpn_ml_kem_selftest(void)
{
    key_exchange_t *alice = NULL;
    key_exchange_t *bob = NULL;
    chunk_t alice_pub = chunk_empty;
    chunk_t bob_ct = chunk_empty;
    chunk_t alice_secret = chunk_empty;
    chunk_t bob_secret = chunk_empty;
    int result = -1;

    alice = lib->crypto->create_ke(lib->crypto, ML_KEM_768);
    if (!alice) { wasm_vpn_emit("error", "create_ke(alice) failed"); goto out; }

    if (!alice->get_public_key(alice, &alice_pub)) {
        wasm_vpn_emit("error", "alice get_public_key failed"); goto out;
    }

    bob = lib->crypto->create_ke(lib->crypto, ML_KEM_768);
    if (!bob) { wasm_vpn_emit("error", "create_ke(bob) failed"); goto out; }

    if (!bob->set_public_key(bob, alice_pub)) {
        wasm_vpn_emit("error", "bob set_public_key(alice_pub) failed"); goto out;
    }
    if (!bob->get_public_key(bob, &bob_ct)) {
        wasm_vpn_emit("error", "bob get_public_key (=ciphertext) failed"); goto out;
    }
    if (!bob->get_shared_secret(bob, &bob_secret)) {
        wasm_vpn_emit("error", "bob get_shared_secret failed"); goto out;
    }

    if (!alice->set_public_key(alice, bob_ct)) {
        wasm_vpn_emit("error", "alice set_public_key(ciphertext) failed"); goto out;
    }
    if (!alice->get_shared_secret(alice, &alice_secret)) {
        wasm_vpn_emit("error", "alice get_shared_secret failed"); goto out;
    }

    result = chunk_equals(alice_secret, bob_secret) ? 1 : 0;

    char msg[160];
    snprintf(msg, sizeof(msg),
             "ML-KEM-768 loopback: pub=%zu ct=%zu secret=%zu match=%d",
             alice_pub.len, bob_ct.len, alice_secret.len, result);
    wasm_vpn_emit("ml_kem_selftest", msg);

out:
    chunk_free(&alice_pub);
    chunk_free(&bob_ct);
    chunk_free(&alice_secret);
    chunk_free(&bob_secret);
    if (alice) alice->destroy(alice);
    if (bob) bob->destroy(bob);
    return result;
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
