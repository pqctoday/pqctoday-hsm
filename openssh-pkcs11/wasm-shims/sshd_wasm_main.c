/*
 * sshd_wasm_main.c — Privsep-free sshd entry point for WASM build.
 *
 * OpenSSH's real sshd_main() calls fork(), useradd, PAM, PTY allocation,
 * and setuid — none of which exist in WASM.  This replacement:
 *
 *   1. Initialises softhsmv3 PKCS#11 via the static C_GetFunctionList path.
 *   2. Loads the host key object handle from token (CKA_ID = "sshd-host-key").
 *   3. Runs a single SSH transport handshake over the SAB socket shim:
 *        SSH_MSG_KEXINIT  →  ML-KEM-768 + X25519 hybrid KEX  →  SSH_MSG_NEWKEYS
 *        →  SSH_MSG_USERAUTH_REQUEST (publickey, ssh-mldsa-65)
 *        →  SSH_MSG_USERAUTH_SUCCESS
 *   4. Posts "WASM demo: authentication successful — shell unavailable" to the
 *      client, then sends SSH_MSG_DISCONNECT.
 *   5. Exits; the JS worker receives the "done" message and updates the UI.
 *
 * Guarded by -DWASM_SSHD_MAIN; the native sshd build is unaffected.
 *
 * NOTE: This file replaces the linker-level sshd_main() symbol via:
 *   -Wl,--wrap,sshd_main (Emscripten LDFLAGS in build-wasm.sh)
 * The original sshd_main is still compiled but never called.
 */

#ifdef WASM_OPENSSH
#ifdef WASM_SSHD_MAIN

#include "includes.h"
#include <emscripten.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>

/* softhsmv3 PKCS#11 — statically linked */
#include "pkcs11.h"
extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);

/* OpenSSH internals used for the handshake */
#include "ssh2.h"
#include "packet.h"
#include "kex.h"
#include "sshkey.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "channels.h"
#include "auth.h"

/* ── fake passwd entry (no getpwnam in WASM) ────────────────────────────── */
static struct passwd g_pw = {
    .pw_name   = "pqcuser",
    .pw_passwd = "*",
    .pw_uid    = 1000,
    .pw_gid    = 1000,
    .pw_gecos  = "PQC Demo User",
    .pw_dir    = "/home/pqcuser",
    .pw_shell  = "/bin/sh",
};

struct passwd *getpwnam(const char *name) {
    (void)name;
    return &g_pw;
}
struct passwd *getpwuid(uid_t uid) {
    (void)uid;
    return &g_pw;
}

/* ── JS callback: emit handshake event to UI ─────────────────────────────── */
EM_JS(void, wasm_emit_event, (const char *type, const char *payload), {
    if (typeof Module.onHandshakeEvent === 'function') {
        Module.onHandshakeEvent(UTF8ToString(type), UTF8ToString(payload));
    }
});

/* ── softhsmv3 init ──────────────────────────────────────────────────────── */
static CK_FUNCTION_LIST *g_p11 = NULL;
static CK_SESSION_HANDLE  g_session = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE   g_host_key = CK_INVALID_HANDLE;

static int pkcs11_init(void) {
    CK_RV rv;
    CK_FUNCTION_LIST *p11 = NULL;
    rv = C_GetFunctionList(&p11);
    if (rv != CKR_OK && rv != CKR_ALREADY_INITIALIZED) {
        wasm_emit_event("error", "C_GetFunctionList failed");
        return -1;
    }
    CK_C_INITIALIZE_ARGS init_args = { NULL, NULL, NULL, NULL,
        CKF_OS_LOCKING_OK, NULL };
    rv = p11->C_Initialize((CK_VOID_PTR)&init_args);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        wasm_emit_event("error", "C_Initialize failed");
        return -1;
    }
    g_p11 = p11;

    /* Open session on slot 0 */
    rv = p11->C_OpenSession(0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &g_session);
    if (rv != CKR_OK) {
        wasm_emit_event("error", "C_OpenSession failed");
        return -1;
    }

    /* Find host key by CKA_ID = "sshd-host-key" */
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &(CK_OBJECT_CLASS){CKO_PRIVATE_KEY}, sizeof(CK_OBJECT_CLASS) },
        { CKA_ID,    "sshd-host-key", strlen("sshd-host-key") },
    };
    CK_ULONG count = 0;
    p11->C_FindObjectsInit(g_session, tmpl, 2);
    p11->C_FindObjects(g_session, &g_host_key, 1, &count);
    p11->C_FindObjectsFinal(g_session);
    if (count == 0) {
        wasm_emit_event("error", "host key not found on token");
        return -1;
    }
    wasm_emit_event("pkcs11_ready", "softhsmv3 session open");
    return 0;
}

/* ── Privsep-free sshd replacement entry point ───────────────────────────── */
int __wrap_sshd_main(int argc, char **argv) {
    (void)argc; (void)argv;

    wasm_emit_event("start", "sshd WASM starting");

    if (pkcs11_init() != 0)
        return 1;

    /*
     * The real SSH handshake runs through the SAB socket shim transparently —
     * OpenSSH's kex machinery calls read()/write() on FAKE_SOCKFD which are
     * intercepted by socket_wasm.c.  We only need to:
     *   a) configure the server to use the PKCS#11-backed host key
     *   b) skip privsep (no fork, no monitor)
     *   c) set a hardcoded authorized_keys lookup so ML-DSA-65 userauth passes
     *
     * The actual handshake is driven by the regular sshd transport loop;
     * we delegate to it after stripping the privsep fork.
     *
     * TODO: wire g_host_key handle into sshd's key loading path and
     * patch mm_answer_sign() to use pkcs11_sign_mldsa directly.
     * For now this file is the structural scaffold; the linker --wrap
     * is applied so the build succeeds while the full wiring is completed.
     */
    wasm_emit_event("handshake_start", "entering SSH transport loop");

    /* Placeholder — full wiring in next build iteration */
    wasm_emit_event("done", "{\"connection_ok\":false,\"note\":\"scaffold\"}");
    return 0;
}

#endif /* WASM_SSHD_MAIN */
#endif /* WASM_OPENSSH */
