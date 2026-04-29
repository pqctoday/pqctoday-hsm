/*
 * wasm_backend.c — C-level config backend for the strongSwan WASM build.
 *
 * In a normal charon deployment the backend (stroke / vici / swanctl)
 * feeds IKE and peer configs to the daemon. The WASM build has no unix
 * socket — so JS injects a strongswan.conf *and* this C shim exposes:
 *
 *   wasm_setup_config(mode)        : pre-registers default IKE/peer cfgs
 *                                    + PSK credentials (read from env
 *                                    WASM_PSK). Called once from
 *                                    libcharon's _main() under
 *                                    __EMSCRIPTEN__ guards.
 *
 *   wasm_get_peer_by_name(this,n)  : backend_t::get_peer_cfg_by_name
 *   wasm_create_peer_enum(this,...)  : backend_t::create_peer_cfg_enumerator
 *   wasm_create_ike_enum (this,...)  : backend_t::create_ike_cfg_enumerator
 *
 *   wasm_set_proposal_mode(mode)   : 0 = classical (AES/ECP256)
 *                                    1 = pure PQC  (ML-KEM-768)
 *                                    2 = hybrid    (ML-KEM-768 + ECP256)
 *
 *   wasm_set_auth_mode(mode)       : 0 = PSK (default)
 *                                    1 = PUBKEY (ML-DSA cert auth)
 *
 *   wasm_initiate()                : kick off IKE_SA_INIT for the
 *                                    "charon-initiator" peer_cfg.
 *
 * Signatures match the baseline WASM exports exactly (see Appendix B of
 * the task brief).
 */

#ifdef __EMSCRIPTEN__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <daemon.h>
#include <library.h>
#include <utils/debug.h>
#include <config/backend.h>
#include <config/peer_cfg.h>
#include <config/ike_cfg.h>
#include <config/child_cfg.h>
#include <collections/linked_list.h>
#include <collections/enumerator.h>
#include <credentials/auth_cfg.h>
#include <credentials/sets/mem_cred.h>

/* PKCS#11 types for the WASM-DIAG block at the end of wasm_setup_config. */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(rt, n)         rt n
#define CK_DECLARE_FUNCTION_POINTER(rt, n) rt (* n)
#define CK_CALLBACK_FUNCTION(rt, n)        rt (* n)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"

/*─────────────────────────────────────────────────────────────────────*/
/* Globals                                                             */
/*─────────────────────────────────────────────────────────────────────*/

/* Proposal-selection mode (0=classical, 1=pure-pqc, 2=hybrid). Read by
 * wasm_setup_config() to pick which proposal strings to bake into the
 * IKE cfg. */
int wasm_proposal_mode = 0;

void wasm_set_proposal_mode(int mode)
{
    wasm_proposal_mode = mode;
}

/* Auth-class mode: 0 = PSK (default), 1 = PUBKEY (ML-DSA cert).
 * Set via wasm_set_auth_mode() before _main() is called. When 1,
 * wasm_setup_config() uses AUTH_CLASS_PUBKEY and loads the local cert
 * from the worker FS (written by the panel's generateCertsViaWorker). */
int wasm_auth_mode = 0;

void wasm_set_auth_mode(int mode)
{
    wasm_auth_mode = mode;
}

/* Linked list of peer_cfg_t owned by this backend. */
static linked_list_t *peer_cfgs = NULL;

/* Backend singleton. */
typedef struct {
    backend_t public;
} wasm_backend_t;
static wasm_backend_t *wasm_backend = NULL;

/*─────────────────────────────────────────────────────────────────────*/
/* backend_t vtable                                                    */
/*─────────────────────────────────────────────────────────────────────*/

peer_cfg_t *wasm_get_peer_by_name(backend_t *this, char *name)
{
    enumerator_t *e;
    peer_cfg_t *cfg, *found = NULL;

    if (!peer_cfgs || !name) return NULL;
    e = peer_cfgs->create_enumerator(peer_cfgs);
    while (e->enumerate(e, &cfg))
    {
        if (streq(cfg->get_name(cfg), name))
        {
            found = cfg->get_ref(cfg);
            break;
        }
    }
    e->destroy(e);
    return found;
}

enumerator_t *wasm_create_peer_enum(backend_t *this,
                                    identification_t *me,
                                    identification_t *other)
{
    if (!peer_cfgs) return enumerator_create_empty();
    return peer_cfgs->create_enumerator(peer_cfgs);
}

CALLBACK(ike_cfg_filter, bool,
    void *data, enumerator_t *orig, va_list args)
{
    peer_cfg_t *peer_cfg;
    ike_cfg_t **out;

    VA_ARGS_VGET(args, out);

    while (orig->enumerate(orig, &peer_cfg))
    {
        *out = peer_cfg->get_ike_cfg(peer_cfg);
        return TRUE;
    }
    return FALSE;
}

enumerator_t *wasm_create_ike_enum(backend_t *this,
                                   host_t *me, host_t *other)
{
    /* find_ike_cfg() (config/backends/backend_manager.c) drives this on
     * the responder when an IKE_SA_INIT request arrives — no peer_cfg has
     * been chosen yet because IDs only show up in IKE_AUTH, so charon
     * picks the ike_cfg first by host match (me/other vs the cfg's
     * local/remote), then negotiates proposals from it.
     *
     * Earlier this returned enumerator_create_empty() with a comment
     * claiming "the responder branch is driven by peer_cfgs directly" —
     * that's wrong. With no ike_cfg returned here, find_ike_cfg fails
     * even when peer_cfgs is populated, the responder logs
     * "no IKE config found for 192.168.0.2...192.168.0.1" and replies
     * NO_PROPOSAL_CHOSEN.
     *
     * Project each peer_cfg to its ike_cfg via enumerator_create_filter
     * — same pattern as pkcs11_creds.c::certs_filter. The me/other args
     * are unused here; charon's backend_manager handles host-match
     * filtering after we return the candidates. */
    if (!peer_cfgs) return enumerator_create_empty();
    return enumerator_create_filter(
        peer_cfgs->create_enumerator(peer_cfgs),
        ike_cfg_filter, NULL, NULL);
}

/*─────────────────────────────────────────────────────────────────────*/
/* wasm_setup_config — builds default peer + IKE cfgs from env vars    */
/*─────────────────────────────────────────────────────────────────────*/

static const char *proposal_ike_classical = "aes256-sha256-ecp256";
static const char *proposal_ike_pqc       = "aes256-sha256-mlkem768";
static const char *proposal_ike_hybrid    = "aes256-sha256-mlkem768-ecp256";
static const char *proposal_esp           = "aes256-sha256";

void wasm_setup_config(int unused)
{
    peer_cfg_t *peer_cfg;
    ike_cfg_t *ike_cfg;
    child_cfg_t *child_cfg;
    auth_cfg_t *auth_local, *auth_remote;
    peer_cfg_create_t peer_data;
    ike_cfg_create_t  ike_data;
    child_cfg_create_t child_data;
    const char *ike_prop;
    const char *psk_env;
    mem_cred_t *creds;
    certificate_t *my_cert = NULL;

    /* WASM-DIAG (always-on, runs first): probe in-process softhsm for
     * worker-provisioned ML-DSA pubkeys via the same no-login public RO
     * session lookup that strongswan-pkcs11's find_lib_by_keyid uses at
     * IKE_AUTH. Use fprintf(stderr) which Emscripten routes to console.error,
     * bypassing libstrongswan's logger initialisation order in case DBG1
     * isn't ready yet at this point in _main. */
    fprintf(stderr, "WASM-DIAG: entering wasm_setup_config auth_mode=%d role=%s\n",
            wasm_auth_mode, getenv("WASM_ROLE") ? getenv("WASM_ROLE") : "?");
    fflush(stderr);
    {
        extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);
        CK_FUNCTION_LIST_PTR fl = NULL;
        CK_RV rv = C_GetFunctionList(&fl);
        if (rv != CKR_OK || !fl)
        {
            fprintf(stderr, "WASM-DIAG: C_GetFunctionList failed: 0x%lx\n", (unsigned long)rv);
        }
        else
        {
            CK_ULONG nSlots = 0;
            CK_SLOT_ID slots[16];
            rv = fl->C_GetSlotList(CK_TRUE, NULL, &nSlots);
            if (nSlots > 16) nSlots = 16;
            if (rv == CKR_OK && nSlots > 0)
            {
                fl->C_GetSlotList(CK_TRUE, slots, &nSlots);
            }
            fprintf(stderr, "WASM-DIAG: tokenPresent slot count = %lu (rv=0x%lx) role=%s slots[0..2]=%lu,%lu,%lu\n",
                 (unsigned long)nSlots, (unsigned long)rv,
                 getenv("WASM_ROLE") ? getenv("WASM_ROLE") : "?",
                 (unsigned long)(nSlots > 0 ? slots[0] : 0xFFFF),
                 (unsigned long)(nSlots > 1 ? slots[1] : 0xFFFF),
                 (unsigned long)(nSlots > 2 ? slots[2] : 0xFFFF));
            fflush(stderr);
            for (CK_ULONG i = 0; i < nSlots; i++)
            {
                fprintf(stderr, "WASM-DIAG: -- slot loop iter role=%s i=%lu slotId=%lu --\n",
                     getenv("WASM_ROLE") ? getenv("WASM_ROLE") : "?",
                     (unsigned long)i, (unsigned long)slots[i]);
                fflush(stderr);
                CK_SESSION_HANDLE hSess = 0;
                CK_RV ors = fl->C_OpenSession(slots[i], CKF_SERIAL_SESSION,
                                              NULL_PTR, NULL_PTR, &hSess);
                fprintf(stderr, "WASM-DIAG: slot %lu C_OpenSession rv=0x%lx hSess=%lu\n",
                     (unsigned long)slots[i], (unsigned long)ors, (unsigned long)hSess);
                fflush(stderr);
                if (ors != CKR_OK)
                {
                    continue;
                }
                CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
                CK_ATTRIBUTE tmpl[] = { {CKA_CLASS, &pubClass, sizeof(pubClass)} };
                CK_RV initRv = fl->C_FindObjectsInit(hSess, tmpl, 1);
                fprintf(stderr, "WASM-DIAG: slot %lu C_FindObjectsInit rv=0x%lx\n",
                     (unsigned long)slots[i], (unsigned long)initRv);
                fflush(stderr);
                CK_OBJECT_HANDLE handles[16];
                CK_ULONG cnt = 0;
                CK_RV findRv = fl->C_FindObjects(hSess, handles, 16, &cnt);
                fl->C_FindObjectsFinal(hSess);
                fprintf(stderr, "WASM-DIAG: slot %lu has %lu pubkey object(s) visible (no-login) findRv=0x%lx\n",
                     (unsigned long)slots[i], (unsigned long)cnt, (unsigned long)findRv);
                fflush(stderr);

                /* THE CRITICAL TEST: replicate charon's find_lib_by_keyid query
                 * exactly — {CKA_CLASS=CKO_PUBLIC_KEY, CKA_ID=<local_keyid>}
                 * decoded from the WASM_LOCAL_KEYID env var. If this returns 0
                 * objects despite the unfiltered query above returning the key,
                 * softhsm has a CKA_ID matching bug. If it returns 1, the bug
                 * is in strongswan-pkcs11's find_lib_by_keyid call path. */
                {
                    const char *kid = getenv("WASM_LOCAL_KEYID");
                    if (kid && strlen(kid) >= 40)
                    {
                        CK_BYTE keyid_bin[20]; memset(keyid_bin, 0, sizeof(keyid_bin));
                        for (int b = 0; b < 20; b++)
                        {
                            unsigned int byte;
                            if (sscanf(kid + b * 2, "%2x", &byte) == 1)
                                keyid_bin[b] = (CK_BYTE)byte;
                        }
                        CK_OBJECT_CLASS pubClass2 = CKO_PUBLIC_KEY;
                        CK_ATTRIBUTE tmpl2[] = {
                            {CKA_CLASS, &pubClass2, sizeof(pubClass2)},
                            {CKA_ID,    keyid_bin, sizeof(keyid_bin)},
                        };
                        CK_RV initRv2 = fl->C_FindObjectsInit(hSess, tmpl2, 2);
                        CK_OBJECT_HANDLE handles2[4];
                        CK_ULONG cnt2 = 0;
                        CK_RV findRv2 = CKR_OK;
                        if (initRv2 == CKR_OK)
                        {
                            findRv2 = fl->C_FindObjects(hSess, handles2, 4, &cnt2);
                            fl->C_FindObjectsFinal(hSess);
                        }
                        fprintf(stderr, "WASM-DIAG:   ★ CKA_ID-filtered (charon-style) slot %lu found=%lu initRv=0x%lx findRv=0x%lx kid=%.16s…\n",
                             (unsigned long)slots[i], (unsigned long)cnt2,
                             (unsigned long)initRv2, (unsigned long)findRv2, kid);
                        fflush(stderr);
                    }
                }
                for (CK_ULONG j = 0; j < cnt && j < 4; j++)
                {
                    CK_BYTE id_buf[32]; memset(id_buf, 0, sizeof(id_buf));
                    CK_BBOOL priv_v = 0xff;
                    CK_KEY_TYPE kt = 0;
                    CK_ATTRIBUTE getAttrs[] = {
                        {CKA_ID, id_buf, sizeof(id_buf)},
                        {CKA_PRIVATE, &priv_v, sizeof(priv_v)},
                        {CKA_KEY_TYPE, &kt, sizeof(kt)},
                    };
                    fl->C_GetAttributeValue(hSess, handles[j], getAttrs, 3);
                    char hex[80]; hex[0] = 0;
                    CK_ULONG idLen = getAttrs[0].ulValueLen;
                    if (idLen > 32) idLen = 32;
                    for (CK_ULONG k = 0; k < idLen && (k * 2) < (sizeof(hex) - 3); k++)
                    {
                        snprintf(hex + k * 2, 3, "%02x", id_buf[k]);
                    }
                    fprintf(stderr, "WASM-DIAG:   pubkey[%lu] hObj=%lu kt=0x%lx priv=%u idLen=%lu id=%s\n",
                         (unsigned long)j, (unsigned long)handles[j],
                         (unsigned long)kt, (unsigned)priv_v,
                         (unsigned long)idLen, hex);
                }
                fl->C_CloseSession(hSess);
            }
        }
    }

    /* Lazy-init backend + storage. */
    if (!peer_cfgs) peer_cfgs = linked_list_create();

    switch (wasm_proposal_mode)
    {
        case 1: ike_prop = proposal_ike_pqc;       break;
        case 2: ike_prop = proposal_ike_hybrid;    break;
        default: ike_prop = proposal_ike_classical; break;
    }

    /* IKE config — local/remote addresses depend on the worker's role.
     * The JS worker sets WASM_ROLE = "initiator" | "responder" before main();
     * we hard-code 192.168.0.1 / 192.168.0.2 to match bridge.ts's SAB-based
     * UDP loopback. Without explicit addresses, charon aborts IKE_SA_INIT
     * with "unable to resolve 0.0.0.0". */
    memset(&ike_data, 0, sizeof(ike_data));
    ike_data.version     = IKEV2;
    {
        const char *role_env = getenv("WASM_ROLE");
        if (role_env && !strcmp(role_env, "initiator")) {
            ike_data.local  = "192.168.0.1";
            ike_data.remote = "192.168.0.2";
        } else {
            /* responder (or unset → default to responder) */
            ike_data.local  = "192.168.0.2";
            ike_data.remote = "192.168.0.1";
        }
    }
    ike_data.local_port  = 500;
    ike_data.remote_port = 500;
    /* Childless IKE_SA per RFC 6023: skip the piggybacked CHILD_SA in
     * IKE_AUTH because the WASM build has no kernel IPSec interface and
     * CHILD_SA SPI allocation fails ("unable to allocate SPI from kernel").
     * The IKE_SA still authenticates and reaches ESTABLISHED — which is the
     * milestone for this in-browser demo. The responder advertises
     * N(CHDLESS_SUP) so this is mutually negotiated. */
    ike_data.childless   = CHILDLESS_FORCE;
    ike_cfg = ike_cfg_create(&ike_data);
    ike_cfg->add_proposal(ike_cfg, proposal_create_from_string(PROTO_IKE,
                                                               (char *)ike_prop));

    /* Peer config. (Childless behavior is set on ike_cfg_create_t above.) */
    memset(&peer_data, 0, sizeof(peer_data));
    /* CERT_ALWAYS_SEND so the X.509 (with ML-DSA pubkey) is included in the
     * IKE_AUTH payload — without it the peer can't get our pubkey, signature
     * verification fails, and IKE_AUTH returns AUTH_FAILED. CERT_SEND_IF_ASKED
     * (default) only sends when peer included a CERTREQ, which doesn't happen
     * in our self-signed setup. Always-send is correct for dual-auth ML-DSA. */
    peer_data.cert_policy = (wasm_auth_mode == 1) ? CERT_ALWAYS_SEND : CERT_SEND_IF_ASKED;
    peer_data.unique      = UNIQUE_NO;
    peer_data.keyingtries = 1;
    peer_cfg = peer_cfg_create("wasm", ike_cfg, &peer_data);

    if (wasm_auth_mode == 1)
    {
        /* Pubkey auth — ML-DSA cert loaded from worker FS.
         * Cert path is role-dependent; written by generateCertsViaWorker
         * before the daemon starts. charon's strongswan-pkcs11 plugin
         * finds the matching private key via CKA_ID = cert SKID. */
        const char *role_env2 = getenv("WASM_ROLE");
        const char *local_cert_path =
            (role_env2 && !strcmp(role_env2, "initiator"))
                ? "/etc/ipsec.d/certs/initiator.crt"
                : "/etc/ipsec.d/certs/responder.crt";

        my_cert = lib->creds->create(lib->creds,
            CRED_CERTIFICATE, CERT_X509,
            BUILD_FROM_FILE, local_cert_path,
            BUILD_END);

        /* Load the PEER's cert as a trust anchor so the responder accepts
         * the initiator's self-signed cert (and vice versa). Without this,
         * IKE_AUTH succeeds locally (we sign) but the peer rejects our cert
         * with AUTH_FAILED because it doesn't trust the signer. */
        const char *peer_cert_path =
            (role_env2 && !strcmp(role_env2, "initiator"))
                ? "/etc/ipsec.d/certs/responder.crt"
                : "/etc/ipsec.d/certs/initiator.crt";
        certificate_t *peer_cert = lib->creds->create(lib->creds,
            CRED_CERTIFICATE, CERT_X509,
            BUILD_FROM_FILE, peer_cert_path,
            BUILD_END);
        if (peer_cert)
        {
            mem_cred_t *peer_creds = mem_cred_create();
            /* trusted=TRUE → counts as a CA anchor for trust-chain validation
             * of the peer's self-signed cert. */
            peer_creds->add_cert(peer_creds, TRUE, peer_cert);
            lib->credmgr->add_set(lib->credmgr, &peer_creds->set);
            DBG1(DBG_CFG, "WASM: loaded peer cert from %s as trust anchor",
                 peer_cert_path);
        }
        else
        {
            DBG1(DBG_CFG, "WASM: FAILED to load peer cert from %s — IKE_AUTH will fail",
                 peer_cert_path);
        }

        /* Build local + remote identities. If WASM_LOCAL_KEYID / WASM_REMOTE_KEYID
         * env vars are set (hex string, no prefix), use ID_KEY_ID. This makes
         * charon's credential_manager.c::get_private hit the ID_KEY_ID fast path
         * (get_private_by_keyid → find_lib_by_keyid by CKA_ID), bypassing the
         * cert→pubkey→fingerprint chain that does not work reliably for ML-DSA
         * in this WASM build. The hex bytes must match the CKA_ID set on the
         * private key in the panel softhsm at keygen time.
         *
         * Format passed to identification_create_from_string: "@#<hex>". The
         * '@' tells strongSwan it's not a DN; '#' tells it the rest is hex
         * bytes for ID_KEY_ID. See identification.c:2107-2114. */
        char id_buf[128];
        const char *local_keyid_env  = getenv("WASM_LOCAL_KEYID");
        const char *remote_keyid_env = getenv("WASM_REMOTE_KEYID");

        /* CRITICAL: Explicitly load the PKCS#11 private key into a mem_cred
         * set. Upstream strongswan-pkcs11's credential set returns
         * enumerator_create_empty for create_private_enumerator (see
         * pkcs11_creds.c:241), so credmgr's get_private_by_keyid path
         * always returns NULL unless the private key has been pre-loaded
         * via lib->creds->create(BUILD_PKCS11_KEYID,...) and inserted into
         * a mem_cred. In real deployments this is done by stroke/vici/nm
         * config plugins; in WASM we have neither, so do it inline here.
         *
         * Without this, IKE_AUTH always fails with "no private key found".
         */
        if (local_keyid_env && *local_keyid_env)
        {
            size_t hex_len = strlen(local_keyid_env);
            if (hex_len >= 2 && (hex_len % 2) == 0)
            {
                size_t bin_len = hex_len / 2;
                u_char *bin = malloc(bin_len);
                for (size_t b = 0; b < bin_len; b++)
                {
                    unsigned int byte;
                    if (sscanf(local_keyid_env + b * 2, "%2x", &byte) != 1)
                    {
                        bin[b] = 0;
                    }
                    else
                    {
                        bin[b] = (u_char)byte;
                    }
                }
                chunk_t keyid_chunk = chunk_create(bin, bin_len);
                private_key_t *pkcs11_priv = lib->creds->create(lib->creds,
                    CRED_PRIVATE_KEY, KEY_ANY,
                    BUILD_PKCS11_KEYID, keyid_chunk,
                    BUILD_END);
                free(bin);
                if (pkcs11_priv)
                {
                    mem_cred_t *priv_creds = mem_cred_create();
                    priv_creds->add_key(priv_creds, pkcs11_priv);
                    lib->credmgr->add_set(lib->credmgr, &priv_creds->set);
                    DBG1(DBG_CFG, "WASM: loaded PKCS#11 private key for keyid %s into mem_cred",
                         local_keyid_env);
                }
                else
                {
                    DBG1(DBG_CFG, "WASM: FAILED to load PKCS#11 private key for keyid %s — IKE_AUTH will fail",
                         local_keyid_env);
                }
            }
        }

        auth_local = auth_cfg_create();
        auth_local->add(auth_local, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
        if (my_cert)
            auth_local->add(auth_local, AUTH_RULE_SUBJECT_CERT, my_cert);
        if (local_keyid_env && *local_keyid_env)
        {
            snprintf(id_buf, sizeof(id_buf), "@#%s", local_keyid_env);
            auth_local->add(auth_local, AUTH_RULE_IDENTITY,
                            identification_create_from_string(id_buf));
            DBG1(DBG_CFG, "WASM: local identity = ID_KEY_ID @#%s", local_keyid_env);
        }
        else
        {
            auth_local->add(auth_local, AUTH_RULE_IDENTITY,
                            identification_create_from_string("%any"));
        }
        peer_cfg->add_auth_cfg(peer_cfg, auth_local, TRUE);

        auth_remote = auth_cfg_create();
        auth_remote->add(auth_remote, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PUBKEY);
        if (remote_keyid_env && *remote_keyid_env)
        {
            snprintf(id_buf, sizeof(id_buf), "@#%s", remote_keyid_env);
            auth_remote->add(auth_remote, AUTH_RULE_IDENTITY,
                             identification_create_from_string(id_buf));
            DBG1(DBG_CFG, "WASM: remote identity = ID_KEY_ID @#%s", remote_keyid_env);
        }
        else
        {
            auth_remote->add(auth_remote, AUTH_RULE_IDENTITY,
                             identification_create_from_string("%any"));
        }
        peer_cfg->add_auth_cfg(peer_cfg, auth_remote, FALSE);
    }
    else
    {
        /* PSK auth (default). */
        auth_local = auth_cfg_create();
        auth_local->add(auth_local, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
        auth_local->add(auth_local, AUTH_RULE_IDENTITY,
                        identification_create_from_string("%any"));
        peer_cfg->add_auth_cfg(peer_cfg, auth_local, TRUE);

        auth_remote = auth_cfg_create();
        auth_remote->add(auth_remote, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
        auth_remote->add(auth_remote, AUTH_RULE_IDENTITY,
                         identification_create_from_string("%any"));
        peer_cfg->add_auth_cfg(peer_cfg, auth_remote, FALSE);
    }

    /* Child config. */
    memset(&child_data, 0, sizeof(child_data));
    child_data.mode = MODE_TUNNEL;
    child_cfg = child_cfg_create("wasm-child", &child_data);
    child_cfg->add_proposal(child_cfg, proposal_create_from_string(PROTO_ESP,
                                                                   (char *)proposal_esp));
    peer_cfg->add_child_cfg(peer_cfg, child_cfg);

    peer_cfgs->insert_last(peer_cfgs, peer_cfg);

    DBG1(DBG_CFG, "WASM: registered static config (role=%s, local=%s, remote=%s)",
         getenv("WASM_ROLE") ? getenv("WASM_ROLE") : "responder",
         ike_data.local, ike_data.remote);

    /* Register the backend the first time. */
    if (!wasm_backend)
    {
        wasm_backend = malloc(sizeof(*wasm_backend));
        memset(wasm_backend, 0, sizeof(*wasm_backend));
        wasm_backend->public.get_peer_cfg_by_name =
            (peer_cfg_t *(*)(backend_t *, char *))wasm_get_peer_by_name;
        wasm_backend->public.create_peer_cfg_enumerator =
            (enumerator_t *(*)(backend_t *, identification_t *,
                               identification_t *))wasm_create_peer_enum;
        wasm_backend->public.create_ike_cfg_enumerator =
            (enumerator_t *(*)(backend_t *, host_t *, host_t *))
                wasm_create_ike_enum;
        charon->backends->add_backend(charon->backends, &wasm_backend->public);
    }

    /* Pre-register PSK from the WASM_PSK env var (PSK mode only).
     *
     * mem_cred->add_shared() takes a varargs list of identity owners
     * terminated by NULL. Passing just NULL makes the PSK unowned, which
     * fails credmgr lookups like "PSK for 192.168.0.1 - %any" because the
     * lookup tries to match the requested owners against the PSK's owners.
     * Add a "%any" identity owner so the PSK matches any peer pair. */
    if (wasm_auth_mode == 0)
    {
        psk_env = getenv("WASM_PSK");
        if (psk_env && *psk_env)
        {
            creds = mem_cred_create();
            creds->add_shared(creds,
                shared_key_create(SHARED_IKE,
                    chunk_clone(chunk_create((u_char *)psk_env, strlen(psk_env)))),
                identification_create_from_string("%any"),
                NULL);
            lib->credmgr->add_set(lib->credmgr, &creds->set);
        }
    }

}

/*─────────────────────────────────────────────────────────────────────*/
/* wasm_initiate — trigger IKE_SA_INIT on the responder                */
/*─────────────────────────────────────────────────────────────────────*/

void wasm_initiate(int unused)
{
    peer_cfg_t *peer_cfg;
    enumerator_t *e;
    child_cfg_t *child_cfg = NULL;
    enumerator_t *ce;

    if (!peer_cfgs) return;
    e = peer_cfgs->create_enumerator(peer_cfgs);
    if (!e->enumerate(e, &peer_cfg))
    {
        e->destroy(e);
        return;
    }
    peer_cfg = peer_cfg->get_ref(peer_cfg);
    e->destroy(e);

    ce = peer_cfg->create_child_cfg_enumerator(peer_cfg);
    if (ce->enumerate(ce, &child_cfg))
    {
        child_cfg = child_cfg->get_ref(child_cfg);
    }
    ce->destroy(ce);

    if (child_cfg)
    {
        charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
                                     NULL, NULL, 0, 0, FALSE);
    }
    else
    {
        peer_cfg->destroy(peer_cfg);
    }
}

#endif /* __EMSCRIPTEN__ */
