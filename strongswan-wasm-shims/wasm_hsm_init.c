/*
 * wasm_hsm_init.c — softhsmv3 static-link token initialization for the
 * strongSwan WASM build.
 *
 * When charon is linked statically against softhsmv3 (Emscripten target),
 * the usual "dlopen the PKCS#11 .so" path is replaced by a direct call
 * to C_GetFunctionList(). This shim wraps C_Initialize, token init, slot
 * provisioning, and keypair generation so the JS worker can drive it
 * with a single GEN_KEYS message:
 *
 *   rc = wasm_hsm_init(algType, slot0Size, slot1Size);
 *
 *   algType: 1 = RSA, 2 = ML-DSA (out of scope for this WASM shim — the
 *            PQC key generation is performed by the softhsmv3 build; this
 *            shim only selects mechanism IDs).
 *   slot0Size / slot1Size: key sizes in bits.
 *
 * Returns 0 on success, non-zero CK_RV on failure.
 */

#ifdef __EMSCRIPTEN__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "pkcs11.h"

/* Provided by the statically linked softhsmv3 library. */
extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);

/* Two slots — one for each peer. Tokens are labelled "charon-left"
 * (slot 0) and "charon-right" (slot 1). */
static const char * const TOKEN_LABEL[2] = { "charon-left", "charon-right" };
static const char   * const USER_PIN      = "1234";
static const char   * const SO_PIN        = "0000";

static int cryptoki_initialized = 0;

static int init_slot(CK_FUNCTION_LIST_PTR f, CK_SLOT_ID slot,
                     int alg_type, int key_bits, const char *label)
{
    CK_SESSION_HANDLE sess = CK_INVALID_HANDLE;
    CK_RV rv;
    CK_UTF8CHAR padded_label[32];
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE hpub = 0, hprv = 0;

    /* Pad label to 32 chars with spaces (PKCS#11 requirement). */
    memset(padded_label, ' ', sizeof(padded_label));
    memcpy(padded_label, label,
           strnlen(label, sizeof(padded_label)));

    rv = f->C_InitToken(slot, (CK_UTF8CHAR_PTR)SO_PIN, strlen(SO_PIN),
                        padded_label);
    if (rv != CKR_OK)
    {
        fprintf(stderr, "[wasm_hsm_init] C_InitToken failed: 0x%lx\n",
                (unsigned long)rv);
        return (int)rv;
    }

    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                          NULL, NULL, &sess);
    if (rv != CKR_OK) return (int)rv;

    rv = f->C_Login(sess, CKU_SO, (CK_UTF8CHAR_PTR)SO_PIN, strlen(SO_PIN));
    if (rv != CKR_OK) goto fail;
    rv = f->C_InitPIN(sess, (CK_UTF8CHAR_PTR)USER_PIN, strlen(USER_PIN));
    if (rv != CKR_OK) goto fail;
    rv = f->C_Logout(sess);
    if (rv != CKR_OK) goto fail;
    rv = f->C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN,
                    strlen(USER_PIN));
    if (rv != CKR_OK) goto fail;

    /* Generate keypair. RSA is the only algorithm implemented here;
     * ML-DSA plumbing is added in a later step (out of scope for the
     * WASM infrastructure rebuild). */
    if (alg_type == 1) /* RSA */
    {
        CK_ULONG modulus_bits = (CK_ULONG)key_bits;
        CK_BYTE pub_exp[] = { 0x01, 0x00, 0x01 };
        CK_BBOOL ck_true = CK_TRUE;
        CK_OBJECT_CLASS klass_pub = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS klass_prv = CKO_PRIVATE_KEY;
        CK_KEY_TYPE     ktype = CKK_RSA;

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_CLASS,           &klass_pub,   sizeof(klass_pub) },
            { CKA_KEY_TYPE,        &ktype,       sizeof(ktype)     },
            { CKA_TOKEN,           &ck_true,     sizeof(ck_true)   },
            { CKA_ENCRYPT,         &ck_true,     sizeof(ck_true)   },
            { CKA_VERIFY,          &ck_true,     sizeof(ck_true)   },
            { CKA_MODULUS_BITS,    &modulus_bits,sizeof(modulus_bits) },
            { CKA_PUBLIC_EXPONENT, pub_exp,      sizeof(pub_exp)   },
        };
        CK_ATTRIBUTE prv_tmpl[] = {
            { CKA_CLASS,     &klass_prv, sizeof(klass_prv) },
            { CKA_KEY_TYPE,  &ktype,     sizeof(ktype)     },
            { CKA_TOKEN,     &ck_true,   sizeof(ck_true)   },
            { CKA_PRIVATE,   &ck_true,   sizeof(ck_true)   },
            { CKA_SIGN,      &ck_true,   sizeof(ck_true)   },
            { CKA_DECRYPT,   &ck_true,   sizeof(ck_true)   },
            { CKA_SENSITIVE, &ck_true,   sizeof(ck_true)   },
        };

        mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech.pParameter = NULL;
        mech.ulParameterLen = 0;
        rv = f->C_GenerateKeyPair(sess, &mech,
                                  pub_tmpl, sizeof(pub_tmpl)/sizeof(pub_tmpl[0]),
                                  prv_tmpl, sizeof(prv_tmpl)/sizeof(prv_tmpl[0]),
                                  &hpub, &hprv);
        if (rv != CKR_OK) goto fail;
    }
    /* else: ML-DSA / other PQC — left as a hook point for a follow-up
     * patch. The baseline WASM did NOT include ML-DSA generation in this
     * shim either; the handshake plumbing and pqctoday pkcs11 plugin
     * together provide the PQC verification path. */

    f->C_Logout(sess);
    f->C_CloseSession(sess);
    return 0;

fail:
    if (sess != CK_INVALID_HANDLE) f->C_CloseSession(sess);
    return (int)rv;
}

/**
 * Discover the next uninitialized slot via softhsmv3's on-demand slot
 * provisioning. Mirrors the main-thread JS pattern in
 * VpnSimulationPanel.tsx::generateCerts: calling C_GetSlotList(FALSE, NULL,
 * &cnt) causes softhsmv3 to auto-append an empty slot when all existing
 * slots are initialized; then C_GetSlotList(FALSE, list, &cnt) yields the
 * full list whose LAST entry is the freshly-provisioned uninitialized slot.
 *
 * Returns CK_RV on failure; writes the discovered slot ID into *out_slot.
 */
static CK_RV discover_next_empty_slot(CK_FUNCTION_LIST_PTR f, CK_SLOT_ID *out_slot)
{
    CK_ULONG n_slots = 0;
    CK_SLOT_ID_PTR slots;
    CK_RV rv;

    /* Probe — triggers slot auto-provisioning if needed. */
    rv = f->C_GetSlotList(CK_FALSE, NULL, &n_slots);
    if (rv != CKR_OK) return rv;
    if (n_slots == 0) return CKR_SLOT_ID_INVALID;

    slots = (CK_SLOT_ID_PTR)malloc(n_slots * sizeof(CK_SLOT_ID));
    if (!slots) return CKR_HOST_MEMORY;
    rv = f->C_GetSlotList(CK_FALSE, slots, &n_slots);
    if (rv != CKR_OK) { free(slots); return rv; }

    /* Last slot is always uninitialized per softhsmv3's append-on-probe. */
    *out_slot = slots[n_slots - 1];
    free(slots);
    return CKR_OK;
}

/**
 * JS-callable entry point. Initializes the Cryptoki library on first
 * call, then (re-)initializes both slots with fresh keypairs.
 *
 * Signature (i32,i32,i32) -> i32 must match the baseline.
 */
int wasm_hsm_init(int alg_type, int slot0_bits, int slot1_bits)
{
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV rv;
    CK_SLOT_ID slot0, slot1;
    int rc;

    rv = C_GetFunctionList(&f);
    if (rv != CKR_OK || !f) return (int)(rv ? rv : CKR_GENERAL_ERROR);

    if (!cryptoki_initialized)
    {
        rv = f->C_Initialize(NULL);
        if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
        {
            return (int)rv;
        }
        cryptoki_initialized = 1;
    }

    rv = discover_next_empty_slot(f, &slot0);
    if (rv != CKR_OK) {
        fprintf(stderr, "[wasm_hsm_init] slot0 discovery failed: 0x%lx\n",
                (unsigned long)rv);
        return (int)rv;
    }
    rc = init_slot(f, slot0, alg_type, slot0_bits, TOKEN_LABEL[0]);
    if (rc != 0) return rc;

    rv = discover_next_empty_slot(f, &slot1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[wasm_hsm_init] slot1 discovery failed: 0x%lx\n",
                (unsigned long)rv);
        return (int)rv;
    }
    rc = init_slot(f, slot1, alg_type, slot1_bits, TOKEN_LABEL[1]);
    return rc;
}

#endif /* __EMSCRIPTEN__ */
