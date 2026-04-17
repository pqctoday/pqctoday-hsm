/* Copyright (C) 2026 SoftHSMv3 Contributors
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"

DISPATCH_KEYMGMT_FN(hss, new);
DISPATCH_KEYMGMT_FN(hss, load);
DISPATCH_KEYMGMT_FN(hss, match);
DISPATCH_KEYMGMT_FN(hss, import_types);
DISPATCH_KEYMGMT_FN(hss, export_types);
DISPATCH_KEYMGMT_FN(hss, get_params);
DISPATCH_KEYMGMT_FN(hss, gettable_params);

/* Based on PKCS#11 v3.2, LMS uses CKK_HSS with levels=1 */
DISPATCH_KEYMGMT_FN(lms, new);
DISPATCH_KEYMGMT_FN(lms, load);
DISPATCH_KEYMGMT_FN(lms, match);

static void *p11prov_hss_new(void *provctx)
{
    P11PROV_debug("hss new");
    return p11prov_kmgmt_new(provctx, CKK_HSS);
}

static void *p11prov_lms_new(void *provctx)
{
    P11PROV_debug("lms new");
    return p11prov_kmgmt_new(provctx, CKK_HSS);
}

static void *p11prov_hss_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_HSS);
}

static void *p11prov_lms_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_HSS);
}

static int p11prov_hss_match(const void *keydata1, const void *keydata2,
                             int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_HSS, selection);
}

static int p11prov_lms_match(const void *keydata1, const void *keydata2,
                             int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_HSS, selection);
}

static const OSSL_PARAM *p11prov_hss_import_types(int selection)
{
    static const OSSL_PARAM p11prov_hss_imp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("hss import types");
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_hss_imp_key_types;
    }
    return NULL;
}

static const OSSL_PARAM *p11prov_hss_export_types(int selection)
{
    static const OSSL_PARAM p11prov_hss_exp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("hss export types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_hss_exp_key_types;
    }
    return NULL;
}

static int p11prov_hss_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("hss get params %p", keydata);

    if (key == NULL) {
        return RET_OSSL_ERR;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p) {
        CK_ULONG bits_size = p11prov_obj_get_key_bit_size(key);
        if (bits_size == 0) {
            return RET_OSSL_ERR;
        }
        ret = OSSL_PARAM_set_int(p, bits_size);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }
    
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p) {
        int secbits = 128; /* Default / typical */
        ret = OSSL_PARAM_set_int(p, secbits);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p) {
        CK_ATTRIBUTE *pub;

        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            return RET_OSSL_ERR;
        }
        pub = p11prov_obj_get_attr(key, CKA_VALUE);
        if (!pub) {
            return RET_OSSL_ERR;
        }

        p->return_size = pub->ulValueLen;
        if (p->data) {
            if (p->data_size < pub->ulValueLen) {
                return RET_OSSL_ERR;
            }
            memcpy(p->data, pub->pValue, pub->ulValueLen);
            p->data_size = pub->ulValueLen;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hss_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

#define p11prov_hss_free p11prov_kmgmt_free
#define p11prov_hss_has p11prov_kmgmt_has
#define p11prov_hss_export p11prov_kmgmt_export

#define p11prov_lms_import_types p11prov_hss_import_types
#define p11prov_lms_export_types p11prov_hss_export_types
#define p11prov_lms_get_params p11prov_hss_get_params
#define p11prov_lms_gettable_params p11prov_hss_gettable_params
#define p11prov_lms_free p11prov_kmgmt_free
#define p11prov_lms_has p11prov_kmgmt_has
#define p11prov_lms_export p11prov_kmgmt_export

const OSSL_DISPATCH p11prov_hss_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(hss, NEW, new),
    DISPATCH_KEYMGMT_ELEM(hss, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(hss, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(hss, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(hss, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(hss, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(hss, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_lms_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(lms, NEW, new),
    DISPATCH_KEYMGMT_ELEM(lms, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(lms, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(lms, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(lms, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(lms, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(lms, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};
