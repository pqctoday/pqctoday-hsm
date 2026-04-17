/* Copyright (C) 2026 SoftHSMv3 Contributors
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "kmgmt/internal.h"

DISPATCH_KEYMGMT_FN(xmss, new);
DISPATCH_KEYMGMT_FN(xmss, load);
DISPATCH_KEYMGMT_FN(xmss, match);
DISPATCH_KEYMGMT_FN(xmss, import_types);
DISPATCH_KEYMGMT_FN(xmss, export_types);
DISPATCH_KEYMGMT_FN(xmss, get_params);
DISPATCH_KEYMGMT_FN(xmss, gettable_params);

DISPATCH_KEYMGMT_FN(xmssmt, new);
DISPATCH_KEYMGMT_FN(xmssmt, load);
DISPATCH_KEYMGMT_FN(xmssmt, match);

/* We only implement Public Key parsing/loading for Verification since signing is disabled. */

static void *p11prov_xmss_new(void *provctx)
{
    P11PROV_debug("xmss new");
    return p11prov_kmgmt_new(provctx, CKK_XMSS);
}

static void *p11prov_xmssmt_new(void *provctx)
{
    P11PROV_debug("xmssmt new");
    return p11prov_kmgmt_new(provctx, CKK_XMSSMT);
}

static void *p11prov_xmss_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_XMSS);
}

static void *p11prov_xmssmt_load(const void *reference, size_t reference_sz)
{
    return p11prov_kmgmt_load(reference, reference_sz, CKK_XMSSMT);
}

static int p11prov_xmss_match(const void *keydata1, const void *keydata2,
                              int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_XMSS, selection);
}

static int p11prov_xmssmt_match(const void *keydata1, const void *keydata2,
                                int selection)
{
    return p11prov_kmgmt_match(keydata1, keydata2, CKK_XMSSMT, selection);
}

static const OSSL_PARAM *p11prov_xmss_import_types(int selection)
{
    static const OSSL_PARAM p11prov_xmss_imp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("xmss/mt import types");
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_xmss_imp_key_types;
    }
    return NULL;
}

static const OSSL_PARAM *p11prov_xmss_export_types(int selection)
{
    static const OSSL_PARAM p11prov_xmss_exp_key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END,
    };
    P11PROV_debug("xmss/mt export types");
    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return p11prov_xmss_exp_key_types;
    }
    return NULL;
}

static int p11prov_xmss_get_params(void *keydata, OSSL_PARAM params[])
{
    P11PROV_OBJ *key = (P11PROV_OBJ *)keydata;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("xmss get params %p", keydata);

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
        int secbits = 256; /* Default XMSS/MT assumed param sets */
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

static const OSSL_PARAM *p11prov_xmss_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

#define p11prov_xmss_free p11prov_kmgmt_free
#define p11prov_xmss_has p11prov_kmgmt_has
#define p11prov_xmss_export p11prov_kmgmt_export

#define p11prov_xmssmt_import_types p11prov_xmss_import_types
#define p11prov_xmssmt_export_types p11prov_xmss_export_types
#define p11prov_xmssmt_get_params p11prov_xmss_get_params
#define p11prov_xmssmt_gettable_params p11prov_xmss_gettable_params
#define p11prov_xmssmt_free p11prov_kmgmt_free
#define p11prov_xmssmt_has p11prov_kmgmt_has
#define p11prov_xmssmt_export p11prov_kmgmt_export

const OSSL_DISPATCH p11prov_xmss_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(xmss, NEW, new),
    DISPATCH_KEYMGMT_ELEM(xmss, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(xmss, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(xmss, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(xmss, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(xmss, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(xmss, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_xmssmt_keymgmt_functions[] = {
    DISPATCH_KEYMGMT_ELEM(xmssmt, NEW, new),
    DISPATCH_KEYMGMT_ELEM(xmssmt, LOAD, load),
    DISPATCH_KEYMGMT_ELEM(kmgmt, FREE, free),
    DISPATCH_KEYMGMT_ELEM(kmgmt, HAS, has),
    DISPATCH_KEYMGMT_ELEM(xmssmt, MATCH, match),
    DISPATCH_KEYMGMT_ELEM(xmssmt, IMPORT_TYPES, import_types),
    DISPATCH_KEYMGMT_ELEM(kmgmt, EXPORT, export),
    DISPATCH_KEYMGMT_ELEM(xmssmt, EXPORT_TYPES, export_types),
    DISPATCH_KEYMGMT_ELEM(xmssmt, GET_PARAMS, get_params),
    DISPATCH_KEYMGMT_ELEM(xmssmt, GETTABLE_PARAMS, gettable_params),
    { 0, NULL },
};
