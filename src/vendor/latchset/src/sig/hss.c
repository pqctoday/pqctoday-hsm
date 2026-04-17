/* Copyright (C) 2026 SoftHSMv3 Contributors
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/err.h"



#define DISPATCH_HSS_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_hss, name)

#define DISPATCH_LMS_FN(name) \
    DECL_DISPATCH_FUNC(signature, p11prov_lms, name)

DISPATCH_HSS_FN(verify_init);
DISPATCH_HSS_FN(verify);
DISPATCH_HSS_FN(get_ctx_params);
DISPATCH_HSS_FN(set_ctx_params);
DISPATCH_HSS_FN(gettable_ctx_params);
DISPATCH_HSS_FN(settable_ctx_params);

DISPATCH_LMS_FN(verify_init);
DISPATCH_LMS_FN(verify);

static CK_RV p11prov_hss_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    sigctx->mechanism.mechanism = CKM_HSS;
    sigctx->mechanism.pParameter = NULL;
    sigctx->mechanism.ulParameterLen = 0;
    return CKR_OK;
}

static CK_RV p11prov_hss_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                 size_t *siglen, size_t sigsize,
                                 unsigned char *tbs, size_t tbslen)
{
    CK_RV rv;
    rv = p11prov_hss_set_mechanism(sigctx);
    if (rv != CKR_OK) {
        return rv;
    }
    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static void *p11prov_hss_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_HSS, properties);
    if (sigctx == NULL) {
        return NULL;
    }
    sigctx->fallback_operate = &p11prov_hss_operate;
    return sigctx;
}

static void *p11prov_lms_newctx(void *provctx, const char *properties)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_HSS, properties);
    if (sigctx == NULL) {
        return NULL;
    }
    sigctx->fallback_operate = &p11prov_hss_operate;
    return sigctx;
}

static int p11prov_hss_set_ctx_params(void *ctx, const OSSL_PARAM params[]);

static int p11prov_hss_verify_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    CK_RV ret;
    P11PROV_debug("hss verify init");
    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return p11prov_hss_set_ctx_params(ctx, params);
}

static int p11prov_lms_verify_init(void *ctx, void *provkey,
                                   const OSSL_PARAM params[])
{
    CK_RV ret;
    P11PROV_debug("lms verify init");
    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return p11prov_hss_set_ctx_params(ctx, params);
}

static int p11prov_hss_verify(void *ctx, const unsigned char *sig,
                              size_t siglen, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;
    P11PROV_debug("hss verify");
    ret = p11prov_hss_operate(sigctx, (unsigned char *)sig, NULL, siglen,
                              (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_lms_verify(void *ctx, const unsigned char *sig,
                              size_t siglen, const unsigned char *tbs,
                              size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;
    P11PROV_debug("lms verify");
    ret = p11prov_hss_operate(sigctx, (unsigned char *)sig, NULL, siglen,
                              (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_hss_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_debug("hss get ctx params");
    return RET_OSSL_OK;
}

static int p11prov_hss_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_debug("hss set ctx params");
    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_hss_gettable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_hss_settable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    return params;
}

#define p11prov_lms_get_ctx_params p11prov_hss_get_ctx_params
#define p11prov_lms_set_ctx_params p11prov_hss_set_ctx_params
#define p11prov_lms_gettable_ctx_params p11prov_hss_gettable_ctx_params
#define p11prov_lms_settable_ctx_params p11prov_hss_settable_ctx_params

const OSSL_DISPATCH p11prov_hss_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p11prov_hss_newctx },
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(hss, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(hss, VERIFY, verify),
    DISPATCH_SIG_ELEM(hss, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(hss, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(hss, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(hss, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};

const OSSL_DISPATCH p11prov_lms_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))p11prov_lms_newctx },
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(lms, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(lms, VERIFY, verify),
    DISPATCH_SIG_ELEM(lms, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(lms, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(lms, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(lms, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};
