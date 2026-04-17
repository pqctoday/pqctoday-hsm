/* Copyright (C) 2026 SoftHSMv3 Contributors
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "sig/internal.h"
#include <string.h>
#include "openssl/evp.h"
#include "openssl/err.h"

DISPATCH_SLHDSA_FN(sign_init);
DISPATCH_SLHDSA_FN(sign);
DISPATCH_SLHDSA_FN(verify_init);
DISPATCH_SLHDSA_FN(verify);
DISPATCH_SLHDSA_FN(get_ctx_params);
DISPATCH_SLHDSA_FN(set_ctx_params);
DISPATCH_SLHDSA_FN(gettable_ctx_params);
DISPATCH_SLHDSA_FN(settable_ctx_params);

static int p11prov_slhdsa_set_ctx_params(void *ctx, const OSSL_PARAM params[]);

static CK_RV p11prov_slhdsa_set_mechanism(P11PROV_SIG_CTX *sigctx)
{
    sigctx->mechanism.mechanism = CKM_SLH_DSA;
    if (sigctx->slhdsa_params.ulContextLen > 0) {
        sigctx->mechanism.pParameter = &sigctx->slhdsa_params;
        sigctx->mechanism.ulParameterLen = sizeof(CK_SIGN_ADDITIONAL_CONTEXT);
    } else {
        sigctx->mechanism.pParameter = NULL;
        sigctx->mechanism.ulParameterLen = 0;
    }
    return CKR_OK;
}

static CK_RV p11prov_slhdsa_sig_size(P11PROV_SIG_CTX *sigctx, size_t *siglen)
{
    switch (sigctx->slhdsa_paramset) {
    case CKP_SLH_DSA_SHA2_128F:
        *siglen = 17088;
        return CKR_OK;
    default:
        return CKR_GENERAL_ERROR;
    }
}

static CK_RV p11prov_slhdsa_operate(P11PROV_SIG_CTX *sigctx, unsigned char *sig,
                                    size_t *siglen, size_t sigsize,
                                    unsigned char *tbs, size_t tbslen)
{
    CK_RV rv;

    rv = p11prov_slhdsa_set_mechanism(sigctx);
    if (rv != CKR_OK) {
        return rv;
    }

    return p11prov_sig_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                               tbslen);
}

static void *p11prov_slhdsa_newctx(void *provctx, const char *properties,
                                   CK_SLH_DSA_PARAMETER_SET_TYPE paramset)
{
    P11PROV_CTX *ctx = (P11PROV_CTX *)provctx;
    P11PROV_SIG_CTX *sigctx;

    sigctx = p11prov_sig_newctx(ctx, CKM_SLH_DSA, properties);
    if (sigctx == NULL) {
        return NULL;
    }

    sigctx->slhdsa_paramset = paramset;
    sigctx->fallback_operate = &p11prov_slhdsa_operate;

    return sigctx;
}

static void *p11prov_slhdsa_sha2_128f_newctx(void *provctx, const char *properties)
{
    return p11prov_slhdsa_newctx(provctx, properties, CKP_SLH_DSA_SHA2_128F);
}

static int p11prov_slhdsa_sign_init(void *ctx, void *provkey,
                                    const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("slhdsa sign init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_SIGN, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_sign(void *ctx, unsigned char *sig, size_t *siglen,
                               size_t sigsize, const unsigned char *tbs,
                               size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("slhdsa sign (ctx=%p)", ctx);

    if (sig == NULL) {
        if (siglen == NULL) {
            return RET_OSSL_ERR;
        }
        ret = p11prov_slhdsa_sig_size(sigctx, siglen);
        if (ret != CKR_OK) {
            return RET_OSSL_ERR;
        }
        return RET_OSSL_OK;
    }

    ret = p11prov_slhdsa_operate(sigctx, sig, siglen, sigsize, (void *)tbs,
                                 tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static int p11prov_slhdsa_verify_init(void *ctx, void *provkey,
                                      const OSSL_PARAM params[])
{
    CK_RV ret;

    P11PROV_debug("slhdsa verify init (ctx=%p, key=%p, params=%p)", ctx, provkey,
                  params);

    ret = p11prov_sig_op_init(ctx, provkey, CKF_VERIFY, NULL);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return p11prov_slhdsa_set_ctx_params(ctx, params);
}

static int p11prov_slhdsa_verify(void *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    CK_RV ret;

    P11PROV_debug("slhdsa verify (ctx=%p)", ctx);

    ret = p11prov_slhdsa_operate(sigctx, (unsigned char *)sig, NULL, siglen,
                                 (void *)tbs, tbslen);
    if (ret != CKR_OK) {
        return RET_OSSL_ERR;
    }

    return RET_OSSL_OK;
}

static const unsigned char der_slh_dsa_sha2_128f_alg_id[] = {
    DER_SEQUENCE,     DER_NIST_SIGALGS_LEN + 3,
    DER_OBJECT,       DER_NIST_SIGALGS_LEN + 1,
    DER_NIST_SIGALGS, 0x14
};

static int p11prov_slhdsa_get_ctx_params(void *ctx, OSSL_PARAM *params)
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    OSSL_PARAM *p;
    int ret;

    P11PROV_debug("slhdsa get ctx params (ctx=%p, params=%p)", ctx, params);

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p) {
        switch (sigctx->slhdsa_paramset) {
        case CKP_SLH_DSA_SHA2_128F:
            ret = OSSL_PARAM_set_octet_string(p, der_slh_dsa_sha2_128f_alg_id,
                                              sizeof(der_slh_dsa_sha2_128f_alg_id));
            break;
        default:
            ret = RET_OSSL_ERR;
        }
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif
#ifndef OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING
#define OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING "message-encoding"
#endif
#ifndef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
#define OSSL_SIGNATURE_PARAM_CONTEXT_STRING "context-string"
#endif

static int p11prov_slhdsa_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    P11PROV_SIG_CTX *sigctx = (P11PROV_SIG_CTX *)ctx;
    const OSSL_PARAM *p;
    int ret;

    P11PROV_debug("slhdsa set ctx params (ctx=%p, params=%p)", sigctx, params);

    if (params == NULL) {
        return RET_OSSL_OK;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p) {
        size_t datalen;
        OPENSSL_clear_free(sigctx->slhdsa_params.pContext,
                           sigctx->slhdsa_params.ulContextLen);
        sigctx->slhdsa_params.pContext = NULL;
        ret = OSSL_PARAM_get_octet_string(
            p, (void **)&sigctx->slhdsa_params.pContext, 0, &datalen);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        sigctx->slhdsa_params.ulContextLen = datalen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DETERMINISTIC);
    if (p) {
        CK_HEDGE_TYPE hedge = CKH_HEDGE_PREFERRED;
        int deterministic;
        ret = OSSL_PARAM_get_int(p, &deterministic);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (deterministic == 0) {
            hedge = CKH_HEDGE_REQUIRED;
        } else if (deterministic == 1) {
            hedge = CKH_DETERMINISTIC_REQUIRED;
        } else {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Unsupported 'deterministic' value");
            return RET_OSSL_ERR;
        }
        sigctx->slhdsa_params.hedgeVariant = hedge;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING);
    if (p) {
        int encode;
        ret = OSSL_PARAM_get_int(p, &encode);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
        if (encode != 0) {
            P11PROV_raise(sigctx->provctx, CKR_ARGUMENTS_BAD,
                          "Unsupported 'message-encoding' parameter");
            return RET_OSSL_ERR;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *p11prov_slhdsa_gettable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *p11prov_slhdsa_settable_ctx_params(void *ctx,
                                                            void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, 0),
        OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, 0),
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_DISPATCH p11prov_slhdsa_sha2_128f_signature_functions[] = {
    DISPATCH_SIG_ELEM(slhdsa_sha2_128f, NEWCTX, newctx),
    DISPATCH_SIG_ELEM(sig, FREECTX, freectx),
    DISPATCH_SIG_ELEM(sig, DUPCTX, dupctx),
    DISPATCH_SIG_ELEM(slhdsa, SIGN_INIT, sign_init),
    DISPATCH_SIG_ELEM(slhdsa, SIGN, sign),
    DISPATCH_SIG_ELEM(slhdsa, VERIFY_INIT, verify_init),
    DISPATCH_SIG_ELEM(slhdsa, VERIFY, verify),
    DISPATCH_SIG_ELEM(slhdsa, GET_CTX_PARAMS, get_ctx_params),
    DISPATCH_SIG_ELEM(slhdsa, GETTABLE_CTX_PARAMS, gettable_ctx_params),
    DISPATCH_SIG_ELEM(slhdsa, SET_CTX_PARAMS, set_ctx_params),
    DISPATCH_SIG_ELEM(slhdsa, SETTABLE_CTX_PARAMS, settable_ctx_params),
    { 0, NULL },
};
