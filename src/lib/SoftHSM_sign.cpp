/*
 * Copyright (c) 2022 NLnet Labs
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 SoftHSM_sign.cpp

 PKCS#11 sign/verify/MAC operations: MacSignInit, AsymSignInit, C_SignInit,
 C_Sign, C_SignUpdate, C_SignFinal, C_SignRecoverInit, C_SignRecover,
 MacVerifyInit, AsymVerifyInit, C_VerifyInit, C_Verify, C_VerifyUpdate,
 C_VerifyFinal, multi-message stubs, C_VerifyRecoverInit, C_VerifyRecover,
 combined-operation stubs.  Static helpers: isMacMechanism, kMacMechTable,
 resolveMacMech, parseMLDSASignContext.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "CryptoFactory.h"
#include "cryptoki.h"
#include "MacAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"
#include "MLDSAPublicKey.h"
#include "MLDSAPrivateKey.h"
#include "MLDSAParameters.h"
#include "OSSLMLDSAPublicKey.h"
#include "OSSLMLDSAPrivateKey.h"
#include "SLHDSAPublicKey.h"
#include "SLHDSAPrivateKey.h"
#include "OSSLSLHDSAPublicKey.h"
#include "OSSLSLHDSAPrivateKey.h"

// Sign*/Verify*() is for MACs too
static bool isMacMechanism(CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL_PTR) return false;

	switch(pMechanism->mechanism) {
		case CKM_MD5_HMAC:
		case CKM_SHA_1_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA256_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
		case CKM_SHA3_224_HMAC:
		case CKM_SHA3_256_HMAC:
		case CKM_SHA3_384_HMAC:
		case CKM_SHA3_512_HMAC:
		case CKM_AES_CMAC:
			return true;
		default:
			return false;
	}
}

// ---------------------------------------------------------------------------
// MAC mechanism lookup table (H3 refactor)
//
// Maps each supported MAC mechanism to its required key type, whether
// CKK_GENERIC_SECRET is an acceptable alternative (HMAC), the PKCS#11
// minimum output length in bytes, and the internal MacAlgo identifier.
// Adding a new MAC mechanism requires one table row and no switch edits.
// ---------------------------------------------------------------------------
namespace {

struct MacMechInfo {
	CK_MECHANISM_TYPE mech;
	CK_KEY_TYPE       specificKeyType; ///< e.g. CKK_SHA256_HMAC; CKK_AES for CMAC
	bool              allowGenericSecret; ///< HMAC: true; CMAC: false
	size_t            minKeyBytes;     ///< minimum key length (0 = no PKCS#11 minimum)
	MacAlgo::Type     algo;
};

static const MacMechInfo kMacMechTable[] = {
	{ CKM_SHA_1_HMAC,    CKK_SHA_1_HMAC,    true,  20, MacAlgo::HMAC_SHA1     },
	{ CKM_SHA224_HMAC,   CKK_SHA224_HMAC,   true,  28, MacAlgo::HMAC_SHA224   },
	{ CKM_SHA256_HMAC,   CKK_SHA256_HMAC,   true,  32, MacAlgo::HMAC_SHA256   },
	{ CKM_SHA384_HMAC,   CKK_SHA384_HMAC,   true,  48, MacAlgo::HMAC_SHA384   },
	{ CKM_SHA512_HMAC,   CKK_SHA512_HMAC,   true,  64, MacAlgo::HMAC_SHA512   },
	{ CKM_SHA3_224_HMAC, CKK_SHA3_224_HMAC, true,  28, MacAlgo::HMAC_SHA3_224 },
	{ CKM_SHA3_256_HMAC, CKK_SHA3_256_HMAC, true,  32, MacAlgo::HMAC_SHA3_256 },
	{ CKM_SHA3_384_HMAC, CKK_SHA3_384_HMAC, true,  48, MacAlgo::HMAC_SHA3_384 },
	{ CKM_SHA3_512_HMAC, CKK_SHA3_512_HMAC, true,  64, MacAlgo::HMAC_SHA3_512 },
	{ CKM_AES_CMAC,      CKK_AES,           false,  0, MacAlgo::CMAC_AES      },
};

/**
 * @brief Resolve a MAC mechanism to its algorithm and key-type requirements.
 *
 * Handles the WITH_FIPS compile-time exclusion of CKM_MD5_HMAC and validates
 * that @p keyType is consistent with the chosen mechanism.
 *
 * @param mech     Mechanism identifier from the caller's CK_MECHANISM.
 * @param keyType  CKA_KEY_TYPE of the supplied key object.
 * @param algo     [out] Resolved MacAlgo identifier.
 * @param minKeyBytes [out] Minimum acceptable key byte length.
 * @return CKR_OK, CKR_MECHANISM_INVALID, or CKR_KEY_TYPE_INCONSISTENT.
 */
static CK_RV resolveMacMech(CK_MECHANISM_TYPE mech, CK_KEY_TYPE keyType,
                             MacAlgo::Type& algo, size_t& minKeyBytes)
{
#ifndef WITH_FIPS
	if (mech == CKM_MD5_HMAC) {
		if (keyType != CKK_GENERIC_SECRET && keyType != CKK_MD5_HMAC)
			return CKR_KEY_TYPE_INCONSISTENT;
		algo        = MacAlgo::HMAC_MD5;
		minKeyBytes = 16;
		return CKR_OK;
	}
#endif
	for (const MacMechInfo& e : kMacMechTable) {
		if (e.mech != mech) continue;
		if (e.allowGenericSecret) {
			if (keyType != CKK_GENERIC_SECRET && keyType != e.specificKeyType)
				return CKR_KEY_TYPE_INCONSISTENT;
		} else {
			if (keyType != e.specificKeyType)
				return CKR_KEY_TYPE_INCONSISTENT;
		}
		algo        = e.algo;
		minKeyBytes = e.minKeyBytes;
		return CKR_OK;
	}
	return CKR_MECHANISM_INVALID;
}

} // anonymous namespace

// MacAlgorithm version of C_SignInit
CK_RV SoftHSM::MacSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_SIGN, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Resolve mechanism → algorithm + key-type check via lookup table (H3).
	MacAlgo::Type algo = MacAlgo::Unknown;
	size_t minSize = 0;
	CK_RV mechRv = resolveMacMech(pMechanism->mechanism, keyType, algo, minSize);
	if (mechRv != CKR_OK) return mechRv;

	MacAlgorithm* mac = CryptoFactory::i()->getMacAlgorithm(algo);
	if (mac == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* privkey = new SymmetricKey();

	if (getSymmetricKey(privkey, token, key) != CKR_OK)
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_GENERAL_ERROR;
	}

	// Key must have at least 1 byte; RFC 2104 permits any positive key size for HMAC
	privkey->setBitLen(privkey->getKeyBits().size() * 8);

	if (privkey->getBitLen() == 0)
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_KEY_SIZE_RANGE;
	}

	// Initialize signing
	if (!mac->signInit(privkey))
	{
		mac->recycleKey(privkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_SIGN);
	session->setMacOp(mac);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(privkey);

	return CKR_OK;
}

// Parse CK_SIGN_ADDITIONAL_CONTEXT or CK_HASH_SIGN_ADDITIONAL_CONTEXT → MLDSA_SIGN_PARAMS
// Deep-copies context bytes into inline buffer to avoid dangling pointers in session storage.
static CK_RV parseMLDSASignContext(CK_MECHANISM_PTR pMechanism, MLDSA_SIGN_PARAMS& out)
{
	memset(&out, 0, sizeof(out));
	out.hashAlg = HashAlgo::Unknown;

	if (pMechanism->pParameter == NULL_PTR || pMechanism->ulParameterLen == 0)
	{
		// No params → defaults: hedged, no context, pure mode
		return CKR_OK;
	}

	// Only CKM_HASH_ML_DSA (generic) uses CK_HASH_SIGN_ADDITIONAL_CONTEXT (16 bytes).
	// The specific CKM_HASH_ML_DSA_SHA256 etc. use CK_SIGN_ADDITIONAL_CONTEXT (12 bytes)
	// — the hash algorithm is implicit in the mechanism constant.
	bool isHashMech = (pMechanism->mechanism == CKM_HASH_ML_DSA);

	if (!isHashMech)
	{
		// CK_SIGN_ADDITIONAL_CONTEXT (12 bytes on 32-bit, may vary)
		if (pMechanism->ulParameterLen != sizeof(CK_SIGN_ADDITIONAL_CONTEXT))
		{
			ERROR_MSG("Invalid ML-DSA parameter size (%lu, expected %lu)",
				pMechanism->ulParameterLen, (unsigned long)sizeof(CK_SIGN_ADDITIONAL_CONTEXT));
			return CKR_ARGUMENTS_BAD;
		}
		CK_SIGN_ADDITIONAL_CONTEXT* ctx =
			(CK_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;

		switch (ctx->hedgeVariant)
		{
			case CKH_HEDGE_PREFERRED:
				out.deterministic = false;
				out.hedgeRequired = false;
				break;
			case CKH_HEDGE_REQUIRED:
				out.deterministic = false;
				out.hedgeRequired = true;
				break;
			case CKH_DETERMINISTIC_REQUIRED:
				out.deterministic = true;
				out.hedgeRequired = false;
				break;
			default:
				ERROR_MSG("Invalid hedge variant %lu", ctx->hedgeVariant);
				return CKR_ARGUMENTS_BAD;
		}

		if (ctx->ulContextLen > 255)
		{
			ERROR_MSG("ML-DSA context string too long (%lu, max 255)", ctx->ulContextLen);
			return CKR_ARGUMENTS_BAD;
		}
		out.contextLen = ctx->ulContextLen;
		if (ctx->ulContextLen > 0)
		{
			if (ctx->pContext == NULL_PTR)
			{
				ERROR_MSG("ML-DSA context pointer is NULL with non-zero length");
				return CKR_ARGUMENTS_BAD;
			}
			memcpy(out.context, ctx->pContext, ctx->ulContextLen);
		}
		out.preHash = false;
	}
	else
	{
		// CK_HASH_SIGN_ADDITIONAL_CONTEXT (16 bytes on 32-bit, may vary)
		if (pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
		{
			ERROR_MSG("Invalid HashML-DSA parameter size (%lu, expected %lu)",
				pMechanism->ulParameterLen,
				(unsigned long)sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT));
			return CKR_ARGUMENTS_BAD;
		}
		CK_HASH_SIGN_ADDITIONAL_CONTEXT* ctx =
			(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;

		switch (ctx->hedgeVariant)
		{
			case CKH_HEDGE_PREFERRED:
				out.deterministic = false;
				out.hedgeRequired = false;
				break;
			case CKH_HEDGE_REQUIRED:
				out.deterministic = false;
				out.hedgeRequired = true;
				break;
			case CKH_DETERMINISTIC_REQUIRED:
				out.deterministic = true;
				out.hedgeRequired = false;
				break;
			default:
				ERROR_MSG("Invalid hedge variant %lu", ctx->hedgeVariant);
				return CKR_ARGUMENTS_BAD;
		}

		if (ctx->ulContextLen > 255)
		{
			ERROR_MSG("ML-DSA context string too long (%lu)", ctx->ulContextLen);
			return CKR_ARGUMENTS_BAD;
		}
		out.contextLen = ctx->ulContextLen;
		if (ctx->ulContextLen > 0)
		{
			if (ctx->pContext == NULL_PTR) return CKR_ARGUMENTS_BAD;
			memcpy(out.context, ctx->pContext, ctx->ulContextLen);
		}
		out.preHash = true;
	}
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignInit
CK_RV SoftHSM::AsymSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_SIGN, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	void* param = NULL;
	size_t paramLen = 0;
	RSA_PKCS_PSS_PARAMS pssParam;
	MLDSA_SIGN_PARAMS mldsaSignParam;
	memset(&mldsaSignParam, 0, sizeof(mldsaSignParam));
	bool bAllowMultiPartOp;
	bool isRSA = false;
#ifdef WITH_ECC
	bool isECDSA = false;
#endif
#ifdef WITH_EDDSA
	bool isEDDSA = false;
#endif
	bool isMLDSA = false;
	bool isSLHDSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = AsymMech::RSA_PKCS;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = AsymMech::RSA;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#ifndef WITH_FIPS
		case CKM_MD5_RSA_PKCS:
			mechanism = AsymMech::RSA_MD5_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA1_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA224_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA256_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA384_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA512_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
			{
				ERROR_MSG("Invalid RSA-PSS parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_PKCS_PSS;
			unsigned long allowedMgf;

			switch(CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg) {
				case CKM_SHA_1:
					pssParam.hashAlg = HashAlgo::SHA1;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
					allowedMgf = CKG_MGF1_SHA1;
					break;
				case CKM_SHA224:
					pssParam.hashAlg = HashAlgo::SHA224;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
					allowedMgf = CKG_MGF1_SHA224;
					break;
				case CKM_SHA256:
					pssParam.hashAlg = HashAlgo::SHA256;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
					allowedMgf = CKG_MGF1_SHA256;
					break;
				case CKM_SHA384:
					pssParam.hashAlg = HashAlgo::SHA384;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
					allowedMgf = CKG_MGF1_SHA384;
					break;
				case CKM_SHA512:
					pssParam.hashAlg = HashAlgo::SHA512;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
					allowedMgf = CKG_MGF1_SHA512;
					break;
				default:
					ERROR_MSG("Invalid RSA-PSS hash");
					return CKR_ARGUMENTS_BAD;
			}

			if (CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != allowedMgf) {
				ERROR_MSG("Hash and MGF don't match");
				return CKR_ARGUMENTS_BAD;
			}

			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA_1 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA1_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA1;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA224 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA224_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA224;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA256 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA256_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA256;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA384 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA384_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA384;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA512 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA512_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA512;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_ECC
		case CKM_ECDSA:
			mechanism = AsymMech::ECDSA;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA1:
			mechanism = AsymMech::ECDSA_SHA1;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA224:
			mechanism = AsymMech::ECDSA_SHA224;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA256:
			mechanism = AsymMech::ECDSA_SHA256;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA384:
			mechanism = AsymMech::ECDSA_SHA384;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA512:
			mechanism = AsymMech::ECDSA_SHA512;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
#endif
#ifdef WITH_EDDSA
		case CKM_EDDSA:
			mechanism = AsymMech::EDDSA;
			bAllowMultiPartOp = false;
			isEDDSA = true;
			break;
#endif
		case CKM_ML_DSA:
		{
			mechanism = AsymMech::MLDSA;
			bAllowMultiPartOp = false;
			isMLDSA = true;
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			param = &mldsaSignParam;
			paramLen = sizeof(mldsaSignParam);
			break;
		}
		case CKM_HASH_ML_DSA:
		{
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
			{
				ERROR_MSG("CKM_HASH_ML_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::HASH_MLDSA;
			bAllowMultiPartOp = false;
			isMLDSA = true;
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			// For generic CKM_HASH_ML_DSA, hash comes from param struct
			CK_HASH_SIGN_ADDITIONAL_CONTEXT* hctx =
				(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;
			switch (hctx->hash)
			{
				case CKM_SHA224:   mldsaSignParam.hashAlg = HashAlgo::SHA224;   break;
				case CKM_SHA256:   mldsaSignParam.hashAlg = HashAlgo::SHA256;   break;
				case CKM_SHA384:   mldsaSignParam.hashAlg = HashAlgo::SHA384;   break;
				case CKM_SHA512:   mldsaSignParam.hashAlg = HashAlgo::SHA512;   break;
				case CKM_SHA3_224: mldsaSignParam.hashAlg = HashAlgo::SHA3_224; break;
				case CKM_SHA3_256: mldsaSignParam.hashAlg = HashAlgo::SHA3_256; break;
				case CKM_SHA3_384: mldsaSignParam.hashAlg = HashAlgo::SHA3_384; break;
				case CKM_SHA3_512: mldsaSignParam.hashAlg = HashAlgo::SHA3_512; break;
				default:
					ERROR_MSG("Unsupported hash 0x%08lx for CKM_HASH_ML_DSA", hctx->hash);
					return CKR_ARGUMENTS_BAD;
			}
			param = &mldsaSignParam;
			paramLen = sizeof(mldsaSignParam);
			break;
		}
#define HASH_MLDSA_CASE(CKM_CONST, MECH_ENUM, HASH_ALGO) \
		case CKM_CONST: \
		{ \
			mechanism = AsymMech::MECH_ENUM; \
			bAllowMultiPartOp = false; \
			isMLDSA = true; \
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam); \
			if (rv2 != CKR_OK) return rv2; \
			mldsaSignParam.preHash = true; \
			mldsaSignParam.hashAlg = HashAlgo::HASH_ALGO; \
			param = &mldsaSignParam; \
			paramLen = sizeof(mldsaSignParam); \
			break; \
		}
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA224,  HASH_MLDSA_SHA224,  SHA224)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA256,  HASH_MLDSA_SHA256,  SHA256)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA384,  HASH_MLDSA_SHA384,  SHA384)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA512,  HASH_MLDSA_SHA512,  SHA512)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_224, HASH_MLDSA_SHA3_224, SHA3_224)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_256, HASH_MLDSA_SHA3_256, SHA3_256)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_384, HASH_MLDSA_SHA3_384, SHA3_384)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_512, HASH_MLDSA_SHA3_512, SHA3_512)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHAKE128, HASH_MLDSA_SHAKE128, SHAKE128)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHAKE256, HASH_MLDSA_SHAKE256, SHAKE256)
#undef HASH_MLDSA_CASE
		case CKM_SLH_DSA:
			mechanism = AsymMech::SLHDSA;
			bAllowMultiPartOp = false;
			isSLHDSA = true;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PrivateKey* privateKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#ifdef WITH_ECC
	else if (isECDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getECPrivateKey((ECPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
#ifdef WITH_EDDSA
	else if (isEDDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getEDPrivateKey((EDPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	else if (isMLDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getMLDSAPrivateKey((MLDSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else if (isSLHDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getSLHDSAPrivateKey((SLHDSAPrivateKey*)privateKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
        }

	// Initialize signing
	if (bAllowMultiPartOp && !asymCrypto->signInit(privateKey,mechanism,param,paramLen))
	{
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	// Check if re-authentication is required
	if (key->getBooleanValue(CKA_ALWAYS_AUTHENTICATE, false))
	{
		session->setReAuthentication(true);
	}

	if (param != NULL && paramLen > 0 && !session->setParameters(param, paramLen))
	{
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_HOST_MEMORY;
	}

	session->setOpType(SESSION_OP_SIGN);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(bAllowMultiPartOp);
	session->setAllowSinglePartOp(true);
	session->setPrivateKey(privateKey);

	return CKR_OK;
}

// Initialise a signing operation using the specified key and mechanism
CK_RV SoftHSM::C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (isMacMechanism(pMechanism))
		return MacSignInit(hSession, pMechanism, hKey);
	else
		return AsymSignInit(hSession, pMechanism, hKey);
}

// MacAlgorithm version of C_Sign
static CK_RV MacSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Sign the data
	if (!mac->signUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the signature
	ByteString signature;
	if (!mac->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_Sign
static CK_RV AsymSign(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PrivateKey* privateKey = session->getPrivateKey();
	size_t paramLen;
	void* param = session->getParameters(paramLen);
	if (asymCrypto == NULL || !session->getAllowSinglePartOp() || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data;

	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (mechanism == AsymMech::RSA) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);
	ByteString signature;

	// Sign the data
	if (session->getAllowMultiPartOp())
	{
		if (!asymCrypto->signUpdate(data) ||
		    !asymCrypto->signFinal(signature))
		{
			session->resetOp();
			return CKR_GENERAL_ERROR;
		}
	}
	else if (!asymCrypto->sign(privateKey,data,signature,mechanism,param,paramLen))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// Sign the data in a single pass operation
CK_RV SoftHSM::C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSign(session, pData, ulDataLen,
			       pSignature, pulSignatureLen);
	else
		return AsymSign(session, pData, ulDataLen,
				pSignature, pulSignatureLen);
}

// MacAlgorithm version of C_SignUpdate
static CK_RV MacSignUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Sign the data
	if (!mac->signUpdate(part))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignUpdate
static CK_RV AsymSignUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	if (asymCrypto == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Sign the data
	if (!asymCrypto->signUpdate(part))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running signing operation with additional data
CK_RV SoftHSM::C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSignUpdate(session, pPart, ulPartLen);
	else
		return AsymSignUpdate(session, pPart, ulPartLen);
}

// MacAlgorithm version of C_SignFinal
static CK_RV MacSignFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString signature;
	if (!mac->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_SignFinal
static CK_RV AsymSignFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PrivateKey* privateKey = session->getPrivateKey();
	if (asymCrypto == NULL || privateKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check if re-authentication is required
	if (session->getReAuthentication())
	{
		session->resetOp();
		return CKR_USER_NOT_LOGGED_IN;
	}

	// Size of the signature
	CK_ULONG size = privateKey->getOutputLength();
	if (pSignature == NULL_PTR)
	{
		*pulSignatureLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulSignatureLen < size)
	{
		*pulSignatureLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the signature
	ByteString signature;
	if (!asymCrypto->signFinal(signature))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (signature.size() != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pSignature, signature.byte_str(), size);
	*pulSignatureLen = size;

	session->resetOp();
	return CKR_OK;
}

// Finalise a running signing operation and return the signature
CK_RV SoftHSM::C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_SIGN || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacSignFinal(session, pSignature, pulSignatureLen);
	else
		return AsymSignFinal(session, pSignature, pulSignatureLen);
}

// Initialise a signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	std::shared_ptr<Session> sessionGuard; Session* session;
	{ CK_RV rv = acquireSession(hSession, sessionGuard, session); if (rv != CKR_OK) return rv; }

	// CKM_RSA_X_509 recovery is not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single part signing operation that allows recovery of the signed data
CK_RV SoftHSM::C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pData*/, CK_ULONG /*ulDataLen*/, CK_BYTE_PTR /*pSignature*/, CK_ULONG_PTR /*pulSignatureLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// CKM_RSA_X_509 recovery is not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// MacAlgorithm version of C_VerifyInit
CK_RV SoftHSM::MacVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_VERIFY, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Resolve mechanism → algorithm + key-type check via lookup table (H3).
	MacAlgo::Type algo = MacAlgo::Unknown;
	size_t minSize = 0;
	CK_RV mechRv = resolveMacMech(pMechanism->mechanism, keyType, algo, minSize);
	if (mechRv != CKR_OK) return mechRv;

	MacAlgorithm* mac = CryptoFactory::i()->getMacAlgorithm(algo);
	if (mac == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* pubkey = new SymmetricKey();

	if (getSymmetricKey(pubkey, token, key) != CKR_OK)
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_GENERAL_ERROR;
	}

	// Check key size
	pubkey->setBitLen(pubkey->getKeyBits().size() * 8);

	if (pubkey->getBitLen() < (minSize * 8))
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_KEY_SIZE_RANGE;
	}

	// Initialize verifying
	if (!mac->verifyInit(pubkey))
	{
		mac->recycleKey(pubkey);
		CryptoFactory::i()->recycleMacAlgorithm(mac);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_VERIFY);
	session->setMacOp(mac);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(pubkey);

	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyInit
CK_RV SoftHSM::AsymVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_VERIFY, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	void* param = NULL;
	size_t paramLen = 0;
	RSA_PKCS_PSS_PARAMS pssParam;
	MLDSA_SIGN_PARAMS mldsaSignParam;
	memset(&mldsaSignParam, 0, sizeof(mldsaSignParam));
	bool bAllowMultiPartOp;
	bool isRSA = false;
#ifdef WITH_ECC
	bool isECDSA = false;
#endif
#ifdef WITH_EDDSA
	bool isEDDSA = false;
#endif
	bool isMLDSA = false;
	bool isSLHDSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mechanism = AsymMech::RSA_PKCS;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			mechanism = AsymMech::RSA;
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#ifndef WITH_FIPS
		case CKM_MD5_RSA_PKCS:
			mechanism = AsymMech::RSA_MD5_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA1_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA224_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA256_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA384_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS:
			mechanism = AsymMech::RSA_SHA512_PKCS;
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_RAW_PSS
		case CKM_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_PKCS_PSS;

			unsigned long expectedMgf;
			switch(CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg) {
				case CKM_SHA_1:
					pssParam.hashAlg = HashAlgo::SHA1;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
					expectedMgf = CKG_MGF1_SHA1;
					break;
				case CKM_SHA224:
					pssParam.hashAlg = HashAlgo::SHA224;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
					expectedMgf = CKG_MGF1_SHA224;
					break;
				case CKM_SHA256:
					pssParam.hashAlg = HashAlgo::SHA256;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
					expectedMgf = CKG_MGF1_SHA256;
					break;
				case CKM_SHA384:
					pssParam.hashAlg = HashAlgo::SHA384;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
					expectedMgf = CKG_MGF1_SHA384;
					break;
				case CKM_SHA512:
					pssParam.hashAlg = HashAlgo::SHA512;
					pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
					expectedMgf = CKG_MGF1_SHA512;
					break;
				default:
					return CKR_ARGUMENTS_BAD;
			}

			if (CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != expectedMgf) {
				return CKR_ARGUMENTS_BAD;
			}

			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = false;
			isRSA = true;
			break;
#endif
		case CKM_SHA1_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA_1 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA1)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA1_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA1;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA1;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA224 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA224)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA224_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA224;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA224;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA256 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA256)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA256_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA256;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA256;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA384 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA384)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA384_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA384;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA384;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->hashAlg != CKM_SHA512 ||
			    CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->mgf != CKG_MGF1_SHA512)
			{
				ERROR_MSG("Invalid parameters");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::RSA_SHA512_PKCS_PSS;
			pssParam.hashAlg = HashAlgo::SHA512;
			pssParam.mgf = AsymRSAMGF::MGF1_SHA512;
			pssParam.sLen = CK_RSA_PKCS_PSS_PARAMS_PTR(pMechanism->pParameter)->sLen;
			param = &pssParam;
			paramLen = sizeof(pssParam);
			bAllowMultiPartOp = true;
			isRSA = true;
			break;
#ifdef WITH_ECC
		case CKM_ECDSA:
			mechanism = AsymMech::ECDSA;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA1:
			mechanism = AsymMech::ECDSA_SHA1;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA224:
			mechanism = AsymMech::ECDSA_SHA224;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA256:
			mechanism = AsymMech::ECDSA_SHA256;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA384:
			mechanism = AsymMech::ECDSA_SHA384;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
		case CKM_ECDSA_SHA512:
			mechanism = AsymMech::ECDSA_SHA512;
			bAllowMultiPartOp = false;
			isECDSA = true;
			break;
#endif
#ifdef WITH_EDDSA
		case CKM_EDDSA:
			mechanism = AsymMech::EDDSA;
			bAllowMultiPartOp = false;
			isEDDSA = true;
			break;
#endif
		case CKM_ML_DSA:
		{
			mechanism = AsymMech::MLDSA;
			bAllowMultiPartOp = false;
			isMLDSA = true;
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			param = &mldsaSignParam;
			paramLen = sizeof(mldsaSignParam);
			break;
		}
		case CKM_HASH_ML_DSA:
		{
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_HASH_SIGN_ADDITIONAL_CONTEXT))
			{
				ERROR_MSG("CKM_HASH_ML_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT");
				return CKR_ARGUMENTS_BAD;
			}
			mechanism = AsymMech::HASH_MLDSA;
			bAllowMultiPartOp = false;
			isMLDSA = true;
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam);
			if (rv2 != CKR_OK) return rv2;
			CK_HASH_SIGN_ADDITIONAL_CONTEXT* hctx =
				(CK_HASH_SIGN_ADDITIONAL_CONTEXT*)pMechanism->pParameter;
			switch (hctx->hash)
			{
				case CKM_SHA224:   mldsaSignParam.hashAlg = HashAlgo::SHA224;   break;
				case CKM_SHA256:   mldsaSignParam.hashAlg = HashAlgo::SHA256;   break;
				case CKM_SHA384:   mldsaSignParam.hashAlg = HashAlgo::SHA384;   break;
				case CKM_SHA512:   mldsaSignParam.hashAlg = HashAlgo::SHA512;   break;
				case CKM_SHA3_224: mldsaSignParam.hashAlg = HashAlgo::SHA3_224; break;
				case CKM_SHA3_256: mldsaSignParam.hashAlg = HashAlgo::SHA3_256; break;
				case CKM_SHA3_384: mldsaSignParam.hashAlg = HashAlgo::SHA3_384; break;
				case CKM_SHA3_512: mldsaSignParam.hashAlg = HashAlgo::SHA3_512; break;
				default:
					ERROR_MSG("Unsupported hash 0x%08lx for CKM_HASH_ML_DSA", hctx->hash);
					return CKR_ARGUMENTS_BAD;
			}
			param = &mldsaSignParam;
			paramLen = sizeof(mldsaSignParam);
			break;
		}
#define HASH_MLDSA_CASE(CKM_CONST, MECH_ENUM, HASH_ALGO) \
		case CKM_CONST: \
		{ \
			mechanism = AsymMech::MECH_ENUM; \
			bAllowMultiPartOp = false; \
			isMLDSA = true; \
			CK_RV rv2 = parseMLDSASignContext(pMechanism, mldsaSignParam); \
			if (rv2 != CKR_OK) return rv2; \
			mldsaSignParam.preHash = true; \
			mldsaSignParam.hashAlg = HashAlgo::HASH_ALGO; \
			param = &mldsaSignParam; \
			paramLen = sizeof(mldsaSignParam); \
			break; \
		}
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA224,  HASH_MLDSA_SHA224,  SHA224)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA256,  HASH_MLDSA_SHA256,  SHA256)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA384,  HASH_MLDSA_SHA384,  SHA384)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA512,  HASH_MLDSA_SHA512,  SHA512)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_224, HASH_MLDSA_SHA3_224, SHA3_224)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_256, HASH_MLDSA_SHA3_256, SHA3_256)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_384, HASH_MLDSA_SHA3_384, SHA3_384)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHA3_512, HASH_MLDSA_SHA3_512, SHA3_512)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHAKE128, HASH_MLDSA_SHAKE128, SHAKE128)
		HASH_MLDSA_CASE(CKM_HASH_ML_DSA_SHAKE256, HASH_MLDSA_SHAKE256, SHAKE256)
#undef HASH_MLDSA_CASE
		case CKM_SLH_DSA:
			mechanism = AsymMech::SLHDSA;
			bAllowMultiPartOp = false;
			isSLHDSA = true;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* asymCrypto = NULL;
	PublicKey* publicKey = NULL;
	if (isRSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getRSAPublicKey((RSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#ifdef WITH_ECC
	else if (isECDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getECPublicKey((ECPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
#ifdef WITH_EDDSA
	else if (isEDDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getEDPublicKey((EDPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	else if (isMLDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getMLDSAPublicKey((MLDSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else if (isSLHDSA)
	{
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);
		if (asymCrypto == NULL) return CKR_MECHANISM_INVALID;

		publicKey = asymCrypto->newPublicKey();
		if (publicKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}

		if (getSLHDSAPublicKey((SLHDSAPublicKey*)publicKey, token, key) != CKR_OK)
		{
			asymCrypto->recyclePublicKey(publicKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
        }

	// Initialize verifying
	if (bAllowMultiPartOp && !asymCrypto->verifyInit(publicKey,mechanism,param,paramLen))
	{
		asymCrypto->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_MECHANISM_INVALID;
	}

	if (param != NULL && paramLen > 0 && !session->setParameters(param, paramLen))
	{
		asymCrypto->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
		return CKR_HOST_MEMORY;
	}

	session->setOpType(SESSION_OP_VERIFY);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(bAllowMultiPartOp);
	session->setAllowSinglePartOp(true);
	session->setPublicKey(publicKey);

	return CKR_OK;
}

// Initialise a verification operation using the specified key and mechanism
CK_RV SoftHSM::C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (isMacMechanism(pMechanism))
		return MacVerifyInit(hSession, pMechanism, hKey);
	else
		return AsymVerifyInit(hSession, pMechanism, hKey);
}

// MacAlgorithm version of C_Verify
static CK_RV MacVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString data(pData, ulDataLen);

	// Verify the data
	if (!mac->verifyUpdate(data))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Get the signature
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the signature
	if (!mac->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_Verify
static CK_RV AsymVerify(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PublicKey* publicKey = session->getPublicKey();
	size_t paramLen;
	void* param = session->getParameters(paramLen);
	if (asymCrypto == NULL || !session->getAllowSinglePartOp() || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = publicKey->getOutputLength();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString data;

	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (mechanism == AsymMech::RSA) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (session->getAllowMultiPartOp())
	{
		if (!asymCrypto->verifyUpdate(data) ||
		    !asymCrypto->verifyFinal(signature))
		{
			session->resetOp();
			return CKR_SIGNATURE_INVALID;
		}
	}
	else if (!asymCrypto->verify(publicKey,data,signature,mechanism,param,paramLen))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// Perform a single pass verification operation
CK_RV SoftHSM::C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerify(session, pData, ulDataLen,
				 pSignature, ulSignatureLen);
	else
		return AsymVerify(session, pData, ulDataLen,
				  pSignature, ulSignatureLen);
}

// MacAlgorithm version of C_VerifyUpdate
static CK_RV MacVerifyUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Verify the data
	if (!mac->verifyUpdate(part))
	{
		// verifyUpdate can't fail for a logical reason, so we assume total breakdown.
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyUpdate
static CK_RV AsymVerifyUpdate(Session* session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	if (asymCrypto == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Get the part
	ByteString part(pPart, ulPartLen);

	// Verify the data
	if (!asymCrypto->verifyUpdate(part))
	{
		// verifyUpdate can't fail for a logical reason, so we assume total breakdown.
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	session->setAllowSinglePartOp(false);
	return CKR_OK;
}

// Update a running verification operation with additional data
CK_RV SoftHSM::C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pPart == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerifyUpdate(session, pPart, ulPartLen);
	else
		return AsymVerifyUpdate(session, pPart, ulPartLen);
}

// MacAlgorithm version of C_SignFinal
static CK_RV MacVerifyFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	MacAlgorithm* mac = session->getMacOp();
	if (mac == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = mac->getMacSize();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the signature
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (!mac->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// AsymmetricAlgorithm version of C_VerifyFinal
static CK_RV AsymVerifyFinal(Session* session, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the signature
	CK_ULONG size = publicKey->getOutputLength();

	// Check buffer size
	if (ulSignatureLen != size)
	{
		ERROR_MSG("The size of the signature differs from the size of the mechanism");
		session->resetOp();
		return CKR_SIGNATURE_LEN_RANGE;
	}

	// Get the data
	ByteString signature(pSignature, ulSignatureLen);

	// Verify the data
	if (!asymCrypto->verifyFinal(signature))
	{
		session->resetOp();
		return CKR_SIGNATURE_INVALID;
	}

	session->resetOp();
	return CKR_OK;
}

// Finalise the verification operation and check the signature
CK_RV SoftHSM::C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_VERIFY || !session->getAllowMultiPartOp())
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getMacOp() != NULL)
		return MacVerifyFinal(session, pSignature, ulSignatureLen);
	else
		return AsymVerifyFinal(session, pSignature, ulSignatureLen);
}

// ── PKCS#11 v3.0: one-shot message signing ───────────────────────────────────────────────────

// C_MessageSignInit — initialise a multi-message sign context (PKCS#11 v3.0 §5.8.1)
CK_RV SoftHSM::C_MessageSignInit(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	// Reuse existing asymmetric-sign init; it validates the key, mechanism, and session
	CK_RV rv = AsymSignInit(hSession, pMechanism, hKey);
	if (rv != CKR_OK) return rv;

	// Upgrade op type so C_Sign cannot be called against this context
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	session->setOpType(SESSION_OP_MESSAGE_SIGN);
	return CKR_OK;
}

// C_SignMessage — one-shot message sign (PKCS#11 v3.0 §5.8.2)
// pParameter / ulParameterLen are mechanism-specific; NULL/0 for ML-DSA and SLH-DSA.
CK_RV SoftHSM::C_SignMessage(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulSignatureLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	// Per-message ML-DSA parameter override (PKCS#11 v3.2 §5.8.5)
	// Allows overriding context string and hedging for this specific message
	if (pParameter != NULL_PTR && ulParameterLen > 0)
	{
		AsymMech::Type mech = session->getMechanism();
		if (mech >= AsymMech::MLDSA && mech <= AsymMech::HASH_MLDSA_SHAKE256)
		{
			// Preserve pre-hash settings from init mechanism
			size_t existingLen;
			void* existing = session->getParameters(existingLen);

			MLDSA_SIGN_PARAMS mldsaParam;
			CK_MECHANISM fakeMech;
			fakeMech.mechanism = CKM_ML_DSA;
			fakeMech.pParameter = pParameter;
			fakeMech.ulParameterLen = ulParameterLen;
			CK_RV rv2 = parseMLDSASignContext(&fakeMech, mldsaParam);
			if (rv2 != CKR_OK) return rv2;

			if (existing && existingLen == sizeof(MLDSA_SIGN_PARAMS))
			{
				MLDSA_SIGN_PARAMS* initParams = (MLDSA_SIGN_PARAMS*)existing;
				mldsaParam.preHash = initParams->preHash;
				mldsaParam.hashAlg = initParams->hashAlg;
			}
			if (!session->setParameters(&mldsaParam, sizeof(mldsaParam)))
				return CKR_HOST_MEMORY;
		}
	}

	// AsymSign expects SESSION_OP_SIGN; temporarily satisfy that check.
	// AsymSign calls resetOp() before returning (both size-query and real sign),
	// so we must unconditionally restore MESSAGE_SIGN on success to keep the
	// multi-message contract (caller may send further messages under this session).
	session->setOpType(SESSION_OP_SIGN);
	CK_RV rv = AsymSign(session, pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK)
		session->setOpType(SESSION_OP_MESSAGE_SIGN);

	return rv;
}

// C_MessageSignFinal — end a multi-message sign context (PKCS#11 v3.0 §5.8.6)
CK_RV SoftHSM::C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;
	session->resetOp();
	return CKR_OK;
}

// C_MessageVerifyInit — initialise a multi-message verify context (PKCS#11 v3.0 §5.8.7)
CK_RV SoftHSM::C_MessageVerifyInit(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = AsymVerifyInit(hSession, pMechanism, hKey);
	if (rv != CKR_OK) return rv;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	session->setOpType(SESSION_OP_MESSAGE_VERIFY);
	return CKR_OK;
}

// C_VerifyMessage — one-shot message verify (PKCS#11 v3.2 §5.8.8)
// pParameter / ulParameterLen allow per-message ML-DSA parameter override.
CK_RV SoftHSM::C_VerifyMessage(CK_SESSION_HANDLE hSession,
	CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pData == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pSignature == NULL_PTR) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	// Per-message ML-DSA parameter override (PKCS#11 v3.2 §5.8.8)
	if (pParameter != NULL_PTR && ulParameterLen > 0)
	{
		AsymMech::Type mech = session->getMechanism();
		if (mech >= AsymMech::MLDSA && mech <= AsymMech::HASH_MLDSA_SHAKE256)
		{
			size_t existingLen;
			void* existing = session->getParameters(existingLen);

			MLDSA_SIGN_PARAMS mldsaParam;
			CK_MECHANISM fakeMech;
			fakeMech.mechanism = CKM_ML_DSA;
			fakeMech.pParameter = pParameter;
			fakeMech.ulParameterLen = ulParameterLen;
			CK_RV rv2 = parseMLDSASignContext(&fakeMech, mldsaParam);
			if (rv2 != CKR_OK) return rv2;

			if (existing && existingLen == sizeof(MLDSA_SIGN_PARAMS))
			{
				MLDSA_SIGN_PARAMS* initParams = (MLDSA_SIGN_PARAMS*)existing;
				mldsaParam.preHash = initParams->preHash;
				mldsaParam.hashAlg = initParams->hashAlg;
			}
			if (!session->setParameters(&mldsaParam, sizeof(mldsaParam)))
				return CKR_HOST_MEMORY;
		}
	}

	// AsymVerify expects SESSION_OP_VERIFY; temporarily satisfy that check.
	// AsymVerify calls resetOp() before returning, so restore MESSAGE_VERIFY on
	// success to maintain the multi-message contract.
	session->setOpType(SESSION_OP_VERIFY);
	CK_RV rv = AsymVerify(session, pData, ulDataLen, pSignature, ulSignatureLen);
	if (rv == CKR_OK)
		session->setOpType(SESSION_OP_MESSAGE_VERIFY);
	return rv;
}

// C_MessageVerifyFinal — end a multi-message verify context (PKCS#11 v3.0 §5.8.12)
CK_RV SoftHSM::C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	if (session->getOpType() != SESSION_OP_MESSAGE_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;
	session->resetOp();
	return CKR_OK;
}

// ─────────────────────────────────────────────────────────────────────────────

// Initialise a verification operation the allows recovery of the signed data from the signature
CK_RV SoftHSM::C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR /*pMechanism*/, CK_OBJECT_HANDLE /*hKey*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	std::shared_ptr<Session> sessionGuard; Session* session;
	{ CK_RV rv = acquireSession(hSession, sessionGuard, session); if (rv != CKR_OK) return rv; }

	// CKM_RSA_X_509 recovery is not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Perform a single part verification operation and recover the signed data
CK_RV SoftHSM::C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pSignature*/, CK_ULONG /*ulSignatureLen*/, CK_BYTE_PTR /*pData*/, CK_ULONG_PTR /*pulDataLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// CKM_RSA_X_509 recovery is not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part encryption and digesting operation
CK_RV SoftHSM::C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG_PTR /*pulEncryptedPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Combined multi-part operations are not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part decryption and digesting operation
CK_RV SoftHSM::C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pDecryptedPart*/, CK_ULONG_PTR /*pulDecryptedPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Combined multi-part operations are not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part signing and encryption operation
CK_RV SoftHSM::C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pPart*/, CK_ULONG /*ulPartLen*/, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG_PTR /*pulEncryptedPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Combined multi-part operations are not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Update a running multi-part decryption and verification operation
CK_RV SoftHSM::C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR /*pEncryptedPart*/, CK_ULONG /*ulEncryptedPartLen*/, CK_BYTE_PTR /*pPart*/, CK_ULONG_PTR /*pulPartLen*/)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Combined multi-part operations are not planned in the current Phase 0â6 roadmap.
	// Track as a future enhancement: https://github.com/pqctoday/softhsmv3/issues
	return CKR_FUNCTION_NOT_SUPPORTED;
}


