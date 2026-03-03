/*
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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
 OSSLRSAPrivateKey.cpp

 OpenSSL RSA private key class — EVP_PKEY throughout (OpenSSL 3.x)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLRSAPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <string.h>

// Constructors
OSSLRSAPrivateKey::OSSLRSAPrivateKey()
{
	pkey = NULL;
}

OSSLRSAPrivateKey::OSSLRSAPrivateKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLRSAPrivateKey::~OSSLRSAPrivateKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLRSAPrivateKey::type = "OpenSSL RSA Private Key";

// Check if the key is of the given type
bool OSSLRSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Set from OpenSSL EVP_PKEY representation
void OSSLRSAPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	BIGNUM* bn = NULL;

#define EXTRACT_BN(param, setter) \
	if (EVP_PKEY_get_bn_param(inPKEY, param, &bn) && bn) { \
		ByteString val = OSSL::bn2ByteString(bn); \
		setter(val); \
		BN_clear_free(bn); \
		bn = NULL; \
	}

	EXTRACT_BN(OSSL_PKEY_PARAM_RSA_N,            setN)
	EXTRACT_BN(OSSL_PKEY_PARAM_RSA_E,            setE)
	EXTRACT_BN(OSSL_PKEY_PARAM_RSA_D,            setD)
	EXTRACT_BN(OSSL_PKEY_PARAM_RSA_FACTOR1,      setP)
	EXTRACT_BN(OSSL_PKEY_PARAM_RSA_FACTOR2,      setQ)
	EXTRACT_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1,    setDP1)
	EXTRACT_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2,    setDQ1)
	EXTRACT_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, setPQ)

#undef EXTRACT_BN
}

// Setters for the RSA private key components
void OSSLRSAPrivateKey::setP(const ByteString& inP)
{
	RSAPrivateKey::setP(inP);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLRSAPrivateKey::setQ(const ByteString& inQ)
{
	RSAPrivateKey::setQ(inQ);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLRSAPrivateKey::setPQ(const ByteString& inPQ)
{
	RSAPrivateKey::setPQ(inPQ);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLRSAPrivateKey::setDP1(const ByteString& inDP1)
{
	RSAPrivateKey::setDP1(inDP1);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLRSAPrivateKey::setDQ1(const ByteString& inDQ1)
{
	RSAPrivateKey::setDQ1(inDQ1);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLRSAPrivateKey::setD(const ByteString& inD)
{
	RSAPrivateKey::setD(inD);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

// Setters for the RSA public key components
void OSSLRSAPrivateKey::setN(const ByteString& inN)
{
	RSAPrivateKey::setN(inN);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLRSAPrivateKey::setE(const ByteString& inE)
{
	RSAPrivateKey::setE(inE);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

// Retrieve the OpenSSL EVP_PKEY representation of the key (built lazily)
EVP_PKEY* OSSLRSAPrivateKey::getOSSLKey()
{
	if (pkey != NULL)
		return pkey;

	if (n.size() == 0 || e.size() == 0 || d.size() == 0)
		return NULL;

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
		return NULL;

	// Required components
	BIGNUM* bn_n  = OSSL::byteString2bn(n);
	BIGNUM* bn_e  = OSSL::byteString2bn(e);
	BIGNUM* bn_d  = OSSL::byteString2bn(d);
	// Optional CRT components
	BIGNUM* bn_p  = p.size()   ? OSSL::byteString2bn(p)   : NULL;
	BIGNUM* bn_q  = q.size()   ? OSSL::byteString2bn(q)   : NULL;
	BIGNUM* bn_dp = dp1.size() ? OSSL::byteString2bn(dp1) : NULL;
	BIGNUM* bn_dq = dq1.size() ? OSSL::byteString2bn(dq1) : NULL;
	BIGNUM* bn_qi = pq.size()  ? OSSL::byteString2bn(pq)  : NULL;

	bool ok = (bn_n && bn_e && bn_d);
	if (ok) ok = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) == 1);
	if (ok) ok = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e) == 1);
	if (ok) ok = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, bn_d) == 1);
	if (ok && bn_p)  ok = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1,      bn_p)  == 1);
	if (ok && bn_q)  ok = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2,      bn_q)  == 1);
	if (ok && bn_dp) ok = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1,    bn_dp) == 1);
	if (ok && bn_dq) ok = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2,    bn_dq) == 1);
	if (ok && bn_qi) ok = (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, bn_qi) == 1);

	if (!ok)
	{
		BN_clear_free(bn_n);  BN_clear_free(bn_e);  BN_clear_free(bn_d);
		BN_clear_free(bn_p);  BN_clear_free(bn_q);
		BN_clear_free(bn_dp); BN_clear_free(bn_dq); BN_clear_free(bn_qi);
		OSSL_PARAM_BLD_free(bld);
		return NULL;
	}

	// BIGNUMs must stay alive until OSSL_PARAM_BLD_to_param() copies them
	OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);

	BN_clear_free(bn_n);  BN_clear_free(bn_e);  BN_clear_free(bn_d);
	BN_clear_free(bn_p);  BN_clear_free(bn_q);
	BN_clear_free(bn_dp); BN_clear_free(bn_dq); BN_clear_free(bn_qi);

	if (params == NULL)
		return NULL;

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL)
	{
		OSSL_PARAM_free(params);
		return NULL;
	}

	if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
	{
		ERROR_MSG("Could not build EVP_PKEY for RSA private key (0x%08X)", ERR_get_error());
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);

	return pkey;
}

// Encode into PKCS#8 DER
ByteString OSSLRSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return der;

	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(key);
	if (p8inf == NULL) return der;

	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char* priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len) der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLRSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* key = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (key == NULL) return false;
	setFromOSSL(key);
	EVP_PKEY_free(key);
	return true;
}
