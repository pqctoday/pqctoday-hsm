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
 SoftHSM_cipher.cpp

 PKCS#11 encryption/decryption: SymEncryptInit, AsymEncryptInit, C_EncryptInit,
 C_Encrypt, C_EncryptUpdate, C_EncryptFinal, SymDecryptInit, AsymDecryptInit,
 C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "CryptoFactory.h"
#include "cryptoki.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "SymmetricAlgorithm.h"
#include "AESKey.h"

static bool isSymMechanism(CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL_PTR) return false;

	switch(pMechanism->mechanism) {
		case CKM_AES_ECB:
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
		case CKM_AES_CTR:
		case CKM_AES_GCM:
			return true;
		default:
			return false;
	}
}

// SymAlgorithm version of C_EncryptInit
CK_RV SoftHSM::SymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_ENCRYPT, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	size_t counterBits = 0;
	ByteString aad;
	size_t tagBytes = 0;
	switch(pMechanism->mechanism) {
		case CKM_AES_ECB:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
		case CKM_AES_CBC:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		case CKM_AES_CBC_PAD:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		case CKM_AES_CTR:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CTR;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS))
			{
				DEBUG_MSG("CTR mode requires a counter block");
				return CKR_ARGUMENTS_BAD;
			}
			counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
			if (counterBits == 0 || counterBits > 128)
			{
				DEBUG_MSG("Invalid ulCounterBits");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
			break;
		case CKM_AES_GCM:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::GCM;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
			{
				DEBUG_MSG("GCM mode requires parameters");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
			memcpy(&iv[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
			aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0)
				memcpy(&aad[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			tagBytes = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
			if (tagBytes > 128 || tagBytes % 8 != 0)
			{
				DEBUG_MSG("Invalid ulTagBits value");
				return CKR_ARGUMENTS_BAD;
			}
			tagBytes = tagBytes / 8;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();

	if (getSymmetricKey(secretkey, token, key) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize encryption
	if (!cipher->encryptInit(secretkey, mode, iv, padding, counterBits, aad, tagBytes))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_ENCRYPT);
	session->setSymmetricCryptoOp(cipher);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(secretkey);

	return CKR_OK;
}

// AsymAlgorithm version of C_EncryptInit
CK_RV SoftHSM::AsymEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_ENCRYPT, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism;
	bool isRSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			mechanism = AsymMech::RSA_PKCS;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			mechanism = AsymMech::RSA;
			isRSA = true;
			break;
		case CKM_RSA_PKCS_OAEP:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			rv = MechParamCheckRSAPKCSOAEP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			{
				CK_RSA_PKCS_OAEP_PARAMS_PTR oaepP = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;
				switch (oaepP->hashAlg) {
					case CKM_SHA224: mechanism = AsymMech::RSA_PKCS_OAEP_SHA224; break;
					case CKM_SHA256: mechanism = AsymMech::RSA_PKCS_OAEP_SHA256; break;
					case CKM_SHA384: mechanism = AsymMech::RSA_PKCS_OAEP_SHA384; break;
					case CKM_SHA512: mechanism = AsymMech::RSA_PKCS_OAEP_SHA512; break;
					default:         mechanism = AsymMech::RSA_PKCS_OAEP;        break;
				}
			}
			isRSA = true;
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
	else
	{
		return CKR_MECHANISM_INVALID;
        }

	session->setOpType(SESSION_OP_ENCRYPT);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setPublicKey(publicKey);

	return CKR_OK;
}

// Initialise encryption using the specified object and mechanism
CK_RV SoftHSM::C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (isSymMechanism(pMechanism))
		return SymEncryptInit(hSession, pMechanism, hKey);
	else
		return AsymEncryptInit(hSession, pMechanism, hKey);
}

// SymAlgorithm version of C_Encrypt
static CK_RV SymEncrypt(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	CK_ULONG maxSize = ulDataLen + cipher->getTagBytes();
	if (cipher->isBlockCipher())
	{
		CK_ULONG remainder = ulDataLen % cipher->getBlockSize();
		if (cipher->getPaddingMode() == false && remainder != 0)
		{
			session->resetOp();
			return CKR_DATA_LEN_RANGE;
		}

		// Round up to block size
		if (remainder != 0)
		{
			maxSize = ulDataLen + cipher->getBlockSize() - remainder;
		}
		else if (cipher->getPaddingMode() == true)
		{
			maxSize = ulDataLen + cipher->getBlockSize();
		}
	}
	if (!cipher->checkMaximumBytes(ulDataLen))
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}

	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulEncryptedDataLen < maxSize)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);
	ByteString encryptedData;

	// Encrypt the data
	if (!cipher->encryptUpdate(data, encryptedData))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Finalize encryption
	ByteString encryptedFinal;
	if (!cipher->encryptFinal(encryptedFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	encryptedData += encryptedFinal;
	encryptedData.resize(maxSize);

	memcpy(pEncryptedData, encryptedData.byte_str(), encryptedData.size());
	*pulEncryptedDataLen = encryptedData.size();

	session->resetOp();
	return CKR_OK;
}

// AsymAlgorithm version of C_Encrypt
static CK_RV AsymEncrypt(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PublicKey* publicKey = session->getPublicKey();
	if (asymCrypto == NULL || !session->getAllowSinglePartOp() || publicKey == NULL)
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Size of the encrypted data
	CK_ULONG size = publicKey->getOutputLength();

	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulEncryptedDataLen < size)
	{
		*pulEncryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data;
	ByteString encryptedData;

	// We must allow input length <= k and therfore need to prepend the data with zeroes.
	if (mechanism == AsymMech::RSA) {
		data.wipe(size-ulDataLen);
	}

	data += ByteString(pData, ulDataLen);

	// Encrypt the data
	if (!asymCrypto->encrypt(publicKey,data,encryptedData,mechanism))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}

	// Check size
	if (encryptedData.size() != size)
	{
		ERROR_MSG("The size of the encrypted data differs from the size of the mechanism");
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	memcpy(pEncryptedData, encryptedData.byte_str(), size);
	*pulEncryptedDataLen = size;

	session->resetOp();
	return CKR_OK;
}

// Perform a single operation encryption operation in the specified session
CK_RV SoftHSM::C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((pData == NULL_PTR) || (pulEncryptedDataLen == NULL_PTR))
	{
		// Fix issue 585
		session->resetOp();

		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymEncrypt(session, pData, ulDataLen,
				  pEncryptedData, pulEncryptedDataLen);
	else
		return AsymEncrypt(session, pData, ulDataLen,
				   pEncryptedData, pulEncryptedDataLen);
}

// SymAlgorithm version of C_EncryptUpdate
static CK_RV SymEncryptUpdate(Session* session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	size_t blockSize = cipher->getBlockSize();
	size_t remainingSize = cipher->getBufferSize();
	// Guard against integer overflow before adding ulDataLen + remainingSize.
	if (ulDataLen > (~(CK_ULONG)0 - (CK_ULONG)remainingSize))
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}
	CK_ULONG maxSize = ulDataLen + (CK_ULONG)remainingSize;
	if (cipher->isBlockCipher())
	{
		CK_ULONG nrOfBlocks = (ulDataLen + (CK_ULONG)remainingSize) / (CK_ULONG)blockSize;
		maxSize = nrOfBlocks * (CK_ULONG)blockSize;
	}
	if (!cipher->checkMaximumBytes(ulDataLen))
	{
		session->resetOp();
		return CKR_DATA_LEN_RANGE;
	}

	// Check data size
	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = maxSize;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulEncryptedDataLen < maxSize)
	{
		DEBUG_MSG("ulDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x",
			  ulDataLen, *pulEncryptedDataLen, blockSize, remainingSize, maxSize);
		*pulEncryptedDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pData, ulDataLen);
	ByteString encryptedData;

	// Encrypt the data
	if (!cipher->encryptUpdate(data, encryptedData))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	DEBUG_MSG("ulDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x  encryptedData.size(): %#5x",
		  ulDataLen, *pulEncryptedDataLen, blockSize, remainingSize, maxSize, encryptedData.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulEncryptedDataLen < encryptedData.size())
	{
		session->resetOp();
		ERROR_MSG("EncryptUpdate returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
			  *pulEncryptedDataLen, encryptedData.size());
		return CKR_GENERAL_ERROR;
	}

	if (encryptedData.size() > 0)
	{
		memcpy(pEncryptedData, encryptedData.byte_str(), encryptedData.size());
	}
	*pulEncryptedDataLen = encryptedData.size();

	return CKR_OK;
}

// Feed data to the running encryption operation in a session
CK_RV SoftHSM::C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((pData == NULL_PTR) || (pulEncryptedDataLen == NULL_PTR))
	{
		session->resetOp();

		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymEncryptUpdate(session, pData, ulDataLen,
				  pEncryptedData, pulEncryptedDataLen);
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
}

// SymAlgorithm version of C_EncryptFinal
static CK_RV SymEncryptFinal(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check data size
	size_t remainingSize = cipher->getBufferSize() + cipher->getTagBytes();
	CK_ULONG size = remainingSize;
	if (cipher->isBlockCipher())
	{
		size_t blockSize = cipher->getBlockSize();
		bool isPadding = cipher->getPaddingMode();
		if ((remainingSize % blockSize) != 0 && !isPadding)
		{
			session->resetOp();
			DEBUG_MSG("Remaining buffer size is not an integral of the block size. Block size: %#2x  Remaining size: %#2x",
				  blockSize, remainingSize);
			return CKR_DATA_LEN_RANGE;
		}
		// when padding: an integral of the block size that is longer than the remaining data.
		size = isPadding ? ((remainingSize + blockSize) / blockSize) * blockSize : remainingSize;
	}

	// Give required output buffer size.
	if (pEncryptedData == NULL_PTR)
	{
		*pulEncryptedDataLen = size;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulEncryptedDataLen < size)
	{
		DEBUG_MSG("output buffer size: %#5x  size: %#5x",
			  *pulEncryptedDataLen, size);
		*pulEncryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Finalize encryption
	ByteString encryptedFinal;
	if (!cipher->encryptFinal(encryptedFinal))
	{
		session->resetOp();
		return CKR_GENERAL_ERROR;
	}
	DEBUG_MSG("output buffer size: %#2x  size: %#2x  encryptedFinal.size(): %#2x",
		  *pulEncryptedDataLen, size, encryptedFinal.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulEncryptedDataLen < encryptedFinal.size())
	{
		session->resetOp();
		ERROR_MSG("EncryptFinal returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
			  *pulEncryptedDataLen, encryptedFinal.size());
		return CKR_GENERAL_ERROR;
	}

	if (encryptedFinal.size() > 0)
	{
		memcpy(pEncryptedData, encryptedFinal.byte_str(), encryptedFinal.size());
	}
	*pulEncryptedDataLen = encryptedFinal.size();

	session->resetOp();
	return CKR_OK;
}

// Finalise the encryption operation
CK_RV SoftHSM::C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Github issue #469, check NULL_PTR on pulEncryptedDataLen
	if (pulEncryptedDataLen == NULL)
	{
		session->resetOp();
		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_ENCRYPT) return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymEncryptFinal(session, pEncryptedData, pulEncryptedDataLen);
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
}

// SymAlgorithm version of C_DecryptInit
CK_RV SoftHSM::SymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_DECRYPT, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	size_t counterBits = 0;
	ByteString aad;
	size_t tagBytes = 0;
	switch(pMechanism->mechanism) {
		case CKM_AES_ECB:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
		case CKM_AES_CBC:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		case CKM_AES_CBC_PAD:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			padding = true;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen == 0)
			{
				DEBUG_MSG("CBC mode requires an init vector");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(pMechanism->ulParameterLen);
			memcpy(&iv[0], pMechanism->pParameter, pMechanism->ulParameterLen);
			break;
		case CKM_AES_CTR:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::CTR;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_AES_CTR_PARAMS))
			{
				DEBUG_MSG("CTR mode requires a counter block");
				return CKR_ARGUMENTS_BAD;
			}
			counterBits = CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->ulCounterBits;
			if (counterBits == 0 || counterBits > 128)
			{
				DEBUG_MSG("Invalid ulCounterBits");
				return CKR_MECHANISM_PARAM_INVALID;
			}
			iv.resize(16);
			memcpy(&iv[0], CK_AES_CTR_PARAMS_PTR(pMechanism->pParameter)->cb, 16);
			break;
		case CKM_AES_GCM:
			if (keyType != CKK_AES)
				return CKR_KEY_TYPE_INCONSISTENT;
			algo = SymAlgo::AES;
			mode = SymMode::GCM;
			if (pMechanism->pParameter == NULL_PTR ||
			    pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS))
			{
				DEBUG_MSG("GCM mode requires parameters");
				return CKR_ARGUMENTS_BAD;
			}
			iv.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
			memcpy(&iv[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pIv, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulIvLen);
			aad.resize(CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			if (CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen > 0)
				memcpy(&aad[0], CK_GCM_PARAMS_PTR(pMechanism->pParameter)->pAAD, CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulAADLen);
			tagBytes = CK_GCM_PARAMS_PTR(pMechanism->pParameter)->ulTagBits;
			if (tagBytes > 128 || tagBytes % 8 != 0)
			{
				DEBUG_MSG("Invalid ulTagBits value");
				return CKR_ARGUMENTS_BAD;
			}
			tagBytes = tagBytes / 8;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* secretkey = new SymmetricKey();

	if (getSymmetricKey(secretkey, token, key) != CKR_OK)
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

	// Initialize decryption
	if (!cipher->decryptInit(secretkey, mode, iv, padding, counterBits, aad, tagBytes))
	{
		cipher->recycleKey(secretkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	session->setOpType(SESSION_OP_DECRYPT);
	session->setSymmetricCryptoOp(cipher);
	session->setAllowMultiPartOp(true);
	session->setAllowSinglePartOp(true);
	session->setSymmetricKey(secretkey);

	return CKR_OK;
}

// AsymAlgorithm version of C_DecryptInit
CK_RV SoftHSM::AsymDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;

	std::shared_ptr<Session> sessionGuard;
	Session* session; Token* token; OSObject* key;
	CK_RV rv = acquireSessionTokenKey(hSession, hKey, CKA_DECRYPT, pMechanism,
	                                   sessionGuard, session, token, key);
	if (rv != CKR_OK) return rv;

	// Get key info

	// Get key info
	CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);

	// Get the asymmetric algorithm matching the mechanism
	AsymMech::Type mechanism = AsymMech::Unknown;
	bool isRSA = false;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			mechanism = AsymMech::RSA_PKCS;
			isRSA = true;
			break;
		case CKM_RSA_X_509:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			mechanism = AsymMech::RSA;
			isRSA = true;
			break;
		case CKM_RSA_PKCS_OAEP:
			if (keyType != CKK_RSA)
				return CKR_KEY_TYPE_INCONSISTENT;
			rv = MechParamCheckRSAPKCSOAEP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			{
				CK_RSA_PKCS_OAEP_PARAMS_PTR oaepP = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;
				switch (oaepP->hashAlg) {
					case CKM_SHA224: mechanism = AsymMech::RSA_PKCS_OAEP_SHA224; break;
					case CKM_SHA256: mechanism = AsymMech::RSA_PKCS_OAEP_SHA256; break;
					case CKM_SHA384: mechanism = AsymMech::RSA_PKCS_OAEP_SHA384; break;
					case CKM_SHA512: mechanism = AsymMech::RSA_PKCS_OAEP_SHA512; break;
					default:         mechanism = AsymMech::RSA_PKCS_OAEP;        break;
				}
			}
			isRSA = true;
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
	else
	{
		return CKR_MECHANISM_INVALID;
        }

	// Check if re-authentication is required
	if (key->getBooleanValue(CKA_ALWAYS_AUTHENTICATE, false))
	{
		session->setReAuthentication(true);
	}

	session->setOpType(SESSION_OP_DECRYPT);
	session->setAsymmetricCryptoOp(asymCrypto);
	session->setMechanism(mechanism);
	session->setAllowMultiPartOp(false);
	session->setAllowSinglePartOp(true);
	session->setPrivateKey(privateKey);

	return CKR_OK;
}

// Initialise decryption using the specified object
CK_RV SoftHSM::C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (isSymMechanism(pMechanism))
		return SymDecryptInit(hSession, pMechanism, hKey);
	else
		return AsymDecryptInit(hSession, pMechanism, hKey);
}

// SymAlgorithm version of C_Decrypt
static CK_RV SymDecrypt(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowSinglePartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted data size
	if (cipher->isBlockCipher() && ulEncryptedDataLen % cipher->getBlockSize() != 0)
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}
	if (!cipher->checkMaximumBytes(ulEncryptedDataLen))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (pData == NULL_PTR)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < ulEncryptedDataLen)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString encryptedData(pEncryptedData, ulEncryptedDataLen);
	ByteString data;

	// Decrypt the data
	if (!cipher->decryptUpdate(encryptedData,data))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}

	// Finalize decryption
	ByteString dataFinal;
	if (!cipher->decryptFinal(dataFinal))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}
	data += dataFinal;
	if (data.size() > ulEncryptedDataLen)
	{
		data.resize(ulEncryptedDataLen);
	}

	if (data.size() != 0)
	{
		memcpy(pData, data.byte_str(), data.size());
	}
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;

}

// AsymAlgorithm version of C_Decrypt
static CK_RV AsymDecrypt(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	AsymmetricAlgorithm* asymCrypto = session->getAsymmetricCryptoOp();
	AsymMech::Type mechanism = session->getMechanism();
	PrivateKey* privateKey = session->getPrivateKey();
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

	// Size of the data
	CK_ULONG size = privateKey->getOutputLength();
	if (pData == NULL_PTR)
	{
		*pulDataLen = size;
		return CKR_OK;
	}

	// Check buffer size
	if (*pulDataLen < size)
	{
		*pulDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString encryptedData(pEncryptedData, ulEncryptedDataLen);
	ByteString data;

	// Decrypt the data
	if (!asymCrypto->decrypt(privateKey,encryptedData,data,mechanism))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}

	// Check size
	if (data.size() > size)
	{
		ERROR_MSG("The size of the decrypted data exceeds the size of the mechanism");
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}
	if (data.size() != 0)
	{
		memcpy(pData, data.byte_str(), data.size());
	}
	*pulDataLen = data.size();

	session->resetOp();
	return CKR_OK;

}

// Perform a single operation decryption in the given session
CK_RV SoftHSM::C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((pEncryptedData == NULL_PTR) || (pulDataLen == NULL_PTR))
	{
		session->resetOp();

		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymDecrypt(session, pEncryptedData, ulEncryptedDataLen,
				  pData, pulDataLen);
	else
		return AsymDecrypt(session, pEncryptedData, ulEncryptedDataLen,
				   pData, pulDataLen);
}

// SymAlgorithm version of C_DecryptUpdate
static CK_RV SymDecryptUpdate(Session* session, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted data size
	size_t blockSize = cipher->getBlockSize();
	size_t remainingSize = cipher->getBufferSize();
	CK_ULONG maxSize = ulEncryptedDataLen + remainingSize;
	if (cipher->isBlockCipher())
	{
		// There must always be one block left in padding mode if next operation is DecryptFinal.
		// To guarantee that one byte is removed in padding mode when the number of blocks is calculated.
		size_t paddingAdjustByte = cipher->getPaddingMode() ? 1 : 0;
		int nrOfBlocks = (ulEncryptedDataLen + remainingSize - paddingAdjustByte) / blockSize;
		maxSize = nrOfBlocks * blockSize;
	}
	if (!cipher->checkMaximumBytes(ulEncryptedDataLen))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	// Give required output buffer size.
	if (pData == NULL_PTR)
	{
		*pDataLen = maxSize;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pDataLen < maxSize)
	{
		DEBUG_MSG("Output buffer too short   ulEncryptedDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x",
			  ulEncryptedDataLen, *pDataLen, blockSize, remainingSize, maxSize);
		*pDataLen = maxSize;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Get the data
	ByteString data(pEncryptedData, ulEncryptedDataLen);
	ByteString decryptedData;

	// Decrypt the data
	if (!cipher->decryptUpdate(data, decryptedData))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}
	DEBUG_MSG("ulEncryptedDataLen: %#5x  output buffer size: %#5x  blockSize: %#3x  remainingSize: %#4x  maxSize: %#5x  decryptedData.size(): %#5x",
		  ulEncryptedDataLen, *pDataLen, blockSize, remainingSize, maxSize, decryptedData.size());

	// Check output size from crypto. Unrecoverable error if too large.
	if (*pDataLen < decryptedData.size())
	{
		session->resetOp();
		ERROR_MSG("DecryptUpdate returning too much data. Length of output data buffer is %i but %i bytes was returned by the decrypt.",
				*pDataLen, decryptedData.size());
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (decryptedData.size() > 0)
	{
		memcpy(pData, decryptedData.byte_str(), decryptedData.size());
	}
	*pDataLen = decryptedData.size();

	return CKR_OK;
}


// Feed data to the running decryption operation in a session
CK_RV SoftHSM::C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	if ((pEncryptedData == NULL_PTR) || (pDataLen == NULL_PTR))
	{
		session->resetOp();

		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymDecryptUpdate(session, pEncryptedData, ulEncryptedDataLen,
				  pData, pDataLen);
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV SymDecryptFinal(Session* session, CK_BYTE_PTR pDecryptedData, CK_ULONG_PTR pulDecryptedDataLen)
{
	SymmetricAlgorithm* cipher = session->getSymmetricCryptoOp();
	if (cipher == NULL || !session->getAllowMultiPartOp())
	{
		session->resetOp();
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// Check encrypted data size
	size_t remainingSize = cipher->getBufferSize();
	CK_ULONG size = remainingSize;
	if (cipher->isBlockCipher())
	{
		size_t blockSize = cipher->getBlockSize();
		if (remainingSize % blockSize != 0)
		{
			session->resetOp();
			DEBUG_MSG("Remaining data length is not an integral of the block size. Block size: %#2x  Remaining size: %#2x",
				   blockSize, remainingSize);
			return CKR_ENCRYPTED_DATA_LEN_RANGE;
		}
		// It is at least one padding byte. If no padding the all remains will be returned.
		size_t paddingAdjustByte = cipher->getPaddingMode() ? 1 : 0;
		size = remainingSize - paddingAdjustByte;
	}

	// Give required output buffer size.
	if (pDecryptedData == NULL_PTR)
	{
		*pulDecryptedDataLen = size;
		return CKR_OK;
	}

	// Check output buffer size
	if (*pulDecryptedDataLen < size)
	{
		DEBUG_MSG("output buffer size: %#5x  size: %#5x",
			  *pulDecryptedDataLen, size);
		*pulDecryptedDataLen = size;
		return CKR_BUFFER_TOO_SMALL;
	}

	// Finalize decryption
	ByteString decryptedFinal;
	if (!cipher->decryptFinal(decryptedFinal))
	{
		session->resetOp();
		return CKR_ENCRYPTED_DATA_INVALID;
	}
	DEBUG_MSG("output buffer size: %#2x  size: %#2x  decryptedFinal.size(): %#2x",
		  *pulDecryptedDataLen, size, decryptedFinal.size());

	// Check output size from crypto. Unrecoverable error if to large.
	if (*pulDecryptedDataLen < decryptedFinal.size())
	{
		session->resetOp();
		ERROR_MSG("DecryptFinal returning too much data. Length of output data buffer is %i but %i bytes was returned by the encrypt.",
			  *pulDecryptedDataLen, decryptedFinal.size());
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (decryptedFinal.size() > 0)
	{
		memcpy(pDecryptedData, decryptedFinal.byte_str(), decryptedFinal.size());
	}
	*pulDecryptedDataLen = decryptedFinal.size();

	session->resetOp();
	return CKR_OK;
}

// Finalise the decryption operation
CK_RV SoftHSM::C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Github issue #469, check NULL_PTR on pDataLen
	if (pDataLen == NULL)
	{
		session->resetOp();
		return CKR_ARGUMENTS_BAD;
	}

	// Check if we are doing the correct operation
	if (session->getOpType() != SESSION_OP_DECRYPT) return CKR_OPERATION_NOT_INITIALIZED;

	if (session->getSymmetricCryptoOp() != NULL)
		return SymDecryptFinal(session, pData, pDataLen);
	else
		return CKR_FUNCTION_NOT_SUPPORTED;
}


