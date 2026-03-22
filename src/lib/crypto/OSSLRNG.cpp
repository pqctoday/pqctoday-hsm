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
 OSSLRNG.cpp

 OpenSSL random number generator class
 *****************************************************************************/

#include "config.h"
#include "OSSLRNG.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>

bool acvp_mode = false;
unsigned char acvp_seed[32] = {0};
EVP_CIPHER_CTX *acvp_ctx = NULL;

static int acvp_rand_bytes(unsigned char *buf, int num) {
	if (num <= 0) return 1;
	if (!acvp_ctx) return 0;
	int outlen = 0;
	unsigned char *zeros = (unsigned char *)calloc(num, 1);
	EVP_EncryptUpdate(acvp_ctx, buf, &outlen, zeros, num);
	free(zeros);
	return 1;
}

static RAND_METHOD acvp_rand_method = {
	NULL,
	acvp_rand_bytes,
	NULL,
	NULL,
	acvp_rand_bytes,
	NULL
};

void OSSLRNG_enableACVP(unsigned char* seed) {
	acvp_mode = true;
	memcpy(acvp_seed, seed, 32);

	if (acvp_ctx) {
		EVP_CIPHER_CTX_free(acvp_ctx);
	}
	acvp_ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[16] = {0};
	EVP_EncryptInit_ex(acvp_ctx, EVP_chacha20(), NULL, acvp_seed, iv);

	RAND_set_rand_method(&acvp_rand_method);
}

void OSSLRNG_disableACVP() {
	if (acvp_ctx) {
		EVP_CIPHER_CTX_free(acvp_ctx);
		acvp_ctx = NULL;
	}
	acvp_mode = false;
	memset(acvp_seed, 0, 32);
	RAND_set_rand_method(RAND_OpenSSL());
}

// Generate random data
bool OSSLRNG::generateRandom(ByteString& data, const size_t len)
{
	data.wipe(len);

	if (len == 0)
		return true;
	return RAND_bytes(&data[0], len) == 1;
}

// Seed the random pool
void OSSLRNG::seed(ByteString& seedData)
{
	RAND_seed(seedData.byte_str(), seedData.size());
}

