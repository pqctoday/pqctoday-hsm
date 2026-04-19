/*
 * ssh-mldsa.c -- ML-DSA-65 key type for OpenSSH
 *
 * Implements draft-sfluhrer-ssh-mldsa-06 (April 2026)
 * https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/
 *
 * s3. Public Key Algorithms
 *   "ssh-mldsa-44", "ssh-mldsa-65", "ssh-mldsa-87" -- NIST Cat 2, 3, 5.
 *   This file implements ML-DSA-65 (Category 3).
 *
 * s4. Public Key Format
 *   string  "ssh-mldsa-65"
 *   string  key         (1952 raw bytes; ML-DSA.KeyGen pk, FIPS 204 s7.2)
 *
 * s5. Signature Algorithm
 *   Pure ML-DSA (FIPS 204 s5.2). Context string always empty.
 *   Hedged or deterministic mode acceptable; both interoperable.
 *   NOTE: signing is PKCS#11-only (ssh-pkcs11.c:pkcs11_sign_mldsa).
 *
 * s6. Signature Format
 *   string  "ssh-mldsa-65"
 *   string  signature   (3309 raw bytes)
 *
 * s7. Verification Algorithm
 *   Step 1: Reject if sig length != 3309 bytes for ML-DSA-65.
 *   Step 2: Verify per FIPS 204 s5.3, pure ML-DSA, empty context.
 */

#include "includes.h"
#include <stddef.h>
#include <string.h>

#include <openssl/evp.h>

#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"

/* FIPS 204 Table 2 -- ML-DSA-65 */
#define SSH_MLDSA65_PK_SZ  1952
#define SSH_MLDSA65_SIG_SZ 3309

static void
mldsa65_cleanup(struct sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static int
mldsa65_equal(const struct sshkey *a, const struct sshkey *b)
{
	u_char pka[SSH_MLDSA65_PK_SZ], pkb[SSH_MLDSA65_PK_SZ];
	size_t la = sizeof(pka), lb = sizeof(pkb);

	if (a->pkey == NULL || b->pkey == NULL)
		return 0;
	if (!EVP_PKEY_get_raw_public_key(a->pkey, pka, &la) ||
	    !EVP_PKEY_get_raw_public_key(b->pkey, pkb, &lb))
		return 0;
	if (la != SSH_MLDSA65_PK_SZ || lb != SSH_MLDSA65_PK_SZ)
		return 0;
	return timingsafe_bcmp(pka, pkb, SSH_MLDSA65_PK_SZ) == 0;
}

/*
 * s4: Serialize public key -- write raw key bytes as SSH string.
 * The algorithm name string is written by the sshkey layer before this.
 */
static int
mldsa65_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	u_char raw[SSH_MLDSA65_PK_SZ];
	size_t len = sizeof(raw);

	if (key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!EVP_PKEY_get_raw_public_key(key->pkey, raw, &len))
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (len != SSH_MLDSA65_PK_SZ)
		return SSH_ERR_INVALID_FORMAT;
	return sshbuf_put_string(b, raw, len);
}

/*
 * s4: Deserialize public key.
 * Validates exactly SSH_MLDSA65_PK_SZ bytes, imports via OpenSSL 3.3+.
 */
static int
mldsa65_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	const u_char *pk;
	size_t pklen;
	int r;

	if ((r = sshbuf_get_string_direct(b, &pk, &pklen)) != 0)
		return r;
	/* s7 step 1: reject if length does not match ML-DSA-65 */
	if (pklen != SSH_MLDSA65_PK_SZ)
		return SSH_ERR_KEY_LENGTH;
	EVP_PKEY_free(key->pkey);
	if ((key->pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-65",
	    NULL, pk, pklen)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

static int
mldsa65_copy_public(const struct sshkey *from, struct sshkey *to)
{
	u_char raw[SSH_MLDSA65_PK_SZ];
	size_t len = sizeof(raw);

	if (from->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (!EVP_PKEY_get_raw_public_key(from->pkey, raw, &len))
		return SSH_ERR_LIBCRYPTO_ERROR;
	EVP_PKEY_free(to->pkey);
	if ((to->pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-65",
	    NULL, raw, len)) == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

/*
 * s7. Verification Algorithm
 *
 * Step 1: Reject if sig length != SSH_MLDSA65_SIG_SZ (3309).
 * Step 2: Verify pure ML-DSA, empty context (OpenSSL 3.3+).
 *
 * Wire format (s6):
 *   string  "ssh-mldsa-65"
 *   string  signature   (3309 bytes)
 */
static int
mldsa65_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t datalen,
    const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	struct sshbuf	*b = NULL;
	char		*ktype = NULL;
	const u_char	*sigblob;
	size_t		 slen;
	EVP_MD_CTX	*md_ctx = NULL;
	int		 r = SSH_ERR_INTERNAL_ERROR;

	if (detailsp != NULL)
		*detailsp = NULL;
	if (key == NULL || key->pkey == NULL || sig == NULL || siglen == 0 ||
	    data == NULL || datalen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	/* s6: parse wire format */
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0)
		goto out;
	if (strcmp(ktype, "ssh-mldsa-65") != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if ((r = sshbuf_get_string_direct(b, &sigblob, &slen)) != 0)
		goto out;
	/* s7 step 1: reject wrong signature length */
	if (slen != SSH_MLDSA65_SIG_SZ) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* s7 step 2: verify pure ML-DSA, empty context.
	 * ML-DSA hashes internally (like Ed25519), so use EVP_DigestVerify
	 * rather than EVP_PKEY_verify (which skips the internal hash). */
	if ((md_ctx = EVP_MD_CTX_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, key->pkey) != 1 ||
	    EVP_DigestVerify(md_ctx, sigblob, slen, data, datalen) != 1) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	r = 0;
out:
	sshbuf_free(b);
	free(ktype);
	EVP_MD_CTX_free(md_ctx);
	return r;
}

static const struct sshkey_impl_funcs mldsa65_funcs = {
	NULL,			/* size */
	NULL,			/* alloc */
	mldsa65_cleanup,
	mldsa65_equal,
	mldsa65_serialize_public,
	mldsa65_deserialize_public,
	NULL,			/* serialize_private */
	NULL,			/* deserialize_private */
	NULL,			/* generate */
	mldsa65_copy_public,
	NULL,			/* sign -- PKCS#11 only */
	mldsa65_verify,
};

const struct sshkey_impl sshkey_mldsa65_impl = {
	"ssh-mldsa-65",		/* name */
	"MLDSA65",		/* shortname */
	"ssh-mldsa-65",		/* sigalg */
	KEY_MLDSA_65,		/* type */
	0,			/* nid */
	0,			/* cert */
	0,			/* sigonly */
	0,			/* keybits */
	&mldsa65_funcs,
};
