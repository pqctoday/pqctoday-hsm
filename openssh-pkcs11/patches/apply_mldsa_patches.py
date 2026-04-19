#!/usr/bin/env python3
"""
apply_mldsa_patches.py
Applies ML-DSA-65 support to openssh-portable source tree.
Implements draft-sfluhrer-ssh-mldsa-06.
Run from within the openssh-portable directory.
"""
import os, sys, re

def read(path):
    with open(path) as f:
        return f.read()

def write(path, content):
    with open(path, 'w') as f:
        f.write(content)
    print(f"  patched: {path}")

def replace_once(path, old_pattern, new):
    content = read(path)
    if not re.search(old_pattern, content):
        print(f"ERROR: marker not found in {path}:\n  {old_pattern!r}", file=sys.stderr)
        sys.exit(1)
    write(path, re.sub(old_pattern, new, content, count=1))

# ── 1. Makefile.in ───────────────────────────────────────────────────────────
replace_once(
    "Makefile.in",
    r"\tmsg\.o dns\.o entropy\.o gss-genr\.o umac\.o umac128\.o \\",
    r"	ssh-mldsa.o msg.o dns.o entropy.o gss-genr.o umac.o umac128.o \\"
)

# ── 2. myproposal.h ──────────────────────────────────────────────────────────
replace_once(
    "myproposal.h",
    r'#define\s+KEX_DEFAULT_PK_ALG\s+\\\n\s+"ssh-ed25519-cert-v01@openssh\.com,"',
    '#define\tKEX_DEFAULT_PK_ALG\t\\\n\t"ssh-mldsa-65," \\\n\t"ssh-ed25519-cert-v01@openssh.com,"'
)

# ── 3. sshkey.h ──────────────────────────────────────────────────────────────
replace_once(
    "sshkey.h",
    r"\s+KEY_ED25519_SK_CERT,\n\s+KEY_UNSPEC",
    "\n\tKEY_ED25519_SK_CERT,\n\tKEY_MLDSA_65,\n\tKEY_UNSPEC"
)

# ── 4. sshkey.c ──────────────────────────────────────────────────────────────
# 4a: extern declaration
replace_once(
    "sshkey.c",
    r"extern const struct sshkey_impl sshkey_ed25519_sk_cert_impl;\n",
    "extern const struct sshkey_impl sshkey_ed25519_sk_cert_impl;\nextern const struct sshkey_impl sshkey_mldsa65_impl;\n"
)
# 4b: register in keyimpls[]
replace_once(
    "sshkey.c",
    r"&sshkey_ed25519_cert_impl,\n\s*#\s*ifdef ENABLE_SK",
    "&sshkey_ed25519_cert_impl,\n\n\t&sshkey_mldsa65_impl,\n# ifdef ENABLE_SK"
)

# ── 5. ssh-pkcs11.c ──────────────────────────────────────────────────────────
PKCS11_CONSTANTS = r"""
/* ML-DSA PKCS#11 v3.2 -- draft-sfluhrer-ssh-mldsa-06
 * Constants from SoftHSMv3 src/lib/pkcs11/pkcs11t.h */
#ifndef CKK_ML_DSA
#define CKK_ML_DSA              0x0000004aUL
#endif
#ifndef CKM_ML_DSA_KEY_PAIR_GEN
#define CKM_ML_DSA_KEY_PAIR_GEN 0x0000001cUL
#endif
#ifndef CKM_ML_DSA
#define CKM_ML_DSA              0x0000001dUL
#endif
/* PKCS#11 v3.2 §4.9 common CKO_PUBLIC_KEY attribute: DER SubjectPublicKeyInfo.
 * softhsmv3 populates this on every ML-DSA pubkey (SoftHSM_keygen.cpp). */
#ifndef CKA_PUBLIC_KEY_INFO
#define CKA_PUBLIC_KEY_INFO     0x00000129UL
#endif
/* FIPS 204 Table 2 + draft s3 */
#define SSH_MLDSA65_PK_SZ  1952
#define SSH_MLDSA65_SIG_SZ 3309

"""

FETCH_MLDSA = r"""
/*
 * pkcs11_fetch_mldsa_pubkey -- draft-sfluhrer-ssh-mldsa-06 s4
 *
 * Two-path pubkey extraction (softhsmv3 populates both):
 *   1. CKA_PUBLIC_KEY_INFO -- DER SubjectPublicKeyInfo (PKCS#11 v3.2 §4.9).
 *      Parsed via d2i_PUBKEY(); OpenSSL 3.3+ handles ML-DSA-65 SPKI natively.
 *      This is the robust path and is tried first.
 *   2. CKA_VALUE -- raw 1952-byte pk (PKCS#11 v3.2 §6.67.2 Table 280).
 *      Fallback for tokens that populate only raw pk. Imported via
 *      EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-65", ...).
 */
static struct sshkey *
pkcs11_fetch_mldsa_pubkey(struct pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 key_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = NULL;
	CK_RV			 rv;
	struct sshkey		*key = NULL;
	EVP_PKEY		*pkey = NULL;
	int			 success = -1, i;
	const unsigned char	*spki_p;

	memset(&key_attr, 0, sizeof(key_attr));
	key_attr[0].type = CKA_ID;
	key_attr[1].type = CKA_PUBLIC_KEY_INFO; /* DER SPKI -- preferred */
	key_attr[2].type = CKA_VALUE;           /* raw 1952 bytes -- fallback */

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* Size-probe: missing optional attrs return CKR_ATTRIBUTE_TYPE_INVALID
	 * with ulValueLen=CK_UNAVAILABLE_INFORMATION; we accept either as long as
	 * at least one usable pubkey path (SPKI or raw) was returned. */
	rv = f->C_GetAttributeValue(session, *obj, key_attr, 3);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (probe) failed: %lu", rv);
		return NULL;
	}
	if (key_attr[1].ulValueLen == (CK_ULONG)-1)
		key_attr[1].ulValueLen = 0;
	if (key_attr[2].ulValueLen == (CK_ULONG)-1)
		key_attr[2].ulValueLen = 0;
	if (key_attr[1].ulValueLen == 0 && key_attr[2].ulValueLen == 0) {
		error_f("no ML-DSA pubkey material on token object");
		return NULL;
	}
	if (key_attr[2].ulValueLen != 0 &&
	    key_attr[2].ulValueLen != SSH_MLDSA65_PK_SZ) {
		debug_f("CKA_VALUE length %lu != %d (non-fatal; "
		    "will prefer CKA_PUBLIC_KEY_INFO if present)",
		    (u_long)key_attr[2].ulValueLen, SSH_MLDSA65_PK_SZ);
	}
	for (i = 0; i < 3; i++)
		if (key_attr[i].ulValueLen > 0)
			key_attr[i].pValue = xcalloc(1, key_attr[i].ulValueLen);
	rv = f->C_GetAttributeValue(session, *obj, key_attr, 3);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		error("C_GetAttributeValue (fetch) failed: %lu", rv);
		goto fail;
	}

	/* Path 1: DER SPKI -- d2i_PUBKEY handles ML-DSA-65 natively (OpenSSL 3.3+). */
	if (key_attr[1].ulValueLen > 0) {
		spki_p = (const unsigned char *)key_attr[1].pValue;
		pkey = d2i_PUBKEY(NULL, &spki_p,
		    (long)key_attr[1].ulValueLen);
		if (pkey == NULL)
			debug_f("d2i_PUBKEY failed on CKA_PUBLIC_KEY_INFO; "
			    "will try CKA_VALUE fallback");
	}
	/* Path 2: raw 1952-byte pk fallback. */
	if (pkey == NULL && key_attr[2].ulValueLen == SSH_MLDSA65_PK_SZ) {
		pkey = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-65",
		    NULL, key_attr[2].pValue, key_attr[2].ulValueLen);
	}
	if (pkey == NULL) {
		error_f("could not materialise ML-DSA-65 pubkey "
		    "(spki=%lu bytes, raw=%lu bytes)",
		    (u_long)key_attr[1].ulValueLen,
		    (u_long)key_attr[2].ulValueLen);
		goto fail;
	}
	if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
		fatal_f("sshkey_new failed");
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = NULL;
	key->type = KEY_MLDSA_65;
	key->flags |= SSHKEY_FLAG_EXT;
	if (pkcs11_record_key(p, slotidx, &key_attr[0], key))
		goto fail;
	success = 0;
fail:
	if (success != 0) {
		EVP_PKEY_free(pkey);
		sshkey_free(key);
		key = NULL;
	}
	for (i = 0; i < 3; i++)
		free(key_attr[i].pValue);
	return key;
}

"""

SIGN_MLDSA = r"""
/*
 * pkcs11_sign_mldsa -- draft-sfluhrer-ssh-mldsa-06
 *
 * s5. Signature Algorithm
 *   Pure ML-DSA (FIPS 204 s5.2), empty context string.
 *   CKM_ML_DSA (0x1d) NULL_PTR param: full message passed, C_Sign hashes
 *   internally per FIPS 204.
 *
 * s6. Signature Format
 *   string  "ssh-mldsa-65"
 *   string  signature  (3309 raw bytes)
 */
static int
pkcs11_sign_mldsa(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider,
    const char *sk_pin, u_int compat)
{
	struct pkcs11_key	*k11;
	struct pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_MECHANISM		 mech = { CKM_ML_DSA, NULL_PTR, 0 }; /* s5 */
	CK_ULONG		 slen = SSH_MLDSA65_SIG_SZ;
	CK_RV			 rv;
	u_char			*sig = NULL;
	struct sshbuf		*b = NULL;
	int			 ret = SSH_ERR_INTERNAL_ERROR;

	if (sigp != NULL) *sigp = NULL;
	if (lenp != NULL) *lenp = 0;
	if ((k11 = pkcs11_lookup_key(key)) == NULL) {
		error_f("no key found");
		return SSH_ERR_KEY_NOT_FOUND;
	}
	if (pkcs11_get_key(k11, CKM_ML_DSA) == -1)
		return SSH_ERR_AGENT_FAILURE;
	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];
	sig = xmalloc(slen);
	/* s5: full message to C_Sign -- pure ML-DSA, no pre-hash */
	rv = f->C_Sign(si->session, (CK_BYTE_PTR)data, (CK_ULONG)datalen,
	    sig, &slen);
	if (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		goto done;
	}
	if (slen != SSH_MLDSA65_SIG_SZ) {
		error_f("bad signature length: %lu (expected %d)",
		    (u_long)slen, SSH_MLDSA65_SIG_SZ);
		goto done;
	}
	/* s6: wire format */
	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if (sshbuf_put_cstring(b, "ssh-mldsa-65") != 0 ||
	    sshbuf_put_string(b, sig, slen) != 0)
		fatal_f("sshbuf_put failed");
	if (sigp != NULL) {
		*sigp = xmalloc(sshbuf_len(b));
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	if (lenp != NULL)
		*lenp = sshbuf_len(b);
	ret = 0;
done:
	sshbuf_free(b);
	freezero(sig, slen);
	return ret;
}

"""

# 5a: insert constants after crypto_api.h include
replace_once(
    "ssh-pkcs11.c",
    r'#\s*include "crypto_api\.h"\n',
    '# include "crypto_api.h"\n' + PKCS11_CONSTANTS
)

# 5b: insert pkcs11_fetch_mldsa_pubkey before "# ifdef WITH_OPENSSL /* libcrypto"
replace_once(
    "ssh-pkcs11.c",
    r"\n#\s*ifdef WITH_OPENSSL /\* libcrypto needed for certificate parsing \*/",
    "\n" + FETCH_MLDSA + "# ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */"
)

# 5c: add CKK_ML_DSA case in pkcs11_fetch_keys() switch
replace_once(
    "ssh-pkcs11.c",
    r"\t\tcase CKK_EC_EDWARDS:\n\t\t\tkey = pkcs11_fetch_ed25519_pubkey\(p, slotidx, &obj\);\n\t\t\tbreak;\n\t\tdefault:",
    "\t\tcase CKK_EC_EDWARDS:\n\t\t\tkey = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\t/* draft-sfluhrer-ssh-mldsa-06 */\n\t\tcase CKK_ML_DSA:\n\t\t\tkey = pkcs11_fetch_mldsa_pubkey(p, slotidx, &obj);\n\t\t\tbreak;\n\t\tdefault:"
)

# 5d: insert pkcs11_sign_mldsa before pkcs11_sign()
replace_once(
    "ssh-pkcs11.c",
    r"\nint\npkcs11_sign\(struct sshkey \*key,",
    "\n" + SIGN_MLDSA + "int\npkcs11_sign(struct sshkey *key,"
)

# 5e: add KEY_MLDSA_65 case in pkcs11_sign() switch
replace_once(
    "ssh-pkcs11.c",
    r"\treturn pkcs11_sign_ed25519\(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat\);\n\s*default:",
    "\treturn pkcs11_sign_ed25519(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat);\n\t/* draft-sfluhrer-ssh-mldsa-06 */\n\tcase KEY_MLDSA_65:\n\t\treturn pkcs11_sign_mldsa(key, sigp, lenp, data, datalen,\n\t\t    alg, sk_provider, sk_pin, compat);\n\tdefault:"
)

# ── 6. sshd-auth.c — list_hostkey_types() ───────────────────────────────────
# list_hostkey_types() has a switch that only covers RSA/ECDSA/ED25519/SK types.
# Without KEY_MLDSA_65, the server never advertises ssh-mldsa-65 as a host key
# algorithm even when the key is loaded from the agent via HostKeyAgent.
replace_once(
    "sshd-auth.c",
    r"\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t\tappend_hostkey_type\(b, sshkey_ssh_name\(key\)\);\n\t\t\tbreak;",
    "\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t/* draft-sfluhrer-ssh-mldsa-06: agent-backed ML-DSA-65 host key */\n\t\tcase KEY_MLDSA_65:\n\t\t\tappend_hostkey_type(b, sshkey_ssh_name(key));\n\t\t\tbreak;"
)

# ── 7. sshd.c — have_ssh2_key switch ─────────────────────────────────────────
# When sshd loads a HostKey that is only backed by the agent (pubkey-only,
# no private key file), it checks the keytype in a switch to set have_ssh2_key=1.
# Without KEY_MLDSA_65 here, sshd exits with "no hostkeys available" when the
# only configured HostKey is ML-DSA-65 (agent-only, no file-based classical keys).
replace_once(
    "sshd.c",
    r"\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t\tif \(have_agent \|\| key != NULL\)\n\t\t\t\tsensitive_data\.have_ssh2_key = 1;\n\t\t\tbreak;",
    "\t\tcase KEY_ECDSA_SK:\n\t\tcase KEY_ED25519_SK:\n\t\t/* draft-sfluhrer-ssh-mldsa-06 */\n\t\tcase KEY_MLDSA_65:\n\t\t\tif (have_agent || key != NULL)\n\t\t\t\tsensitive_data.have_ssh2_key = 1;\n\t\t\tbreak;"
)

print("All patches applied successfully.")
print("Next: autoreconf -i && ./configure ... && make")
