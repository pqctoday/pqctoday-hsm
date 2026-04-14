# PKCS#11 v3.2 Compliance Report

**Engine:** `./build/src/lib/libsofthsmv3.dylib`
**Timestamp:** Generated automatically

## Summary
- **Total PASS:** 126
- **Total FAIL:** 1
- **Total SKIP:** 0

### AES-CTR

| Test | Status | Details |
|---|---|---|
| EncryptInit | ✅ PASS | RV=0 |

### Attributes

| Test | Status | Details |
|---|---|---|
| CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | Required for all PQC keys |
| CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | Required to be exposed on private objects |
| CKA_HSS_KEYS_REMAINING_Gen | ✅ PASS | Remaining=32 |
| ML_KEM_512_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_512_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_512_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_KEM_512_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_512_CKA_DECAPSULATE | ✅ PASS |  |
| ML_KEM_768_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_768_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_768_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_KEM_768_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_768_CKA_DECAPSULATE | ✅ PASS |  |
| ML_KEM_1024_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_1024_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_1024_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_KEM_1024_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_1024_CKA_DECAPSULATE | ✅ PASS |  |
| ML_DSA_44_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_DSA_44_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_DSA_44_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_DSA_44_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_44_CKA_SIGN | ✅ PASS |  |
| ML_DSA_65_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_DSA_65_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_DSA_65_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_DSA_65_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_65_CKA_SIGN | ✅ PASS |  |
| ML_DSA_87_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_DSA_87_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_DSA_87_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_DSA_87_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_87_CKA_SIGN | ✅ PASS |  |

### AuthWrap

| Test | Status | Details |
|---|---|---|
| C_WrapKeyAuthenticated | ✅ PASS | RV=0 |
| C_UnwrapKeyAuthenticated | ✅ PASS | RV=0 |
| Value_Match | ✅ PASS | Unwrapped keys perfectly match |
| NIST_SP800_38D_KAT | ✅ PASS | Unwrapped GCM payload perfectly matches NIST Test Case 4 PT |

### ChaCha20

| Test | Status | Details |
|---|---|---|
| C_CreateObject | ✅ PASS | Created CKK_CHACHA20 Secret Key |
| C_Encrypt | ✅ PASS | Generated properly with 16 byte MAC tag |

### Classical

| Test | Status | Details |
|---|---|---|
| Generate_RSA_2048 | ✅ PASS | RV=0 |
| C_Sign_RSA_SHA256 | ✅ PASS | RV=0 |

### DSA

| Test | Status | Details |
|---|---|---|
| Generate_ML_DSA_44 | ✅ PASS | Gen ML-DSA-44 |
| C_Sign_44_Pure | ✅ PASS | RV=0 |
| C_Verify_44_Pure | ✅ PASS | RV=0 |
| C_Sign_44_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Verify_44_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Sign_44_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| C_Verify_44_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| Generate_ML_DSA_65 | ✅ PASS | Gen ML-DSA-65 |
| C_Sign_65_Pure | ✅ PASS | RV=0 |
| C_Verify_65_Pure | ✅ PASS | RV=0 |
| C_Sign_65_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Verify_65_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Sign_65_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| C_Verify_65_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| Generate_ML_DSA_87 | ✅ PASS | Gen ML-DSA-87 |
| C_Sign_87_Pure | ✅ PASS | RV=0 |
| C_Verify_87_Pure | ✅ PASS | RV=0 |
| C_Sign_87_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Verify_87_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Sign_87_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| C_Verify_87_PreHash_SHA3_512 | ✅ PASS | RV=0 |

### Discovery

| Test | Status | Details |
|---|---|---|
| CKM_ML_KEM | ✅ PASS | PQC KEM Support |
| CKM_ML_DSA | ✅ PASS | PQC DSA Support |
| CKM_SLH_DSA | ✅ PASS | PQC SLH-DSA Support |
| CKM_XMSS | ✅ PASS | PQC XMSS Support |
| CKM_AES_CTR | ✅ PASS | AES CTR Support (v3.2/5G) |
| CKM_CHACHA20_POLY1305 | ✅ PASS | ChaCha20 Support (RFC 7539) |
| CKM_HKDF_DERIVE | ✅ PASS | HKDF Support (v3.0/5G) |
| CKM_RIPEMD160 | ❌ FAIL | RIPEMD160 Support (Strict Audit) |

### ECDH

| Test | Status | Details |
|---|---|---|
| Generate_X25519 | ✅ PASS | RV=0 |
| Derive_X25519 | ✅ PASS | RV=0 |

### ECDSA

| Test | Status | Details |
|---|---|---|
| Generate_P256 | ✅ PASS | RV=0 |
| Sign_P256 | ✅ PASS | RV=0 |
| Generate_P521 | ✅ PASS | RV=0 |
| Sign_P521 | ✅ PASS | RV=0 |
| Generate_secp256k1 | ✅ PASS | RV=0 |
| Sign_secp256k1 | ✅ PASS | RV=0 |

### EdDSA

| Test | Status | Details |
|---|---|---|
| Generate_Ed25519 | ✅ PASS | RV=0 |
| Sign_Ed25519 | ✅ PASS | RV=0 |
| Generate_Ed448 | ✅ PASS | RV=0 |
| Sign_Ed448 | ✅ PASS | RV=0 |

### FIPS

| Test | Status | Details |
|---|---|---|
| ML-KEM_Truncated_CT | ✅ PASS | RV=274 |
| ML-KEM_Implicit_Rejection | ✅ PASS | Yielded deterministic random secret per FIPS 203 |
| ML-DSA_Oversized_Ctx | ✅ PASS | RV=7 |

### Init

| Test | Status | Details |
|---|---|---|
| TokenSetup | ✅ PASS | Initialized token and session |

### KDF

| Test | Status | Details |
|---|---|---|
| CKM_PKCS5_PBKD2 | ✅ PASS | RV=0 |
| CKM_SP800_108_COUNTER_KDF | ✅ PASS | RV=0 |
| CKM_SP800_108_FEEDBACK_KDF | ✅ PASS | RV=0 |
| CKM_HKDF_DERIVE | ✅ PASS | RV=0 |

### KEM

| Test | Status | Details |
|---|---|---|
| Generate_ML_KEM_512 | ✅ PASS | Gen ML-KEM-512 |
| C_EncapsulateKey_512 | ✅ PASS | CT len=768 |
| C_DecapsulateKey_512 | ✅ PASS | SS matched |
| Generate_ML_KEM_768 | ✅ PASS | Gen ML-KEM-768 |
| C_EncapsulateKey_768 | ✅ PASS | CT len=1088 |
| C_DecapsulateKey_768 | ✅ PASS | SS matched |
| Generate_ML_KEM_1024 | ✅ PASS | Gen ML-KEM-1024 |
| C_EncapsulateKey_1024 | ✅ PASS | CT len=1568 |
| C_DecapsulateKey_1024 | ✅ PASS | SS matched |

### MsgCrypt

| Test | Status | Details |
|---|---|---|
| C_MessageEncryptInit | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV12 | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV16 | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV8 | ✅ PASS | RV=0 |

### MsgSign

| Test | Status | Details |
|---|---|---|
| C_MessageSignInit | ✅ PASS | RV=0 |
| C_SignMessageBegin | ✅ PASS | RV=0 |
| C_SignMessageNext | ✅ PASS | RV=0 |
| C_MessageSignInit_PQCContext | ✅ PASS | RV=113 |

### Negative

| Test | Status | Details |
|---|---|---|
| Sign_With_KEM_Key | ✅ PASS | Expected CKR_KEY_FUNCTION_NOT_PERMITTED, got 99 |
| Boolean_Policy_Violation | ✅ PASS | Expected CKR_KEY_FUNCTION_NOT_PERMITTED, got 104 |
| Extraction_Constraint | ✅ PASS | Expected CKR_ATTRIBUTE_SENSITIVE, got 17 |
| Template_Incomplete_Create | ✅ PASS | Expected CKR_TEMPLATE_INCOMPLETE, got 208 |
| Signature_Len_Range | ✅ PASS | Expected CKR_SIGNATURE_LEN_RANGE, got 193 |
| Signature_Forgery_Invalid | ✅ PASS | Expected CKR_SIGNATURE_INVALID, got 192 |

### SHA-3

| Test | Status | Details |
|---|---|---|
| DigestInit_256 | ✅ PASS | RV=0 |

### SLHDSA

| Test | Status | Details |
|---|---|---|
| Generate_SLH_DSA_SHA2_128S | ✅ PASS | Gen SLH-DSA-SHA2_128S |
| C_Sign_SHA2_128S_Deterministic_Ctx | ✅ PASS | RV=0 |
| Generate_SLH_DSA_SHA2_128F | ✅ PASS | Gen SLH-DSA-SHA2_128F |
| C_Sign_SHA2_128F_Deterministic_Ctx | ✅ PASS | RV=0 |
| Generate_SLH_DSA_SHA2_256F | ✅ PASS | Gen SLH-DSA-SHA2_256F |
| C_Sign_SHA2_256F_Deterministic_Ctx | ✅ PASS | RV=0 |

### Session

| Test | Status | Details |
|---|---|---|
| C_OpenSession_InvalidSlot | ✅ PASS | RV=3 |
| C_SetAttributeValue_RO | ✅ PASS | RV=181 |
| Session_Object_CrossVisibility | ✅ PASS | Visible (Compliant) |

### XMSS

| Test | Status | Details |
|---|---|---|
| Generate_XMSS_SHA2_10_256 | ✅ PASS | Gen XMSS_SHA2_10_256 |
| C_Sign_XMSS_SHA2_10_256 | ✅ PASS | RV=0 |

