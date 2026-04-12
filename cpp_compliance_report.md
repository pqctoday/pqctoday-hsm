# PKCS#11 v3.2 Compliance Report

**Engine:** `src/lib/libsofthsmv3.dylib`
**Timestamp:** Generated automatically

## Summary
- **Total PASS:** 76
- **Total FAIL:** 15
- **Total SKIP:** 0

### Attributes

| Test | Status | Details |
|---|---|---|
| CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | Required for all PQC keys |
| CKA_PUBLIC_KEY_INFO_Priv | ❌ FAIL | Required to be exposed on private objects |
| CKA_HSS_KEYS_REMAINING | ❌ FAIL | Hard FAIL per spec instruction: missing attribute from Private Key (Table 270) |
| ML_KEM_512_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_512_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_512_CKA_PUBLIC_KEY_INFO_Priv | ❌ FAIL | SPKI missing on private |
| ML_KEM_512_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_512_CKA_DECAPSULATE | ✅ PASS |  |
| ML_KEM_768_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_768_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_768_CKA_PUBLIC_KEY_INFO_Priv | ❌ FAIL | SPKI missing on private |
| ML_KEM_768_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_768_CKA_DECAPSULATE | ✅ PASS |  |
| ML_KEM_1024_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_1024_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_1024_CKA_PUBLIC_KEY_INFO_Priv | ❌ FAIL | SPKI missing on private |
| ML_KEM_1024_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_1024_CKA_DECAPSULATE | ✅ PASS |  |
| ML_DSA_44_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_DSA_44_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_DSA_44_CKA_PUBLIC_KEY_INFO_Priv | ❌ FAIL | SPKI missing on private |
| ML_DSA_44_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_44_CKA_SIGN | ✅ PASS |  |
| ML_DSA_65_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_DSA_65_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_DSA_65_CKA_PUBLIC_KEY_INFO_Priv | ❌ FAIL | SPKI missing on private |
| ML_DSA_65_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_65_CKA_SIGN | ✅ PASS |  |
| ML_DSA_87_CKA_VALUE_Pub | ❌ FAIL | §1.21 G-ATTR1 failure |
| ML_DSA_87_CKA_PUBLIC_KEY_INFO_Pub | ❌ FAIL | SPKI missing on public key |
| ML_DSA_87_CKA_PUBLIC_KEY_INFO_Priv | ❌ FAIL | SPKI missing on private |
| ML_DSA_87_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_87_CKA_SIGN | ✅ PASS |  |

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
| CKM_AES_CTR | ✅ PASS | AES CTR Support (v3.2/5G) |
| CKM_HKDF_DERIVE | ✅ PASS | HKDF Support (v3.0/5G) |
| CKM_RIPEMD160 | ❌ FAIL | RIPEMD160 Support (Strict Audit) |

### FIPS

| Test | Status | Details |
|---|---|---|
| ML-KEM_Generate | ❌ FAIL | RV=112 |
| ML-DSA_Generate | ❌ FAIL | RV=112 |

### Init

| Test | Status | Details |
|---|---|---|
| TokenSetup | ✅ PASS | Initialized token and session |

### KDF

| Test | Status | Details |
|---|---|---|
| CKM_PKCS5_PBKD2 | ✅ PASS | RV=0 |
| CKM_SP800_108_COUNTER_KDF | ✅ PASS | RV=0 |

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
| C_EncryptMessageBegin | ✅ PASS | RV=0 |

### MsgSign

| Test | Status | Details |
|---|---|---|
| C_MessageSignInit | ✅ PASS | RV=0 |
| C_SignMessageBegin | ✅ PASS | RV=0 |
| C_SignMessageNext | ✅ PASS | RV=0 |

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
| C_SetAttributeValue_RO | ❌ FAIL | RV=0 |
| Session_Object_CrossVisibility | ❌ FAIL | Visible |

