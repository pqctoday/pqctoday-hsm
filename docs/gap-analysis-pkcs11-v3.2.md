# PKCS#11 v3.2 Compliance Gap Analysis — softhsmv3

**Date:** 2026-03-02
**Baseline:** Phase 1 complete (commit `87b27bf`) — OpenSSL 3.x EVP-only API migration
**Spec reference:** OASIS PKCS#11 v3.2 (http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.2/)
**Scope:** ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
**Out of scope:** HSS, XMSS/XMSSMT (no native OpenSSL 3.x support)

---

## Executive Summary

| Dimension | Total gaps | Blockers | High | Medium |
|---|---|---|---|---|
| C_* function table | 14 | 4 | 8 | 2 |
| CKM_* mechanisms | 28 | 28 | — | — |
| CKK_* key types | 3 | 3 | — | — |
| CKA_* attributes | 5 | 1 | 4 | — |
| **Total** | **50** | **36** | **12** | **2** |

All three in-scope algorithms (ML-KEM, ML-DSA, SLH-DSA) are natively supported by
OpenSSL 3.3+ via the EVP_PKEY API — no external provider or liboqs required for 3.6.

---

## 1. C_* Function Table Gaps

The current implementation fills only `CK_FUNCTION_LIST` (v2.0 shape).
PKCS#11 v3.0 introduced `C_GetInterfaceList` / `C_GetInterface` as the authoritative
mechanism for version negotiation; v3.2 added `C_EncapsulateKey` / `C_DecapsulateKey`
for KEM operations.

### 1.1 Interface negotiation (BLOCKER)

| Function | Added | Severity | Phase |
|---|---|---|---|
| `C_GetInterfaceList` | v3.0 | BLOCKER | Phase 2 (#3) |
| `C_GetInterface` | v3.0 | BLOCKER | Phase 2 (#3) |

`C_GetInterfaceList` / `C_GetInterface` must expose three versioned interface structs:

```
Interface name: "PKCS 11"
  version (2, 40)  →  CK_FUNCTION_LIST       (backward compat)
  version (3, 0)   →  CK_FUNCTION_LIST_3_0
  version (3, 2)   →  CK_FUNCTION_LIST_3_2
```

Without these, any PKCS#11 v3.x library loader will fail to negotiate the correct
function pointer table.

### 1.2 KEM operations (BLOCKER — v3.2 only)

| Function | Added | Severity | Phase |
|---|---|---|---|
| `C_EncapsulateKey` | v3.2 | BLOCKER | Phase 3 (#4) |
| `C_DecapsulateKey` | v3.2 | BLOCKER | Phase 3 (#4) |

These are the only PKCS#11 API calls for ML-KEM encapsulation/decapsulation.
Declared in `src/lib/pkcs11/pkcs11f.h`; not present in `SoftHSM.cpp`.

```c
// Signatures (from pkcs11f.h):
CK_RV C_EncapsulateKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR  pMechanism,   // CKM_ML_KEM
    CK_OBJECT_HANDLE  hPublicKey,
    CK_ATTRIBUTE_PTR  pTemplate,
    CK_ULONG          ulAttributeCount,
    CK_BYTE_PTR       pCiphertext,
    CK_ULONG_PTR      pulCiphertextLen,
    CK_OBJECT_HANDLE_PTR phKey      // derived shared secret object
);

CK_RV C_DecapsulateKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR  pMechanism,   // CKM_ML_KEM
    CK_OBJECT_HANDLE  hPrivateKey,
    CK_ATTRIBUTE_PTR  pTemplate,
    CK_ULONG          ulAttributeCount,
    CK_BYTE_PTR       pCiphertext,
    CK_ULONG          ulCiphertextLen,
    CK_OBJECT_HANDLE_PTR phKey      // derived shared secret object
);
```

### 1.3 One-shot signing API (HIGH — v3.0)

Required for ML-DSA and SLH-DSA (both are pure-message signature schemes; they
internally hash the message as part of the algorithm — not pre-hashed externally).

| Function | Added | Severity | Phase |
|---|---|---|---|
| `C_SignMessage` | v3.0 | HIGH | Phase 2 (#3) |
| `C_SignMessageBegin` | v3.0 | HIGH | Phase 2 (#3) |
| `C_SignMessageNext` | v3.0 | HIGH | Phase 2 (#3) |
| `C_EndSignMessage` | v3.0 | HIGH | Phase 2 (#3) |
| `C_VerifyMessage` | v3.0 | HIGH | Phase 2 (#3) |
| `C_VerifyMessageBegin` | v3.0 | HIGH | Phase 2 (#3) |
| `C_VerifyMessageNext` | v3.0 | HIGH | Phase 2 (#3) |
| `C_EndVerifyMessage` | v3.0 | HIGH | Phase 2 (#3) |

The existing `C_Sign` / `C_Verify` (v2.0) operate in two phases: update then final.
For ML-DSA and SLH-DSA, the message must be passed atomically to OpenSSL's
`EVP_DigestSign` / `EVP_DigestVerify` — the v3.0 one-shot API maps directly to this.

### 1.4 Session and login (MEDIUM — v3.0)

| Function | Added | Severity | Phase |
|---|---|---|---|
| `C_SessionCancel` | v3.0 | MEDIUM | Phase 2 (#3) |
| `C_LoginUser` | v3.0 | MEDIUM | Phase 2 (#3) |

---

## 2. CKM_* Mechanism Gaps

`prepareSupportedMechanisms()` in `SoftHSM.cpp` registers only classical mechanisms.
None of the following appear in the mechanism list or in `C_GenerateKeyPair` /
`C_Sign` / `C_Verify` dispatch.

### 2.1 ML-DSA (FIPS 204) — Phase 2 (#3)

OpenSSL 3.3+ EVP_PKEY names: `"ml-dsa-44"`, `"ml-dsa-65"`, `"ml-dsa-87"`

| Mechanism | Hex value | Operation |
|---|---|---|
| `CKM_ML_DSA_KEY_PAIR_GEN` | `0x0000001cUL` | `C_GenerateKeyPair` |
| `CKM_ML_DSA` | `0x0000001dUL` | `C_Sign` / `C_Verify` (pure message) |
| `CKM_HASH_ML_DSA` | `0x0000001fUL` | `C_Sign` / `C_Verify` (pre-hash variant) |
| `CKM_HASH_ML_DSA_SHA224` | `0x00000023UL` | Pre-hash with SHA-224 |
| `CKM_HASH_ML_DSA_SHA256` | `0x00000024UL` | Pre-hash with SHA-256 |
| `CKM_HASH_ML_DSA_SHA384` | `0x00000025UL` | Pre-hash with SHA-384 |
| `CKM_HASH_ML_DSA_SHA512` | `0x00000026UL` | Pre-hash with SHA-512 |
| `CKM_HASH_ML_DSA_SHA3_224` | `0x00000027UL` | Pre-hash with SHA3-224 |
| `CKM_HASH_ML_DSA_SHA3_256` | `0x00000028UL` | Pre-hash with SHA3-256 |
| `CKM_HASH_ML_DSA_SHA3_384` | `0x00000029UL` | Pre-hash with SHA3-384 |
| `CKM_HASH_ML_DSA_SHA3_512` | `0x0000002aUL` | Pre-hash with SHA3-512 |
| `CKM_HASH_ML_DSA_SHAKE128` | `0x0000002bUL` | Pre-hash with SHAKE-128 |
| `CKM_HASH_ML_DSA_SHAKE256` | `0x0000002cUL` | Pre-hash with SHAKE-256 |

> **Note:** `CKM_ML_DSA` is the pure-message variant (context string optional).
> `CKM_HASH_ML_DSA*` variants pre-hash with the specified digest before signing.
> For Phase 2, implement `CKM_ML_DSA_KEY_PAIR_GEN` + `CKM_ML_DSA` first;
> hash variants can follow.

### 2.2 ML-KEM (FIPS 203) — Phase 3 (#4)

OpenSSL 3.3+ EVP_PKEY names: `"mlkem512"`, `"mlkem768"`, `"mlkem1024"`

| Mechanism | Hex value | Operation |
|---|---|---|
| `CKM_ML_KEM_KEY_PAIR_GEN` | `0x0000000fUL` | `C_GenerateKeyPair` |
| `CKM_ML_KEM` | `0x00000017UL` | `C_EncapsulateKey` / `C_DecapsulateKey` |

Mechanism flags for `CKM_ML_KEM` in the info struct must include:
```c
CKF_ENCAPSULATE  0x10000000UL
CKF_DECAPSULATE  0x20000000UL
```

### 2.3 SLH-DSA (FIPS 205) — Phase 2 or 2.5

OpenSSL 3.3+ EVP_PKEY names: `"slh-dsa-sha2-128s"`, `"slh-dsa-sha2-128f"`,
`"slh-dsa-sha2-192s"`, `"slh-dsa-sha2-192f"`, `"slh-dsa-sha2-256s"`, `"slh-dsa-sha2-256f"`,
`"slh-dsa-shake-128s"`, `"slh-dsa-shake-128f"`, `"slh-dsa-shake-192s"`, `"slh-dsa-shake-192f"`,
`"slh-dsa-shake-256s"`, `"slh-dsa-shake-256f"`

| Mechanism | Hex value | Operation |
|---|---|---|
| `CKM_SLH_DSA_KEY_PAIR_GEN` | `0x0000002dUL` | `C_GenerateKeyPair` |
| `CKM_SLH_DSA` | `0x0000002eUL` | `C_Sign` / `C_Verify` (pure message) |
| `CKM_HASH_SLH_DSA` | `0x00000034UL` | Pre-hash variant |
| `CKM_HASH_SLH_DSA_SHA224` | `0x00000036UL` | Pre-hash with SHA-224 |
| `CKM_HASH_SLH_DSA_SHA256` | `0x00000037UL` | Pre-hash with SHA-256 |
| `CKM_HASH_SLH_DSA_SHA384` | `0x00000038UL` | Pre-hash with SHA-384 |
| `CKM_HASH_SLH_DSA_SHA512` | `0x00000039UL` | Pre-hash with SHA-512 |
| `CKM_HASH_SLH_DSA_SHA3_224` | `0x0000003aUL` | Pre-hash with SHA3-224 |
| `CKM_HASH_SLH_DSA_SHA3_256` | `0x0000003bUL` | Pre-hash with SHA3-256 |
| `CKM_HASH_SLH_DSA_SHA3_384` | `0x0000003cUL` | Pre-hash with SHA3-384 |
| `CKM_HASH_SLH_DSA_SHA3_512` | `0x0000003dUL` | Pre-hash with SHA3-512 |
| `CKM_HASH_SLH_DSA_SHAKE128` | `0x0000003eUL` | Pre-hash with SHAKE-128 |
| `CKM_HASH_SLH_DSA_SHAKE256` | `0x0000003fUL` | Pre-hash with SHAKE-256 |

---

## 3. CKK_* Key Type Gaps

Defined in `src/lib/pkcs11/pkcs11t.h` but not handled in:
- `src/lib/P11Objects.cpp` — object class dispatch
- `src/lib/P11Attributes.cpp` — attribute get/set
- `src/lib/SoftHSM.cpp` — key storage and retrieval helpers

No crypto implementation files exist yet for any PQC key type:

| Key type | Hex | Files needed (pattern: OSSLEDDSA) | Phase |
|---|---|---|---|
| `CKK_ML_DSA` | `0x0000004aUL` | `OSSLMLDSAPublicKey.{h,cpp}`, `OSSLMLDSAPrivateKey.{h,cpp}`, `OSSLMLDSAKeyPair.{h,cpp}`, `OSSLMLDSA.{h,cpp}` | Phase 2 (#3) |
| `CKK_SLH_DSA` | `0x0000004bUL` | `OSSLSLHDSAPublicKey.{h,cpp}`, `OSSLSLHDSAPrivateKey.{h,cpp}`, `OSSLSLHDSAKeyPair.{h,cpp}`, `OSSLSLHDSA.{h,cpp}` | Phase 2/2.5 |
| `CKK_ML_KEM` | `0x00000049UL` | `OSSLMLKEMPublicKey.{h,cpp}`, `OSSLMLKEMPrivateKey.{h,cpp}`, `OSSLMLKEMKeyPair.{h,cpp}`, `OSSLMLKEM.{h,cpp}` | Phase 3 (#4) |

Reference pattern: `OSSLEDDSA.cpp` + `OSSLEDPublicKey.cpp` / `OSSLEDPrivateKey.cpp`
(already use EVP_PKEY throughout — copy and adapt).

---

## 4. CKA_* Attribute Gaps

Defined in `src/lib/pkcs11/pkcs11t.h` but not parsed in `src/lib/P11Attributes.cpp`
or stored in the object database.

| Attribute | Hex | Purpose | Severity | Phase |
|---|---|---|---|---|
| `CKA_PARAMETER_SET` | `0x0000061dUL` | Selects PQC parameter set (ML-KEM-512/768/1024; ML-DSA-44/65/87; SLH-DSA variant string) | **BLOCKER** | Phase 2+3 |
| `CKA_ENCAPSULATE` | `0x00000633UL` | Boolean: key may be used for encapsulation | HIGH | Phase 3 (#4) |
| `CKA_DECAPSULATE` | `0x00000634UL` | Boolean: key may be used for decapsulation | HIGH | Phase 3 (#4) |
| `CKA_ENCAPSULATE_TEMPLATE` | `0x0000062aUL` | Attribute array constraining derived secret from encapsulation | HIGH | Phase 3 (#4) |
| `CKA_DECAPSULATE_TEMPLATE` | `0x0000062bUL` | Attribute array constraining derived secret from decapsulation | HIGH | Phase 3 (#4) |

### CKA_PARAMETER_SET values (PKCS#11 v3.2 §6.x)

The spec defines `CKA_PARAMETER_SET` as a `CK_ULONG` whose value identifies the
parameter set. For the in-scope algorithms:

| Algorithm | Parameter sets |
|---|---|
| ML-KEM | `CKP_ML_KEM_512`, `CKP_ML_KEM_768`, `CKP_ML_KEM_1024` |
| ML-DSA | `CKP_ML_DSA_44`, `CKP_ML_DSA_65`, `CKP_ML_DSA_87` |
| SLH-DSA | `CKP_SLH_DSA_SHA2_128S`, `CKP_SLH_DSA_SHA2_128F`, `CKP_SLH_DSA_SHA2_192S`, `CKP_SLH_DSA_SHA2_192F`, `CKP_SLH_DSA_SHA2_256S`, `CKP_SLH_DSA_SHA2_256F`, `CKP_SLH_DSA_SHAKE_128S`, `CKP_SLH_DSA_SHAKE_128F`, `CKP_SLH_DSA_SHAKE_192S`, `CKP_SLH_DSA_SHAKE_192F`, `CKP_SLH_DSA_SHAKE_256S`, `CKP_SLH_DSA_SHAKE_256F` |

> Without `CKA_PARAMETER_SET`, the token has no way to distinguish ML-KEM-512
> from ML-KEM-768, or to route `C_GenerateKeyPair` to the correct OpenSSL EVP_PKEY name.

---

## 5. OpenSSL 3.6 Algorithm Support Matrix

All in-scope algorithms are natively supported in OpenSSL 3.3+ with no external provider.
The EVP_PKEY name strings to use in `EVP_PKEY_CTX_new_from_name(NULL, name, NULL)`:

| Algorithm | Parameter set | OpenSSL EVP_PKEY name | Since |
|---|---|---|---|
| ML-KEM | ML-KEM-512 | `"mlkem512"` | 3.3 |
| ML-KEM | ML-KEM-768 | `"mlkem768"` | 3.3 |
| ML-KEM | ML-KEM-1024 | `"mlkem1024"` | 3.3 |
| ML-DSA | ML-DSA-44 | `"ml-dsa-44"` | 3.3 |
| ML-DSA | ML-DSA-65 | `"ml-dsa-65"` | 3.3 |
| ML-DSA | ML-DSA-87 | `"ml-dsa-87"` | 3.3 |
| SLH-DSA | SLH-DSA-SHA2-128s | `"slh-dsa-sha2-128s"` | 3.3 |
| SLH-DSA | SLH-DSA-SHA2-128f | `"slh-dsa-sha2-128f"` | 3.3 |
| SLH-DSA | SLH-DSA-SHA2-192s | `"slh-dsa-sha2-192s"` | 3.3 |
| SLH-DSA | SLH-DSA-SHA2-192f | `"slh-dsa-sha2-192f"` | 3.3 |
| SLH-DSA | SLH-DSA-SHA2-256s | `"slh-dsa-sha2-256s"` | 3.3 |
| SLH-DSA | SLH-DSA-SHA2-256f | `"slh-dsa-sha2-256f"` | 3.3 |
| SLH-DSA | SLH-DSA-SHAKE-128s | `"slh-dsa-shake-128s"` | 3.3 |
| SLH-DSA | SLH-DSA-SHAKE-128f | `"slh-dsa-shake-128f"` | 3.3 |
| SLH-DSA | SLH-DSA-SHAKE-192s | `"slh-dsa-shake-192s"` | 3.3 |
| SLH-DSA | SLH-DSA-SHAKE-192f | `"slh-dsa-shake-192f"` | 3.3 |
| SLH-DSA | SLH-DSA-SHAKE-256s | `"slh-dsa-shake-256s"` | 3.3 |
| SLH-DSA | SLH-DSA-SHAKE-256f | `"slh-dsa-shake-256f"` | 3.3 |

> **Note:** SHAKE variants (SHAKE-128, SHAKE-256) for pre-hash ML-DSA / SLH-DSA
> require OpenSSL's XOF (extendable output function) API — verify availability in 3.6 before implementing.

---

## 6. Phase Milestone Mapping

| Gap | GitHub issues | Phase |
|---|---|---|
| `C_GetInterfaceList` / `C_GetInterface` | #8 | Phase 2 (#3) |
| `C_SignMessage` / `C_VerifyMessage` + streaming | #10 | Phase 2 (#3) |
| `CKA_PARAMETER_SET` | #13 | Phase 2 (#3) |
| `CKK_ML_DSA` + `CKM_ML_DSA*` + crypto files | #11 | Phase 2 (#3) |
| `CKK_SLH_DSA` + `CKM_SLH_DSA*` + crypto files | #12 | Phase 2/2.5 |
| `C_EncapsulateKey` / `C_DecapsulateKey` | #9 | Phase 3 (#4) |
| `CKK_ML_KEM` + `CKM_ML_KEM*` + crypto files | #14 | Phase 3 (#4) |
| `CKA_ENCAPSULATE` / `CKA_DECAPSULATE` + templates | #15 | Phase 3 (#4) |

---

## 7. Recommended Implementation Order (Phase 2)

1. `CKA_PARAMETER_SET` in `P11Attributes.cpp` — needed by all PQC key types
2. `C_GetInterfaceList` / `C_GetInterface` — unblocks v3.x callers
3. `CKK_ML_DSA` key type: `OSSLMLDSAPublicKey` + `OSSLMLDSAPrivateKey` + `OSSLMLDSA`
4. `CKM_ML_DSA_KEY_PAIR_GEN` + `CKM_ML_DSA` dispatch in `SoftHSM.cpp`
5. `C_SignMessage` / `C_VerifyMessage` for ML-DSA one-shot signing
6. `CKK_SLH_DSA` key type + `CKM_SLH_DSA*` (same pattern as ML-DSA)

Phase 3 then adds ML-KEM and the KEM API (`C_EncapsulateKey` / `C_DecapsulateKey`).
