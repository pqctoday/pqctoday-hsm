# PKCS#11 v3.2 Compliance Gap Analysis — softhsmv3 (v9)

**Updated:** 2026-04-01 (v9 — SLH-DSA context string G4 + deterministic mode G5 resolved, full C++/Rust/TypeScript parity)
**Baseline:** Post-Phase-8 + G4 (SLH-DSA context string, FIPS 205 §9.2) + G5 (SLH-DSA deterministic mode, FIPS 205 §10) — all tracked gaps resolved
**Spec reference:** OASIS PKCS#11 v3.2 CSD01 (<http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.2/>)
**Prior baseline (v8):** CKM_KMAC_128/256 vendor extension (G-KMAC1/KMAC2), C_GetMechanismInfo full coverage (2026-03-13).

---

## Executive Summary

All NIST PQC finalists (ML-KEM, ML-DSA, SLH-DSA) are fully implemented.
All v3.2 KEM functions (`C_EncapsulateKey`, `C_DecapsulateKey`) are implemented.
All v3.0/v3.2 message sign/verify functions are implemented (one-shot and streaming).
All v3.2 pre-hash mechanisms for both ML-DSA and SLH-DSA are registered and dispatched.
All v3.2 additions tracked as G1–G6 are implemented.
**v4:** `CKM_PKCS5_PBKD2` (G-DA1) and `CKM_ECDSA_SHA3_224/256/384/512` (G-DA2)
implemented — completing the Digital Assets module crypto requirements.
**v5:** `CKM_AES_CTR` (G-5G1), `CKD_SHA256_KDF` on `CKM_ECDH1_DERIVE` (G-5G2),
and `CKM_HKDF_DERIVE` (G-5G3) implemented — completing the 5G Security module PKCS#11 path
for SUCI deconcealment (3GPP TS 33.501 §6.12.2).
**NEW (v6):** `CKA_PUBLIC_KEY_INFO` (G-PUB1) computed at keygen for all 6 key types
(RSA, EC, EdDSA, ML-DSA, SLH-DSA, ML-KEM) via `i2d_PUBKEY()`. `CKM_SP800_108_COUNTER_KDF`
(G-PK1) implemented using OpenSSL KBKDF — completes NIST SP 800-108 counter mode support.
**NEW (v7):** `CKM_SP800_108_FEEDBACK_KDF` (G-PK2) implemented — SP 800-108 feedback mode
KBKDF with optional IV seed via `OSSL_KDF_PARAM_SEED`. `CKM_ECDH1_COFACTOR_DERIVE` (G-PK4)
implemented via new `OSSLECDH::deriveKeyWithCofactor()` using `EVP_PKEY_CTX_set_ecdh_cofactor_mode`.
**Bugfix (v7):** `C_DeriveKey` validation switch was missing `CKM_HKDF_DERIVE` and
`CKM_SP800_108_COUNTER_KDF` case labels — these mechanisms were unreachable (added in prior
sessions but not gated in the `#ifndef WITH_FIPS` switch). All KDF mechanisms now correctly
listed in the validation switch.
**NEW (v8):** `CKM_KMAC_128` (G-KMAC1) and `CKM_KMAC_256` (G-KMAC2) implemented as
vendor-defined MAC mechanisms (`CKM_VENDOR_DEFINED | 0x100/0x101`) in both C++ (`OSSLKMAC.cpp`,
OpenSSL `EVP_MAC_fetch("KMAC-128/256")`) and Rust (`kmac` crate). Both engines expose
`CKF_SIGN | CKF_VERIFY` and support variable-length output.
**Bugfix (v8):** `C_GetMechanismInfo` now handles all 30 mechanisms advertised by
`C_GetMechanismList`. Previously, AES-CTR, all pre-hash ML-DSA/SLH-DSA variants, ECDSA-SHA3
variants, ECDH1-cofactor, and all KDF mechanisms fell through to `CKR_MECHANISM_INVALID` —
a contradiction visible in the playground log during mechanism discovery.
**NEW (v9):** SLH-DSA context string (G4, FIPS 205 §9.2) and deterministic signing (G5,
FIPS 205 §10) implemented across the full stack:
- C++: `SLHDSA_SIGN_PARAMS.deterministic` added; `CKM_SLH_DSA` sign/verify init now accepts
  optional `CK_SIGN_ADDITIONAL_CONTEXT`; `OSSLSLHDSA::sign/verify` apply
  `OSSL_SIGNATURE_PARAM_CONTEXT_STRING` and `OSSL_SIGNATURE_PARAM_DETERMINISTIC` via
  `EVP_PKEY_CTX_set_params`.
- Rust: `SIGN_STATE`/`VERIFY_STATE` expanded to `(mech, key, ctx: Vec<u8>, deterministic: bool)`;
  `parse_slh_dsa_ctx` helper parses `CK_SIGN_ADDITIONAL_CONTEXT` (WASM32 layout) in all init
  paths; `slh_dsa_sign!`/`slh_dsa_verify!` macros and `sign_slh_dsa`/`verify_slh_dsa` functions
  accept `ctx` + `deterministic`; 3 new unit tests validate context, deterministic, and
  cross-context failure.
- TypeScript: `SLHDSASignOptions.context` and `.deterministic` added; `buildSlhDsaSignContext`
  helper allocates `CK_SIGN_ADDITIONAL_CONTEXT` in WASM heap; `hsm_slhdsaSign` and
  `hsm_slhdsaVerify` pass context params for pure `CKM_SLH_DSA`.
- Playground UI: SLH-DSA panel gains Context text input and Deterministic checkbox (hidden in
  pre-hash mode).

| Dimension | Remaining open | Notes |
| --- | --- | --- |
| C_* function stubs (in scope) | 0 | All G1–G6 + G-DA1/G-DA2 + G-5G1/5G2/5G3 + G-PUB1/G-PK1/G-PK2/G-PK4 + G-KMAC1/KMAC2 resolved |
| CKM_* mechanisms (in scope) | 0 | AES-CTR, HKDF, X9.63 KDF, SP 800-108 Counter+Feedback KDF, ECDH1 Cofactor, KMAC-128/256 added |
| CKA_* attribute stubs (in scope) | 0 | CKA_PUBLIC_KEY_INFO now populated at keygen for all key types |
| Out-of-scope stubs | 3 | Async (G7), Recovery/Combined ops (G8) |
| Out-of-scope mechanisms | 1 | CKM_RIPEMD160 (WASM `no-module` constraint, G9) |

---

## 1. Resolved Gaps (v2 list — G1–G6)

All of the following were open in the v2 baseline and are now confirmed implemented.

### 1.1 G1 — CKM_HASH_SLH_DSA* — 13 pre-hash mechanism variants ✓ RESOLVED

All 13 SLH-DSA pre-hash mechanisms are:

- **Registered** in `prepareSupportedMechanisms()` (`src/lib/SoftHSM_slots.cpp:414–427`)
- **Dispatched** in `AsymSignInit()` and `AsymVerifyInit()` (`src/lib/SoftHSM_sign.cpp`, `HASH_SLHDSA_CASE` macros)
- **Handled** in `OSSLSLHDSA.cpp` (`AsymMech::HASH_SLHDSA` through `HASH_SLHDSA_SHAKE256`)
- **Defined** in `AsymmetricAlgorithm.h` enum

Full parity with ML-DSA pre-hash (12 hash variants each, plus 1 generic = 13 total for each).

Playground integration also resolved: `softhsm.ts` now exports `CKM_HASH_SLH_DSA_*` constants
and `hsm_slhdsaSign`/`hsm_slhdsaVerify` accept `opts.preHash` for all 10 hash variants.

### 1.2 G2 — Streaming message sign/verify — 4 functions ✓ RESOLVED

| Function | File | Lines |
| --- | --- | --- |
| `C_SignMessageBegin` | `SoftHSM_sign.cpp` | 2461 |
| `C_SignMessageNext` | `SoftHSM_sign.cpp` | 2484 |
| `C_VerifyMessageBegin` | `SoftHSM_sign.cpp` | 2528 |
| `C_VerifyMessageNext` | `SoftHSM_sign.cpp` | 2549 |

### 1.3 G3 — Message Encrypt/Decrypt API — 10 functions ✓ RESOLVED

All 10 functions implemented in `src/lib/SoftHSM_cipher.cpp` (from line 1299).
`C_MessageEncryptInit` at line 1529. State machine uses `SESSION_OP_MESSAGE_ENCRYPT` (0x15).

### 1.4 G4 — C_VerifySignature* — 4 functions ✓ RESOLVED

| Function | File | Lines |
| --- | --- | --- |
| `C_VerifySignatureInit` | `SoftHSM_sign.cpp` | 2595 |
| `C_VerifySignature` | `SoftHSM_sign.cpp` | (follows) |
| `C_VerifySignatureUpdate` | `SoftHSM_sign.cpp` | (follows) |
| `C_VerifySignatureFinal` | `SoftHSM_sign.cpp` | (follows) |

State: `SESSION_OP_VERIFY_SIGNATURE` (0x19) defined in `session_mgr/Session.h:65`.

### 1.5 G5 — Authenticated key wrapping — 2 functions ✓ RESOLVED

| Function | File | Lines |
| --- | --- | --- |
| `C_WrapKeyAuthenticated` | `SoftHSM_keygen.cpp` | 1568 |
| `C_UnwrapKeyAuthenticated` | `SoftHSM_keygen.cpp` | (follows) |

### 1.6 G6 — v3.0 session management — 2 functions ✓ RESOLVED

| Function | File | Lines |
| --- | --- | --- |
| `C_LoginUser` | `SoftHSM_sessions.cpp` | 238 |
| `C_SessionCancel` | `SoftHSM_sessions.cpp` | 250 |

---

## 1.5 Digital Assets Module Gaps (v4 additions — G-DA1, G-DA2)

Identified via audit of the Digital Assets learning module crypto operations cross-referenced
against PKCS#11 v3.2 spec. All Digital Assets crypto was mapped; two mechanisms were missing.

### 1.7 G-DA1 — `CKM_PKCS5_PBKD2` — PBKDF2 key derivation ✓ RESOLVED

**Need:** BIP39 mnemonic → 64-byte seed derivation (`PBKDF2-HMAC-SHA512`, 2048 iterations).
**PKCS#11 v3.2:** `§5.7.3.1` — `CKM_PKCS5_PBKD2` (`0x000003b0`), uses `CK_PKCS5_PBKD2_PARAMS2`.

| Component | File | Change |
| --- | --- | --- |
| Mechanism registry | `SoftHSM_slots.cpp:356` | Added `CKM_PKCS5_PBKD2` with `CKF_DERIVE` |
| C_DeriveKey handler | `SoftHSM_keygen.cpp:1908` | PBKDF2 early-return path (no base key) |
| OpenSSL call | `SoftHSM_keygen.cpp` | `PKCS5_PBKDF2_HMAC()` — maps `CKP_PKCS5_PBKD2_HMAC_{SHA1,SHA224,SHA256,SHA384,SHA512}` |
| Playground constant | `softhsm.ts:1103` | `CKM_PKCS5_PBKD2 = 0x3b0` + `CKP_PKCS5_PBKD2_HMAC_*` |
| Playground helper | `softhsm.ts:1669` | `hsm_pbkdf2(M, hSession, password, salt, iterations, keyLen, prf?)` |
| Learning module | `hsmConstants.ts` | Added to `PKCS11_MECHANISMS` array |

**PRFs supported:** SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (default: SHA-512 for BIP39).

### 1.8 G-DA2 — `CKM_ECDSA_SHA3_224/256/384/512` — ECDSA with SHA-3 prehash ✓ RESOLVED

**Need:** PKCS#11 v3.2 §6.3 spec completeness. SHA-3 hash support already existed; only
  registration and dispatch were missing.

| Component | File | Change |
| --- | --- | --- |
| Enum values | `AsymmetricAlgorithm.h:98` | Added `ECDSA_SHA3_{224,256,384,512}` |
| OpenSSL dispatch | `OSSLECDSA.cpp:108,245` | Added `EVP_sha3_{224,256,384,512}()` in `sign()` + `verify()` |
| Mechanism registry | `SoftHSM_slots.cpp:391` | Registered 4 `CKM_ECDSA_SHA3_*` mechanisms |
| Sign dispatch | `SoftHSM_sign.cpp:670` | Added 4 cases in `AsymSignInit()` |
| Verify dispatch | `SoftHSM_sign.cpp:1670` | Added 4 cases in `AsymVerifyInit()` |
| Playground constants | `softhsm.ts:1091` | `CKM_ECDSA_SHA3_{224,256,384,512} = 0x1047–0x104a` |
| Learning module | `hsmConstants.ts` | Added 4 entries to `PKCS11_MECHANISMS` |

**Note:** `CKM_RIPEMD160` is **not** implemented — see G11 below for rationale.

---

## 1.9 5G Security Module Gaps (v5 additions — G-5G1, G-5G2, G-5G3)

Identified via audit of the 5G Security learning module (SUCI deconcealment + MILENAGE) crypto
operations cross-referenced against PKCS#11 v3.2 and softhsmv3 coverage.

**Context:** 5G NR SUCI (3GPP TS 33.501 §6.12.2) uses ECIES-based subscriber privacy:
Profile A (X25519 + ANSI X9.63-SHA256 KDF + AES-128-CTR + HMAC-SHA256),
Profile B (P-256 + same), Profile C (ML-KEM-768 hybrid + AES-256-CTR + HMAC-SHA3-256).
MILENAGE (TS 35.206) uses AES-128-ECB for f1–f5. KAUSF uses HMAC-SHA-256.

### 1.9 G-5G1 — `CKM_AES_CTR` — AES Counter mode ✓ RESOLVED

**Need:** SUCI MSIN encryption for Profiles A/B (AES-128-CTR) and Profile C (AES-256-CTR).
`CKM_AES_CTR` was already registered and dispatched in softhsmv3 (slots.cpp:380, cipher.cpp:59,130,746)
but was missing from the app-side WASM wrapper — app-only fix, no WASM rebuild required.

**`CK_AES_CTR_PARAMS`** (20 bytes): `ulCounterBits`[4] + `cb[16]` counter/IV block. For SUCI:
`ulCounterBits = 128`, `cb = 00...00` (zero IV per 3GPP spec).

| Component | File | Change |
| --- | --- | --- |
| Constants | `softhsm.ts:~1113` | `CKM_AES_ECB = 0x1081`, `CKM_AES_CTR = 0x1086` |
| Helper | `softhsm.ts` | `hsm_aesCtrEncrypt(M, hSession, key, ctrIv, counterBits, data)` |
| Helper | `softhsm.ts` | `hsm_aesCtrDecrypt(M, hSession, key, ctrIv, counterBits, data)` |
| Learning module | `hsmConstants.ts` | Added `ckm-aes-ecb` and `ckm-aes-ctr` entries |

### 1.10 G-5G2 — `CKD_SHA256_KDF` on `CKM_ECDH1_DERIVE` — ANSI X9.63 KDF ✓ RESOLVED

**Need:** SUCI Profiles A/B key derivation after ECDH — `K = SHA256(Z ∥ counter ∥ SharedInfo)`
(ANSI X9.63, 3GPP TS 33.501 §C.3). Maps to `CKM_ECDH1_DERIVE` with `kdf = CKD_SHA256_KDF`
in `CK_ECDH1_DERIVE_PARAMS`. Previously softhsmv3 rejected any `kdf != CKD_NULL`.

**OpenSSL implementation:** `EVP_KDF_fetch(NULL, "X963KDF", NULL)` + `EVP_KDF_derive()` with
`OSSL_KDF_PARAM_DIGEST`, `OSSL_KDF_PARAM_SECRET`, `OSSL_KDF_PARAM_INFO` (SharedInfo).
KDF confirmed present in WASM libcrypto.a via `ossl_kdf_x963_kdf_functions` symbol.
Used non-deprecated OpenSSL 3.x EVP_KDF API (not `ECDH_KDF_X9_62` which is OSSL_DEPRECATEDIN_3_0).

| Component | File | Change |
| --- | --- | --- |
| Validation fix (ECDH) | `SoftHSM_keygen.cpp:deriveECDH()` | Accept `CKD_SHA{1,256,384,512}_KDF`; reject only unknown KDFs |
| KDF dispatch (ECDH) | `SoftHSM_keygen.cpp:deriveECDH()` | After `secret->getKeyBits()`: apply `EVP_KDF X963KDF` if `kdf != CKD_NULL` |
| Validation fix (EdDSA/X25519) | `SoftHSM_keygen.cpp:deriveEDDSA()` | Same as ECDH |
| KDF dispatch (EdDSA/X25519) | `SoftHSM_keygen.cpp:deriveEDDSA()` | Same as ECDH |
| New includes | `SoftHSM_keygen.cpp:79` | `<openssl/kdf.h>`, `<openssl/core_names.h>`, `<openssl/params.h>` |
| File-scope helpers | `SoftHSM_keygen.cpp:89` | `ckdToDigestName()`, `ckmToDigestName()` static functions |
| Constants | `softhsm.ts` | `CKD_SHA1_KDF=0x2`, `CKD_SHA256_KDF=0x6`, `CKD_SHA384_KDF=0x7`, `CKD_SHA512_KDF=0x8` |
| API update | `softhsm.ts:hsm_ecdhDerive()` | New optional params: `kdf`, `sharedData`, `keyLen` |

**KDFs supported:** SHA-1, SHA-256, SHA-384, SHA-512 via `CKD_SHA{1,256,384,512}_KDF`.
**Note:** `checkValue = false` applied when KDF is active — KCV not meaningful for KDF-derived keys.

### 1.11 G-5G3 — `CKM_HKDF_DERIVE` — HMAC-based KDF ✓ RESOLVED

**Need:** PKCS#11 v3.0 standard HKDF mechanism for hybrid key combination (SUCI Profile C:
`SHA256(Z_ecdh ∥ Z_kem) → KDF`), TLS 1.3 key schedule, Signal Protocol.
`CKM_HKDF_DERIVE = 0x0000402a`. Not present in softhsmv3 prior to this fix.

**OpenSSL implementation:** `EVP_KDF_fetch(NULL, "HKDF", NULL)` + `EVP_KDF_derive()` with
`OSSL_KDF_PARAM_MODE` (integer: `EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND` etc.),
`OSSL_KDF_PARAM_DIGEST`, `OSSL_KDF_PARAM_KEY` (IKM from base key), `OSSL_KDF_PARAM_SALT`,
`OSSL_KDF_PARAM_INFO`. Base key value retrieved via `key->getByteStringValue(CKA_VALUE)`.

| Component | File | Change |
| --- | --- | --- |
| Mechanism registry | `SoftHSM_slots.cpp:358` | `CKM_HKDF_DERIVE` registered |
| C_DeriveKey handler | `SoftHSM_keygen.cpp:2194` | HKDF block between ECDH and symmetric derive dispatchers |
| Constant | `softhsm.ts` | `CKM_HKDF_DERIVE = 0x402a`, `CKF_HKDF_SALT_NULL = 0x1`, `CKF_HKDF_SALT_DATA = 0x2` |
| Helper | `softhsm.ts` | `hsm_hkdf(M, hSession, baseKeyHandle, prf, bExtract, bExpand, salt?, info?, keyLen?)` |
| Learning module | `hsmConstants.ts` | Added `ckm-hkdf-derive` entry |

**PRFs supported:** `CKM_SHA_1`, `CKM_SHA256`, `CKM_SHA384`, `CKM_SHA512`, `CKM_SHA3_256`, `CKM_SHA3_384`, `CKM_SHA3_512`.
**Salt types supported:** `CKF_HKDF_SALT_NULL`, `CKF_HKDF_SALT_DATA`. (`CKF_HKDF_SALT_KEY` — not supported.)
**Modes:** Extract-and-Expand, Extract-only, Expand-only (driven by `bExtract`/`bExpand` flags).

**`CK_HKDF_PARAMS` layout in WASM (32 bytes):**
- Offsets 0–1: `bExtract`, `bExpand` (CK_BBOOL, 1 byte each)
- Offsets 2–3: padding (C struct alignment)
- Offsets 4–31: `prfHashMechanism`, `ulSaltType`, `pSalt`, `ulSaltLen`, `hSaltKey`, `pInfo`, `ulInfoLen` (4 bytes each)

---

## 1.12 Compliance Audit Gaps (v6 additions — G-PUB1, G-PK1)

### 1.12 G-PUB1 — `CKA_PUBLIC_KEY_INFO` — SubjectPublicKeyInfo attribute ✓ RESOLVED

**Need:** PKCS#11 v3.2 §4.14 mandates that all key-pair generation operations populate
`CKA_PUBLIC_KEY_INFO` (attribute type `0x00000129`) on both the public key object and the
private key object with the DER-encoded SubjectPublicKeyInfo of the public key.
Previously the attribute was accepted but always stored as an empty ByteString (3 TODO comments
in `P11Objects.cpp` at lines 428, 705, 1026).

**OpenSSL implementation:** `i2d_PUBKEY(pkey, &p)` — encodes the `EVP_PKEY*` to DER.
All OSSL key classes expose `getOSSLKey()` returning `EVP_PKEY*`; a static helper
`spkiFromPkey(EVP_PKEY*)` calls `i2d_PUBKEY` and returns a `ByteString`.

| Key type | Public key site | Private key site | Cast used |
| --- | --- | --- | --- |
| RSA | `SoftHSM_keygen.cpp` after `CKA_PUBLIC_EXPONENT` | After `CKA_COEFFICIENT` | `(OSSLRSAPublicKey*)pub` |
| EC (ECDSA) | After `CKA_EC_POINT` | After `CKA_VALUE` | `(OSSLECPublicKey*)pub` |
| EdDSA/X25519 | After `CKA_EC_POINT` (value = A) | After `CKA_VALUE` (K) | `(OSSLEDPublicKey*)pub` |
| ML-DSA | After `CKA_VALUE` (public) | After `CKA_VALUE` (private) | `(OSSLMLDSAPublicKey*)pub` |
| SLH-DSA | After `CKA_VALUE` (public) | After `CKA_VALUE` (private) | `(OSSLSLHDSAPublicKey*)pub` |
| ML-KEM | After `CKA_VALUE` (public) | After `CKA_VALUE` (private) | `(OSSLMLKEMPublicKey*)pub` |

**Notes:**
- `CKA_PUBLIC_KEY_INFO` is never encrypted — it is always the SubjectPublicKeyInfo of the public key, stored in clear even on private key objects.
- X.509 certificate case (TODO at `P11Objects.cpp:428`) remains open — requires parsing `CKA_VALUE` (DER cert) at `C_CreateObject` time. Deferred.
- New includes added to `SoftHSM_keygen.cpp`: `OSSLRSAPublicKey.h`, `OSSLECPublicKey.h`, `OSSLEDPublicKey.h`, `<openssl/x509.h>`.

---

### 1.13 G-PK1 — `CKM_SP800_108_COUNTER_KDF` — NIST SP 800-108 Counter KDF ✓ RESOLVED

**Need:** PKCS#11 v3.2 §2.44 defines three SP 800-108 KBKDF mechanisms. Counter mode
(`CKM_SP800_108_COUNTER_KDF = 0x000003ac`) is the most widely deployed — used in
Microsoft CNG, AWS KMS, PKCS#11 HSM interop scenarios. OpenSSL's `ossl_kdf_kbkdf_functions`
is confirmed present in the WASM `libcrypto.a`.

**OpenSSL implementation:** `EVP_KDF_fetch(NULL, "KBKDF", NULL)` + `EVP_KDF_derive()` with:
- `OSSL_KDF_PARAM_MODE = "COUNTER"`
- `OSSL_KDF_PARAM_MAC = "HMAC"` or `"CMAC"`
- `OSSL_KDF_PARAM_DIGEST` (for HMAC) or `OSSL_KDF_PARAM_CIPHER` (for CMAC)
- `OSSL_KDF_PARAM_KEY` = base key bytes (IKM = Ki)
- `OSSL_KDF_PARAM_SALT` = concatenated `CK_SP800_108_BYTE_ARRAY` params (label/context)
- `OSSL_KDF_PARAM_KBKDF_R` = counter width in bits (from `CK_SP800_108_COUNTER_FORMAT`, default 32)

**CK_SP800_108_KDF_PARAMS parsing:**
- `CK_SP800_108_BYTE_ARRAY` data params → concatenated into fixed-input buffer (label ∥ context)
- `CK_SP800_108_ITERATION_VARIABLE` param → optional `CK_SP800_108_COUNTER_FORMAT` for counter width
- `CK_SP800_108_DKM_LENGTH` and `CK_SP800_108_KEY_HANDLE` → silently skipped (not supported)
- `pAdditionalDerivedKeys` / `ulAdditionalDerivedKeys` → must be 0/NULL (not supported)

| Component | File | Change |
| --- | --- | --- |
| Mechanism registry | `SoftHSM_slots.cpp` after `CKM_HKDF_DERIVE` | `CKM_SP800_108_COUNTER_KDF` registered |
| C_DeriveKey handler | `SoftHSM_keygen.cpp` before HKDF block | Full counter KDF handler (~130 LOC) |
| Constant | `softhsm.ts` | `CKM_SP800_108_COUNTER_KDF = 0x3ac`, feedback/double-pipeline constants, `CK_SP800_108_ITERATION_VARIABLE`, `CK_SP800_108_BYTE_ARRAY` |
| Helper | `softhsm.ts` | `hsm_kbkdf(M, hSession, baseKeyHandle, prfType, fixedInput?, keyLen?)` |
| Learning module | `hsmConstants.ts` | Added `ckm-sp800-108-counter-kdf` entry |

**PRFs supported:** `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, `CKM_SHA512_HMAC`, `CKM_SHA_1_HMAC`, `CKM_SHA3_*_HMAC` (via `ckmToDigestName`); `CKM_AES_CMAC` (AES-128/192/256 auto-detected from key size).

---

## 2. Previously Resolved Gaps (v1 list, Phase 0–6)

All 50 gaps from the v1 baseline remain resolved. Closed GitHub issues: #8–#22.
See v2 document section §1 for the complete list.

---

## 3. Explicitly Out of Scope

### 3.1 G7 — Async operations

`C_AsyncComplete` (`main.cpp:1812`), `C_AsyncGetID` (`main.cpp:1818`), `C_AsyncJoin` (`main.cpp:1824`)

Return `CKR_FUNCTION_NOT_SUPPORTED`. Requires `CKF_ASYNC_SESSION` mode and thread-safe
promise-based state machine. No PQC tooling requires this. Omission is acceptable per
PKCS#11 v3.2 §3.4 which marks async as optional when not advertised.

### 3.2 G8 — Recovery and combined operations

`C_SignRecoverInit`, `C_SignRecover` (`SoftHSM_sign.cpp:1181, 1194`)
`C_VerifyRecoverInit`, `C_VerifyRecover` (`SoftHSM_sign.cpp:2790, 2803`)
`C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`
(`SoftHSM_sign.cpp:2818–2875`)

Return `CKR_FUNCTION_NOT_SUPPORTED`. Optional combined/recovery operations from PKCS#11 v2.0.
SoftHSM2 v2.7.0 also omits them. No PQC algorithm requires them.

### 3.3 G9 — Session validation flags (v3.2)

`C_GetSessionValidationFlags` (`main.cpp:1802`) returns `CKR_FUNCTION_NOT_SUPPORTED`.
New in v3.2 §5.22. Not required for PQC operations.

### 3.4 G10 — Stateful hash-based signatures (HSS/XMSS/XMSSMT)

`CKK_HSS`, `CKK_XMSS`, `CKK_XMSSMT` and their mechanisms are defined in PKCS#11 v3.2 headers
but are out of scope because OpenSSL 3.x does not natively support these algorithms.
Would require liboqs integration or a specialized provider — contradicts the OpenSSL-only
backend design of softhsmv3. Deferred pending OpenSSL native support.

### 3.5 G11 — Session-state serialization

`C_GetOperationState` and `C_SetOperationState` (`SoftHSM_sessions.cpp:125, 140`)
return `CKR_FUNCTION_NOT_SUPPORTED`. Not relevant for PQC operations.

### 3.6 G-DA-X — CKM_RIPEMD160 (WASM build constraint)

`CKM_RIPEMD160` (`0x00000240`) — defined in PKCS#11 v3.2 (marked "Historical").

**Blocker:** The OpenSSL WASM build (`scripts/build-openssl-wasm.sh`) uses `no-module` which
disables the OpenSSL legacy provider. RIPEMD-160 lives in the legacy provider and is not
accessible in the WASM build. Enabling it would require adding `enable-legacy` to the WASM
build flags and verifying size impact (~+50 KB estimated). The Digital Assets module currently
computes Bitcoin HASH160 via `@noble/hashes/ripemd160` client-side.

**Decision:** Deferred. No `no-module` removal planned until WASM size budget allows.

---

## 4. OpenSSL 3.6 Algorithm Support Reference

All in-scope algorithms are supported natively via EVP_PKEY in OpenSSL 3.3+ (3.6 for full set).

| Algorithm | Parameter sets | EVP_PKEY name pattern | Minimum OpenSSL |
| --- | --- | --- | --- |
| ML-KEM | 512, 768, 1024 | `"mlkem512"`, `"mlkem768"`, `"mlkem1024"` | 3.3 |
| ML-DSA | 44, 65, 87 | `"ml-dsa-44"`, `"ml-dsa-65"`, `"ml-dsa-87"` | 3.3 |
| SLH-DSA | 12 variants | `"slh-dsa-sha2-128s"` … `"slh-dsa-shake-256f"` | 3.5 (full in 3.6) |

Pre-hash mode: `OSSL_PARAM_utf8_string("digest", "sha256")` pattern (same for ML-DSA and SLH-DSA).
SHAKE XOF pre-hash: verified working via `"shake128"`/`"shake256"` digest names in OpenSSL 3.6.

---

## 5. Rust Engine Parity (softhsmrustv3)

> Full reference: [rust-engine.md](rust-engine.md)

The PQC Today Playground ships two parallel WASM engines. This section records which C++ gaps
are also resolved in the Rust engine and which remain Rust-only stubs.

| Mechanism / Feature | C++ (softhsmv3) | Rust (softhsmrustv3) | Notes |
| --- | --- | --- | --- |
| ML-KEM-512/768/1024 | ✅ | ✅ | Cross-check verified in `dual` mode |
| ML-DSA-44/65/87 (pure) | ✅ | ✅ | Cross-check verified in `dual` mode |
| ML-DSA pre-hash (10 variants) | ✅ | ⚠️ Partial | `ml-dsa` rc crate lacks pre-hash API |
| SLH-DSA (12 param sets, pure) | ✅ | ✅ | |
| SLH-DSA pre-hash (12 variants) | ✅ | ⚠️ Partial | `slh-dsa` rc crate pre-hash pending |
| RSA-2048/3072/4096 | ✅ | ✅ | |
| ECDSA P-256/P-384 | ✅ | ✅ | |
| Ed25519 (EdDSA) | ✅ | ✅ | |
| X25519 (ECDH key agreement) | ✅ | ✅ | `C_DeriveKey` |
| AES-GCM, AES-CBC, AES-KW, AES-CTR | ✅ | ✅ | |
| RSA-OAEP wrap / encrypt | ✅ | ✅ | |
| HMAC-SHA-256/384/512 | ✅ | ✅ | |
| SHA-256/384/512, SHA3-256/512 digest | ✅ | ✅ | |
| HKDF (G-5G3) | ✅ | ✅ | `C_DeriveKey` |
| PBKDF2 / CKM_PKCS5_PBKD2 (G-DA1) | ✅ | ✅ | `C_DeriveKey` |
| ECDSA-SHA3 variants (G-DA2) | ✅ | ✅ | Implemented via `hazmat::PrehashSigner` with manual digests |
| CKA_PUBLIC_KEY_INFO (G-PUB1) | ✅ | ✅ | Via `spki` crate |
| ECDH X9.63 KDF / CKD_SHA256_KDF (G-5G2) | ✅ | ✅ | Manually built on native `sha2` digest loop |
| SP 800-108 Counter KDF (G-PK1) | ✅ | ✅ | Implemented manually built on `hmac`/`sha2` |
| SP 800-108 Feedback KDF (G-PK2) | ✅ | ✅ | Implemented manually built on `hmac`/`sha2` |
| ECDH Cofactor Derive (G-PK4) | ✅ | ✅ | Mapped to standard DH (Cofactor=1 for NIST P-curves) |
| CKM_KMAC_128 / CKM_KMAC_256 (G-KMAC1/2) | ✅ | ✅ | `C_Sign` / `C_Verify`; variable-length output |
| Authenticated key wrap G5 (C_WrapKeyAuthenticated) | ✅ | ❌ Stub (CKR_NOT_IMPL) | |
| Streaming sign/verify G2 | ✅ | ❌ Stub (CKR_NOT_IMPL) | |
| Message encrypt/decrypt G3 | ✅ | ❌ Stub (CKR_NOT_IMPL) | |
| Pre-bound verify G4 (C_VerifySignature*) | ✅ | ❌ Stub (CKR_NOT_IMPL) | |
| GenerateRandom | ✅ | ✅ | Browser CSPRNG via `getrandom::js` |
| C_WrapKey / C_UnwrapKey (one-shot) | ✅ | ✅ | AES-KW, AES-GCM, RSA-OAEP |

**Rust engine Phase 2 (v2.33.0, 2026-03-08):** Added RSA, ECDSA, EdDSA, SLH-DSA, digest,
key wrap/unwrap — achieving full classical + PQC one-shot operation parity with the C++ engine.
Streaming, message-encrypt, and authenticated-wrap remain C++ only.

---

## 6. Playground Integration Status (pqc-timeline-app)

As of 2026-03-04 (v4):

| Feature | `softhsm.ts` | SoftHsmTab UI |
| --- | --- | --- |
| ML-KEM key gen, encap, decap | ✓ | ✓ |
| ML-DSA key gen, pure sign/verify | ✓ | ✓ |
| ML-DSA pre-hash (all 10 variants) | ✓ (expanded) | ✓ (FilterDropdown, all 10 variants) |
| SLH-DSA key gen, pure sign/verify | ✓ | ✓ |
| SLH-DSA pre-hash (all 10 variants) | ✓ (new) | ✓ (FilterDropdown, all 10 variants) |
| RSA, ECDSA, EdDSA | ✓ | ✓ |
| ECDSA-SHA3-224/256/384/512 (G-DA2) | ✓ constants | Not wired (spec completeness) |
| AES-GCM, AES-CMAC, key wrap | ✓ | ✓ |
| PBKDF2 / CKM_PKCS5_PBKD2 (G-DA1) | ✓ `hsm_pbkdf2()` helper | Not wired (low priority) |
| Streaming sign/verify (G2) | softhsmv3 ✓ | Not wired (low priority) |
| Per-message encrypt/decrypt (G3) | softhsmv3 ✓ | Not wired (low priority) |
| Pre-bound signature verify (G4) | softhsmv3 ✓ | Not wired (low priority) |
| Authenticated key wrap (G5) | softhsmv3 ✓ | Not wired (low priority) |
| AES-CTR (G-5G1) | ✓ `hsm_aesCtrEncrypt/Decrypt()` | Not wired |
| ECDH X9.63 KDF / CKD_SHA256_KDF (G-5G2) | ✓ `hsm_ecdhDerive(kdf=CKD_SHA256_KDF)` | Not wired |
| HKDF / CKM_HKDF_DERIVE (G-5G3) | ✓ `hsm_hkdf()` | Not wired |
| CKA_PUBLIC_KEY_INFO at keygen (G-PUB1) | softhsmv3 ✓ (all 6 key types) | Automatic |
| SP 800-108 Counter KDF (G-PK1) | ✓ `hsm_kbkdf()` | Not wired |
| SP 800-108 Feedback KDF (G-PK2) | ✓ `hsm_kbkdfFeedback()` | Not wired |
| ECDH1 Cofactor Derive (G-PK4) | ✓ `hsm_ecdhCofactorDerive()` | Not wired |
| KMAC-128 / KMAC-256 (G-KMAC1/2) | softhsmv3 ✓ (both engines) | Not wired (v8 addition) |

---

## §1.14 G-PK2 — CKM_SP800_108_FEEDBACK_KDF (PKCS#11 v3.2 §2.44.2)

**Status:** ✓ RESOLVED (v7)

**PKCS#11 value:** `0x000003ad`  
**OpenSSL API:** `EVP_KDF_fetch(NULL, "KBKDF", NULL)` with `OSSL_KDF_PARAM_MODE = "FEEDBACK"` + `OSSL_KDF_PARAM_SEED` for IV.

**SP 800-108 §4.2 feedback mode:** K(i) = PRF(Ki, K(i−1) ∥ [i]_r ∥ Label ∥ 0x00 ∥ Context ∥ [L]_r). K(0) = IV (seed). Differs from counter mode in that each output block depends on the previous one, providing forward secrecy within a session.

**Difference from COUNTER_KDF:** uses `CK_SP800_108_FEEDBACK_KDF_PARAMS` (28 bytes) which adds `ulIVLen` + `pIV` fields to the 20-byte `CK_SP800_108_KDF_PARAMS`. IV is passed to OpenSSL via `OSSL_KDF_PARAM_SEED`.

**Changes:**
- `src/lib/SoftHSM_keygen.cpp` — ~160 LOC handler inserted between COUNTER_KDF and HKDF blocks; mirrors COUNTER_KDF handler with `"FEEDBACK"` mode and `OSSL_KDF_PARAM_SEED`.
- `src/lib/SoftHSM_slots.cpp` — `t["CKM_SP800_108_FEEDBACK_KDF"] = CKM_SP800_108_FEEDBACK_KDF;`
- `pqc-timeline-app/src/wasm/softhsm.ts` — `hsm_kbkdfFeedback()` helper (~80 LOC); builds 28-byte `CK_SP800_108_FEEDBACK_KDF_PARAMS` with optional IV.
- `HsmPqc/data/hsmConstants.ts` — `ckm-sp800-108-feedback-kdf` entry added.

---

## §1.15 G-PK4 — CKM_ECDH1_COFACTOR_DERIVE (PKCS#11 v3.2 §2.3.2)

**Status:** ✓ RESOLVED (v7)

**PKCS#11 value:** `0x00001051`  
**OpenSSL API:** `EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1)` called between `EVP_PKEY_derive_init()` and `EVP_PKEY_derive_set_peer()`.

**What cofactor ECDH adds:** multiplies the ECDH shared secret by the curve's cofactor h. For prime-order curves (NIST P-256/384/521, cofactor = 1) the result is identical to `CKM_ECDH1_DERIVE`. For non-prime-order curves (e.g. certain Brainpool variants, cofactor > 1) it eliminates small-subgroup key-recovery attacks per [NIST SP 800-56A §5.7.1.2].

**Changes:**
- `src/lib/crypto/OSSLECDH.h` — added `deriveKeyWithCofactor()` declaration.
- `src/lib/crypto/OSSLECDH.cpp` — added 75 LOC `deriveKeyWithCofactor()` implementation (copy of `deriveKey()` with `EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, 1)` inserted after `EVP_PKEY_derive_init()`).
- `src/lib/SoftHSM_keygen.cpp` — added `#include "OSSLECDH.h"`; extended `C_DeriveKey` ECDH dispatch to also accept `CKM_ECDH1_COFACTOR_DERIVE`; modified `deriveECDH()` to call `((OSSLECDH*)ecdh)->deriveKeyWithCofactor()` when mechanism is cofactor.
- `src/lib/SoftHSM_slots.cpp` — `t["CKM_ECDH1_COFACTOR_DERIVE"] = CKM_ECDH1_COFACTOR_DERIVE;`
- `pqc-timeline-app/src/wasm/softhsm.ts` — `CKM_ECDH1_COFACTOR_DERIVE = 0x1051` constant; `hsm_ecdhCofactorDerive()` helper.
- `HsmPqc/data/hsmConstants.ts` — `ckm-ecdh1-cofactor-derive` entry added.

---

## §1.16 Bugfix — C_DeriveKey validation switch (v7)

**Discovery:** `CKM_HKDF_DERIVE` (added in G-5G3) and `CKM_SP800_108_COUNTER_KDF` (added in G-PK1) were never reachable in `C_DeriveKey()`. The validation switch at `SoftHSM_keygen.cpp:1944` uses a `#ifndef WITH_FIPS` preprocessor guard (opened at line 154) that only listed `CKM_ECDH1_DERIVE` before `#endif`. Any unlisted mechanism returned `CKR_MECHANISM_INVALID` before reaching the handler blocks at lines 2211+ (COUNTER_KDF) and 2440+ (HKDF).

**Fix:** Added the following cases to the validation switch (after the `#endif` so they're available in all build modes):

```cpp
case CKM_HKDF_DERIVE:
case CKM_SP800_108_COUNTER_KDF:
case CKM_SP800_108_FEEDBACK_KDF:
    break;
```

Also added `case CKM_ECDH1_COFACTOR_DERIVE:` before the `#endif` (alongside `CKM_ECDH1_DERIVE`, guarded by `#ifndef WITH_FIPS`).

---

## §1.17 G-KMAC1/KMAC2 — CKM_KMAC_128 / CKM_KMAC_256 (vendor-defined MACs) ✓ RESOLVED (v8)

**Status:** ✓ RESOLVED (v8)

**PKCS#11 values:** `CKM_VENDOR_DEFINED | 0x100` (`0x80000100`) and `CKM_VENDOR_DEFINED | 0x101` (`0x80000101`)
Note: KMAC is not yet assigned a standard CKM value in PKCS#11 v3.2 CSD01; vendor-defined range used pending standardisation.

**OpenSSL API:** `EVP_MAC_fetch(NULL, "KMAC-128", NULL)` / `EVP_MAC_fetch(NULL, "KMAC-256", NULL)` with `OSSL_MAC_PARAM_SIZE` for output length. Available in OpenSSL 3.x.

**What KMAC adds:** KMAC (Keccak Message Authentication Code, NIST SP 800-185 §4) is a MAC built on SHAKE — a SHA-3 family primitive. Unlike HMAC it inherently resists length-extension attacks and supports variable-length output. KMAC-128 provides 128-bit security; KMAC-256 provides 256-bit security.

**Changes:**

- `src/lib/crypto/OSSLKMAC.h` / `OSSLKMAC.cpp` — new MAC implementation (~165 LOC); wraps `EVP_MAC` with key material as `CKA_VALUE`, optional customisation string, variable output length.
- `src/lib/crypto/OSSLCryptoFactory.cpp` — `getMacAlgorithm()` dispatches `KMAC_128` / `KMAC_256`.
- `src/lib/SoftHSM_slots.cpp` — registered under `CKM_KMAC_128` / `CKM_KMAC_256` with `CKF_SIGN | CKF_VERIFY`; `C_GetMechanismInfo` entries added (16–∞ and 32–∞ byte key range).
- `src/lib/SoftHSM_sign.cpp` — dispatch cases added to `C_SignInit` / `C_VerifyInit`.
- `rust/src/ffi.rs` — `C_GetMechanismInfo` arm `CKM_KMAC_128 | CKM_KMAC_256` with `(16, 64, CKF_SIGN | CKF_VERIFY)`. `C_Sign` / `C_Verify` dispatch to `sign_kmac()`.
- `rust/src/lib.rs` — `sign_kmac()` using `kmac` crate (`sha3` dependency added to `Cargo.toml`).
- `rust/src/constants.rs` / `SUPPORTED_MECHS` — `CKM_KMAC_128` and `CKM_KMAC_256` added.
- `src/lib/pkcs11/pkcs11t.h` — `#define CKM_KMAC_128` and `CKM_KMAC_256` added in vendor block.

---

## §1.18 Bugfix — C_GetMechanismInfo full coverage (v8)

**Discovery:** `SUPPORTED_MECHS` (used by `C_GetMechanismList`) listed 30 mechanism types whose `C_GetMechanismInfo` entries fell through the match/switch to `CKR_MECHANISM_INVALID`. This contradiction was visible in the playground log during mechanism discovery. Affected mechanisms:

- Rust engine: `CKM_AES_CTR`, all 10 `CKM_HASH_ML_DSA_*` variants, all 10 `CKM_HASH_SLH_DSA_*` variants, 4 `CKM_ECDSA_SHA3_*` variants, `CKM_ECDH1_COFACTOR_DERIVE`, `CKM_PKCS5_PBKD2`, `CKM_HKDF_DERIVE`, `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`
- C++ engine: `CKM_ECDSA_SHA3_{224,256,384,512}`, `CKM_ECDH1_COFACTOR_DERIVE`

**Fix:**

- `rust/src/ffi.rs` — added match arms for each affected mechanism group with appropriate `(minKey, maxKey, flags)` tuples.
- `src/lib/SoftHSM_slots.cpp` — folded ECDSA-SHA3 variants into the existing `CKM_ECDSA` / `CKM_ECDSA_SHA*` block; folded `CKM_ECDH1_COFACTOR_DERIVE` into the existing `CKM_ECDH1_DERIVE` block.

---

## §1.19 G-SLHDSA1 — SLH-DSA Context String (FIPS 205 §9.2) ✓ RESOLVED (v9)

**Gap:** `CKM_SLH_DSA` (pure mode) rejected any mechanism parameter with `CKR_MECHANISM_PARAM_INVALID`. FIPS 205 §9.2 allows an optional 0–255 byte context string that must be bound to the signature; omitting it is equivalent to a zero-length context. The Rust engine hardcoded `&[]` (no context) in all sign/verify paths.

**PKCS#11 v3.2 interface:** `CK_SIGN_ADDITIONAL_CONTEXT` struct (12 bytes WASM32): `hedgeVariant(4) + pContext(4) + ulContextLen(4)`. Passed as `pParameter` in `CK_MECHANISM` for `CKM_SLH_DSA`.

| Component | File | Change |
| --- | --- | --- |
| `SLHDSA_SIGN_PARAMS` | `src/lib/crypto/AsymmetricAlgorithm.h:175` | Added `bool deterministic` field |
| `CKM_SLH_DSA` sign init | `src/lib/SoftHSM_sign.cpp:897` | Replaced rejection with optional `parseSLHDSASignContext` call |
| `CKM_SLH_DSA` verify init | `src/lib/SoftHSM_sign.cpp:2050` | Same fix |
| `OSSLSLHDSA::sign()` | `src/lib/crypto/OSSLSLHDSA.cpp:321` | `EVP_DigestSignInit(ctx, &pkeyCtx, …)` + `EVP_PKEY_CTX_set_params` for context |
| `OSSLSLHDSA::verify()` | `src/lib/crypto/OSSLSLHDSA.cpp:407` | Same for verify (context only) |
| Rust `SIGN_STATE` | `rust/src/state.rs:12` | Tuple expanded to `(u32, u32, Vec<u8>, bool)` |
| Rust `parse_slh_dsa_ctx` | `rust/src/ffi.rs` | New helper: parses `CK_SIGN_ADDITIONAL_CONTEXT` from WASM32 pointer |
| Rust `_C_SignInit` | `rust/src/ffi.rs:1264` | Calls `parse_slh_dsa_ctx` for `CKM_SLH_DSA`, stores 4-tuple |
| Rust `_C_VerifyInit` | `rust/src/ffi.rs:1387` | Mirror of SignInit |
| `slh_dsa_sign!` macro | `rust/src/crypto/handlers.rs:150` | Added `ctx` + `deterministic` params |
| `slh_dsa_verify!` macro | `rust/src/crypto/handlers.rs:162` | Added `ctx` param |
| `sign_slh_dsa` | `rust/src/crypto/handlers.rs:436` | Signature extended with `ctx: &[u8], deterministic: bool` |
| `verify_slh_dsa` | `rust/src/crypto/handlers.rs:692` | Signature extended with `ctx: &[u8]` |
| TypeScript `SLHDSASignOptions` | `src/wasm/softhsm.ts:1298` | Added `context?: Uint8Array` |
| `buildSlhDsaSignContext` | `src/wasm/softhsm.ts:1357` | New helper allocates `CK_SIGN_ADDITIONAL_CONTEXT` |
| `hsm_slhdsaSign` | `src/wasm/softhsm.ts` | Passes context params when `!preHash && context` |
| `hsm_slhdsaVerify` | `src/wasm/softhsm.ts` | Passes context params when `!preHash && context` |
| Playground UI | `SignVerifyTab.tsx:HsmSlhDsaSignPanel` | Context text input (hidden in pre-hash mode) |

---

## §1.20 G-SLHDSA2 — SLH-DSA Deterministic Signing (FIPS 205 §10) ✓ RESOLVED (v9)

**Gap:** FIPS 205 §10 defines a deterministic signing mode where `opt_rand = PK.seed` instead of a random value. `SLHDSA_SIGN_PARAMS` had no `deterministic` field; `parseSLHDSASignContext` ignored `hedgeVariant`; `OSSLSLHDSA::sign()` passed `NULL` for `pkeyCtx` (no way to set params); Rust hardcoded `None` entropy.

**PKCS#11 v3.2 interface:** `CKH_DETERMINISTIC_REQUIRED = 0x00000002` in `hedgeVariant` field of `CK_SIGN_ADDITIONAL_CONTEXT`. Verification is unaffected (no determinism parameter for verify).

| Component | File | Change |
| --- | --- | --- |
| `SLHDSA_SIGN_PARAMS` | `AsymmetricAlgorithm.h:175` | `bool deterministic` field (shared with G-SLHDSA1 fix) |
| `parseSLHDSASignContext` | `SoftHSM_sign.cpp:~379` | `out.deterministic = (ctx->hedgeVariant == CKH_DETERMINISTIC_REQUIRED)` |
| `OSSLSLHDSA::sign()` | `OSSLSLHDSA.cpp:321` | `OSSL_SIGNATURE_PARAM_DETERMINISTIC` set via `EVP_PKEY_CTX_set_params` |
| `CKH_DETERMINISTIC_REQUIRED` | `rust/src/constants.rs:99` | `pub const CKH_DETERMINISTIC_REQUIRED: u32 = 0x0000_0002` |
| Rust `_C_SignInit` | `rust/src/ffi.rs:1264` | Stores `deterministic` bool extracted from `hedgeVariant` |
| `slh_dsa_sign!` macro | `rust/src/crypto/handlers.rs:150` | `entropy = if deterministic { Some(&sk_bytes[2n..3n]) } else { None }` |
| TypeScript `SLHDSASignOptions` | `src/wasm/softhsm.ts:1298` | Added `deterministic?: boolean` |
| `buildSlhDsaSignContext` | `src/wasm/softhsm.ts:1357` | Sets `CKH_DETERMINISTIC_REQUIRED` when `deterministic=true` |
| Playground UI | `SignVerifyTab.tsx:HsmSlhDsaSignPanel` | Deterministic checkbox (hidden in pre-hash mode) |

**Rust deterministic mechanism (FIPS 205 §10):** SK layout = `SK.seed(n) ‖ SK.prf(n) ‖ PK.seed(n) ‖ PK.root(n)` where `n = sk.len()/4`. Deterministic mode passes `Some(&sk_bytes[2n..3n])` as `opt_rand` to `try_sign_with_context`, which uses PK.seed instead of random bytes.

**Unit tests added** (`rust/tests/pqc_api_test.rs`):
- `test_slh_dsa_sign_verify_with_context` — sign+verify with context, wrong context fails
- `test_slh_dsa_deterministic_produces_same_signature` — same message twice → identical sigs
- `test_slh_dsa_context_cross_verify_fails_on_mismatch` — sign with "sign-ctx", verify with "verify-ctx" → `CKR_SIGNATURE_INVALID`

**Bugfix (v9.1):** `C_SignMessage` and `C_VerifyMessage` were silently discarding context and deterministic flag on every call. Root cause: `AsymSign`/`AsymVerify` call `Session::resetOp()` which frees `param`. Since `C_SignMessage` is invoked twice per message in the two-pass pattern (size query + real sign), the params stored by `C_MessageSignInit` were wiped after the size query, so the actual sign ran with no context. Fix: snapshot `session->param` before `AsymSign`/`AsymVerify` and restore on success. Confirmed in browser ACVP tests 21 and 22 (context binding + deterministic).
