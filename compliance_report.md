# PKCS#11 v3.2 Compliance Report

**Engine:** `./build_fresh/src/lib/libsofthsmv3.dylib`
**Timestamp:** Generated automatically

## Summary
- **Total PASS:** 35
- **Total FAIL:** 0
- **Total SKIP:** 0

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

### ECDSA

| Test | Status | Details |
|---|---|---|
| Generate_P256 | ✅ PASS | RV=0 |
| Sign_P256 | ✅ PASS | RV=0 |
| Generate_P521 | ✅ PASS | RV=0 |
| Sign_P521 | ✅ PASS | RV=0 |
| Generate_secp256k1 | ✅ PASS | RV=0 |
| Sign_secp256k1 | ✅ PASS | RV=0 |
| Generate_P256_SHA3_256 | ✅ PASS | RV=0 |
| Sign_P256_SHA3_256 | ✅ PASS | RV=0 |
| Generate_P521_SHA3_512 | ✅ PASS | RV=0 |
| Sign_P521_SHA3_512 | ✅ PASS | RV=0 |

### Init

| Test | Status | Details |
|---|---|---|
| TokenSetup | ✅ PASS | Initialized token and session |

### MultiPart_ECDSA

| Test | Status | Details |
|---|---|---|
| Setup_KeyGen | ✅ PASS | P-256 key pair generated |
| C_SignInit | ✅ PASS | CKM_ECDSA_SHA256 — RV=0 |
| C_SignUpdate_chunk1 | ✅ PASS | RV=0 |
| C_SignUpdate_chunk2 | ✅ PASS | RV=0 |
| C_SignFinal | ✅ PASS | SigLen=64 RV=0 |
| C_VerifyInit | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk1 | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk2 | ✅ PASS | RV=0 |
| C_VerifyFinal | ✅ PASS | PKCS#11 v3.2 §5.2 P-256 round-trip — RV=0 |
| C_Verify_oneshot_xcheck | ✅ PASS | Multi-part sig matches one-shot verify — RV=0 |

### MultiPart_EdDSA

| Test | Status | Details |
|---|---|---|
| Setup_KeyGen | ✅ PASS | Ed25519 key pair generated |
| C_SignInit | ✅ PASS | CKM_EDDSA — RV=0 |
| C_SignUpdate_chunk1 | ✅ PASS | RV=0 |
| C_SignUpdate_chunk2 | ✅ PASS | RV=0 |
| C_SignFinal | ✅ PASS | SigLen=64 RV=0 |
| C_VerifyInit | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk1 | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk2 | ✅ PASS | RV=0 |
| C_VerifyFinal | ✅ PASS | PKCS#11 v3.2 §5.2 Ed25519 round-trip — RV=0 |
| C_Verify_oneshot_xcheck | ✅ PASS | Multi-part sig matches one-shot verify — RV=0 |

