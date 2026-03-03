# softhsmv3 Developer Guide

> **Scope**: softhsmv3-specific behaviour, supported algorithms, build instructions, and C++ client patterns. This document does not repeat PKCS#11 v3.2 semantics available in the OASIS specification.

---

## 1. What softhsmv3 Is

softhsmv3 is a fork of SoftHSMv2 (v2.7.0 base) that adds:

- **OpenSSL 3.x EVP-only backend** — `ENGINE`/`CONF_MODULE` removed; every crypto operation goes through the modern `EVP_*` API. No Botan support.
- **PKCS#11 v3.2 compliance** — headers, function table, and mechanism constants tracking the OASIS v3.2 draft; FIPS 203/204/205 algorithm support.
- **Emscripten WASM target** — single-threaded build for in-browser use via the `@pqctoday/softhsm-wasm` npm package (Phase 5).
- **ML-DSA, ML-KEM, SLH-DSA** — post-quantum algorithms implemented using OpenSSL 3.3+ built-in EVP providers.

**What it is not**: it is not a hardware HSM, does not protect keys in hardware, and is not FIPS-validated. Keys reside in the process's address space. It is intended for PQC integration testing and browser-based demonstrations.

---

## 2. Algorithm and Mechanism Coverage

### 2.1 Key Types

| CKK constant        | Value  | Algorithm                 | Keygen mechanism            |
|---------------------|--------|---------------------------|-----------------------------|
| `CKK_RSA`           | 0x00   | RSA                       | `CKM_RSA_PKCS_KEY_PAIR_GEN` |
| `CKK_EC`            | 0x03   | ECDSA / ECDH (NIST curves)| `CKM_EC_KEY_PAIR_GEN`       |
| `CKK_EC_EDWARDS`    | 0x40   | EdDSA (Ed25519, Ed448)    | `CKM_EC_EDWARDS_KEY_PAIR_GEN` |
| `CKK_EC_MONTGOMERY` | 0x41   | ECDH (X25519, X448)       | `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` |
| `CKK_AES`           | 0x1f   | AES                       | `CKM_AES_KEY_GEN`           |
| `CKK_GENERIC_SECRET`| 0x10   | Raw secret                | `CKM_GENERIC_SECRET_KEY_GEN`|
| `CKK_ML_DSA`        | 0x4a   | ML-DSA (FIPS 204)         | `CKM_ML_DSA_KEY_PAIR_GEN`   |
| `CKK_SLH_DSA`       | 0x4b   | SLH-DSA (FIPS 205)        | `CKM_SLH_DSA_KEY_PAIR_GEN`  |
| `CKK_ML_KEM`        | 0x49   | ML-KEM (FIPS 203)         | `CKM_ML_KEM_KEY_PAIR_GEN`   |

### 2.2 Sign / Verify Mechanisms

| Mechanism                        | Algorithm     | Notes                                        |
|----------------------------------|---------------|----------------------------------------------|
| `CKM_ML_DSA`                     | ML-DSA        | Pure-message, no pre-hash (FIPS 204 §5.2)    |
| `CKM_HASH_ML_DSA`                | ML-DSA        | Pre-hash; hash algorithm in `CK_HASH_SIGN_ADDITIONAL_CONTEXT` |
| `CKM_HASH_ML_DSA_SHA224` … `SHA512` | ML-DSA     | Pre-hash; hash fixed by mechanism             |
| `CKM_HASH_ML_DSA_SHA3_224` … `SHA3_512` | ML-DSA | Pre-hash; SHA-3 family                       |
| `CKM_HASH_ML_DSA_SHAKE128` / `SHAKE256` | ML-DSA | Pre-hash; SHAKE extendable output           |
| `CKM_SLH_DSA`                    | SLH-DSA       | Pure-message, no pre-hash (FIPS 205 §10.2)   |
| `CKM_HASH_SLH_DSA`               | SLH-DSA       | Pre-hash; hash algorithm in parameter        |
| `CKM_HASH_SLH_DSA_SHA224` … `SHA512` | SLH-DSA   | Pre-hash; hash fixed by mechanism             |
| `CKM_HASH_SLH_DSA_SHA3_224` … `SHA3_512` | SLH-DSA | Pre-hash; SHA-3 family                     |
| `CKM_HASH_SLH_DSA_SHAKE128` / `SHAKE256` | SLH-DSA | Pre-hash; SHAKE                           |
| `CKM_ECDSA` + SHA variants       | ECDSA         | Standard PKCS#11 semantics                   |
| `CKM_EDDSA`                      | EdDSA         | Ed25519 / Ed448                              |
| `CKM_SHA*_RSA_PKCS` + PSS        | RSA           | Standard PKCS#11 semantics                   |

**One-shot only**: ML-DSA and SLH-DSA set `bAllowMultiPartOp = false`. `C_SignUpdate` / `C_SignFinal` return `CKR_OPERATION_NOT_INITIALIZED` for these algorithms. Use `C_Sign` or the message-based API (`C_SignMessage` / `C_SignMessageNext`).

### 2.3 KEM Mechanisms

| Mechanism              | Algorithm | API                                         |
|------------------------|-----------|---------------------------------------------|
| `CKM_ML_KEM`           | ML-KEM    | `C_EncapsulateKey` / `C_DecapsulateKey`     |

ML-KEM parameter sizes (raw bytes, not DER-encoded):

| Variant      | Public key | Private key | Ciphertext | Shared secret |
|--------------|-----------|-------------|------------|---------------|
| ML-KEM-512   | 800        | 1632        | 768        | 32            |
| ML-KEM-768   | 1184       | 2400        | 1088       | 32            |
| ML-KEM-1024  | 1568       | 3168        | 1568       | 32            |

### 2.4 Symmetric / Digest Mechanisms

AES (ECB, CBC, CBC-PAD, CTR, GCM, CMAC, key-wrap), SHA-1/224/256/384/512, SHA3-224/256/384/512, HMAC variants, and ECDH derivation are supported with standard PKCS#11 semantics.

---

## 3. PKCS#11 v3.2 Function Table Coverage

The table below lists functions that have changed status relative to SoftHSMv2:

| Function                   | Status         | Notes                                                      |
|----------------------------|----------------|------------------------------------------------------------|
| `C_EncapsulateKey`         | **Implemented**| ML-KEM encapsulation                                       |
| `C_DecapsulateKey`         | **Implemented**| ML-KEM decapsulation                                       |
| `C_MessageSignInit`        | **Implemented**| Enters multi-message sign session                          |
| `C_SignMessage`            | **Implemented**| One-shot message sign (ML-DSA, SLH-DSA, ECDSA)            |
| `C_SignMessageBegin`       | **Implemented**| Commits per-message params; → MESSAGE_SIGN_BEGIN state     |
| `C_SignMessageNext`        | **Implemented**| Signs (or size-queries) one message                        |
| `C_MessageSignFinal`       | **Implemented**| Ends multi-message sign session                            |
| `C_MessageVerifyInit`      | **Implemented**| Enters multi-message verify session                        |
| `C_VerifyMessage`          | **Implemented**| One-shot message verify                                    |
| `C_VerifyMessageBegin`     | **Implemented**| Commits per-message params; → MESSAGE_VERIFY_BEGIN state   |
| `C_VerifyMessageNext`      | **Implemented**| Verifies one message                                       |
| `C_MessageVerifyFinal`     | **Implemented**| Ends multi-message verify session                          |
| `C_MessageEncryptInit`     | Stub → `CKR_FUNCTION_NOT_SUPPORTED` | Planned G3                  |
| `C_EncryptMessage`         | Stub           | Planned G3                                                 |
| `C_MessageDecryptInit`     | Stub           | Planned G3                                                 |
| `C_DecryptMessage`         | Stub           | Planned G3                                                 |
| `C_VerifySignatureInit`    | Stub           | Planned G4                                                 |
| `C_VerifySignature`        | Stub           | Planned G4                                                 |
| `C_WrapKeyAuthenticated`   | Stub           | Planned G5                                                 |
| `C_UnwrapKeyAuthenticated` | Stub           | Planned G5                                                 |
| `C_LoginUser`              | Stub           | Planned G6                                                 |
| `C_SessionCancel`          | Stub           | Planned G6                                                 |
| `C_SignRecover` / `C_VerifyRecover` | `CKR_FUNCTION_NOT_SUPPORTED` | Not planned        |
| `C_DigestKey`              | `CKR_FUNCTION_NOT_SUPPORTED` | Not planned                      |

---

## 4. Known Limitations

### Algorithm gaps
- **Stateful hash-based signatures** (LMS/HSS, XMSS/XMSS-MT) are not implemented and not planned. These require persistent state management beyond the current object store model.
- **BIKE, HQC, FrodoKEM, Classic McEliece** — not in OpenSSL; not implemented.
- **Falcon** — available in liboqs but not wired into the PKCS#11 layer.
- **CRYSTALS-Kyber (round 3)** — deprecated in favour of ML-KEM; not implemented.

### Signing constraints
- ML-DSA and SLH-DSA are **one-shot only**. `C_SignUpdate` / `C_SignFinal` are not available for these algorithms.
- The ML-DSA hedging variant (`CKH_HEDGE_PREFERRED` / `CKH_HEDGE_REQUIRED`) is forwarded to OpenSSL via `OSSL_SIGNATURE_PARAM_NONCE_TYPE` but OpenSSL's actual hedging behaviour depends on the provider and version.

### WASM build
- Single-threaded; no `SharedArrayBuffer` or worker thread support.
- Token state is in-process memory; no persistence across page reloads.
- Object store uses the in-memory file backend only.

### Object store
- File backend: token data written to `DEFAULT_TOKENDIR` (default: `/var/lib/softhsm/tokens/`). Requires write access.
- SQLite3 backend is optional (`-DWITH_OBJECTSTORE_BACKEND_DB=ON`) and requires `libsqlite3-dev`.

### OpenSSL version
- Minimum: OpenSSL **3.3**. ML-DSA and SLH-DSA EVP providers were added in OpenSSL 3.3. ML-KEM requires 3.3+.
- Recommended: OpenSSL **3.5** or later for the most complete FIPS 203/204/205 provider coverage.

---

## 5. Building

### Prerequisites

```bash
# macOS (Homebrew)
brew install cmake openssl@3 pkg-config

# Ubuntu / Debian
apt-get install cmake libssl-dev pkg-config

# Verify OpenSSL >= 3.3
openssl version   # must print 3.3.x or later
```

### Configure and build

```bash
git clone https://github.com/pqctoday/softhsmv3.git
cd softhsmv3
mkdir build && cd build

cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_STATIC=ON            # builds both .so/.dylib and .a

cmake --build . -j$(nproc)
```

Output artifacts:
- `src/lib/libsofthsmv3.dylib` (macOS) / `libsofthsmv3.so` (Linux)
- `src/lib/libsofthsmv3-static.a`
- `src/bin/softhsm2-util` — token management CLI

### Useful cmake flags

| Flag                             | Default | Effect                                      |
|----------------------------------|---------|---------------------------------------------|
| `ENABLE_STATIC`                  | ON      | Build static `.a` alongside shared library  |
| `WITH_OBJECTSTORE_BACKEND_DB`    | OFF     | Enable SQLite3 object store                 |
| `ENABLE_PEDANTIC`                | OFF     | `-pedantic` warning flag                    |
| `DISABLE_NON_PAGED_MEMORY`       | OFF     | Disable `mlock`; useful in containers       |

### Token initialisation (native builds only)

```bash
# Create a token slot
./src/bin/softhsm2-util --init-token --slot 0 --label "TestToken" \
  --so-pin 1234 --pin 1234

# List slots
./src/bin/softhsm2-util --show-slots
```

---

## 6. Writing a C++ Client

### 6.1 Loading the library

softhsmv3 exposes a standard PKCS#11 function list. Load it at runtime with `dlopen`:

```cpp
#include <dlfcn.h>
#include "pkcs11.h"   // PKCS#11 v3.2 header (from src/lib/pkcs11/)

// Signature of the single entry-point every PKCS#11 library must export
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);

void* lib = dlopen("./libsofthsmv3.dylib", RTLD_NOW | RTLD_LOCAL);
if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }

auto getFuncList = (CK_C_GetFunctionList)dlsym(lib, "C_GetFunctionList");

CK_FUNCTION_LIST* fn = nullptr;
CK_RV rv = getFuncList(&fn);
// rv must be CKR_OK; fn is now your function table pointer
```

All subsequent calls go through `fn->C_*`. Never call C functions directly by name — the function table is the only ABI-stable interface.

### 6.2 Session lifecycle

```cpp
// Initialise the library
fn->C_Initialize(nullptr);

// Open a read-write session on slot 0
CK_SESSION_HANDLE session;
fn->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session);

// Log in (USER role; PIN configured at token init time)
const char* pin = "1234";
fn->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin));

// ... perform operations ...

fn->C_Logout(session);
fn->C_CloseSession(session);
fn->C_Finalize(nullptr);
dlclose(lib);
```

### 6.3 ML-DSA: key generation and sign / verify

**Key generation**: pass a `CKM_ML_DSA_KEY_PAIR_GEN` mechanism and a template that specifies `CKA_ML_DSA_PARAMETER_SET` to select the security level.

```cpp
// Security levels: "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
const char* paramSet   = "ML-DSA-65";
CK_BBOOL    ckTrue     = CK_TRUE;
CK_BBOOL    ckFalse    = CK_FALSE;
CK_KEY_TYPE keyType    = CKK_ML_DSA;
CK_OBJECT_CLASS pubClass  = CKO_PUBLIC_KEY;
CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;

CK_ATTRIBUTE pubTmpl[] = {
    { CKA_CLASS,                   &pubClass,  sizeof(pubClass)  },
    { CKA_KEY_TYPE,                &keyType,   sizeof(keyType)   },
    { CKA_TOKEN,                   &ckFalse,   sizeof(ckFalse)   }, // session key
    { CKA_VERIFY,                  &ckTrue,    sizeof(ckTrue)    },
    { CKA_ML_DSA_PARAMETER_SET,    (void*)paramSet, strlen(paramSet) },
};
CK_ATTRIBUTE privTmpl[] = {
    { CKA_CLASS,    &privClass, sizeof(privClass) },
    { CKA_KEY_TYPE, &keyType,   sizeof(keyType)   },
    { CKA_TOKEN,    &ckFalse,   sizeof(ckFalse)   },
    { CKA_SIGN,     &ckTrue,    sizeof(ckTrue)    },
    { CKA_SENSITIVE,&ckTrue,    sizeof(ckTrue)    },
};

CK_MECHANISM mldsa_keygen = { CKM_ML_DSA_KEY_PAIR_GEN, nullptr, 0 };
CK_OBJECT_HANDLE hPub, hPriv;
fn->C_GenerateKeyPair(session, &mldsa_keygen,
    pubTmpl,  sizeof(pubTmpl)  / sizeof(CK_ATTRIBUTE),
    privTmpl, sizeof(privTmpl) / sizeof(CK_ATTRIBUTE),
    &hPub, &hPriv);
```

**One-shot sign** (`C_SignInit` / `C_Sign`):

```cpp
// Pure-message ML-DSA sign (no pre-hash, no context)
CK_MECHANISM mldsa_sign = { CKM_ML_DSA, nullptr, 0 };
fn->C_SignInit(session, &mldsa_sign, hPriv);

const uint8_t msg[]  = "hello pqc";
uint8_t  sig[3309];   // ML-DSA-65 signature length
CK_ULONG sigLen = sizeof(sig);
fn->C_Sign(session, (CK_BYTE_PTR)msg, sizeof(msg) - 1, sig, &sigLen);

// Verify
fn->C_VerifyInit(session, &mldsa_sign, hPub);
CK_RV result = fn->C_Verify(session,
    (CK_BYTE_PTR)msg, sizeof(msg) - 1,
    sig, sigLen);
// result == CKR_OK → valid signature
```

**Per-message context with the message API** (`C_MessageSignInit` / `C_SignMessage`):

```cpp
// Initialise a multi-message sign session
CK_MECHANISM mldsa_msign = { CKM_ML_DSA, nullptr, 0 };
fn->C_MessageSignInit(session, &mldsa_msign, hPriv);

// Sign message 1 with a context string
const char ctx1[] = "domain:payment";
CK_SIGN_ADDITIONAL_CONTEXT param1 = {
    CKH_HEDGE_PREFERRED,          // hedgeVariant
    (CK_BYTE_PTR)ctx1,            // pContext
    (CK_ULONG)strlen(ctx1)        // ulContextLen
};
const uint8_t msg1[] = "transfer $100";
uint8_t  sig1[3309];
CK_ULONG sig1Len = sizeof(sig1);
// Size query first (sig==NULL)
fn->C_SignMessage(session, &param1, sizeof(param1),
    (CK_BYTE_PTR)msg1, sizeof(msg1) - 1, nullptr, &sig1Len);
// Actual sign
fn->C_SignMessage(session, &param1, sizeof(param1),
    (CK_BYTE_PTR)msg1, sizeof(msg1) - 1, sig1, &sig1Len);

// Sign message 2 with a different context
const char ctx2[] = "domain:audit";
CK_SIGN_ADDITIONAL_CONTEXT param2 = { CKH_HEDGE_PREFERRED, (CK_BYTE_PTR)ctx2, strlen(ctx2) };
// ... same pattern for msg2 ...

fn->C_MessageSignFinal(session);
```

**Streaming two-step sign** (`C_SignMessageBegin` / `C_SignMessageNext`):

```cpp
fn->C_MessageSignInit(session, &mldsa_msign, hPriv);

// Commit per-message context
CK_SIGN_ADDITIONAL_CONTEXT param = { CKH_HEDGE_PREFERRED, (CK_BYTE_PTR)"ctx", 3 };
fn->C_SignMessageBegin(session, &param, sizeof(param));

// Size query (pSignature == nullptr)
CK_ULONG sigLen = 0;
fn->C_SignMessageNext(session, nullptr, 0,
    (CK_BYTE_PTR)msg1, sizeof(msg1) - 1, nullptr, &sigLen);

// Actual sign (pSignature != nullptr → returns to MESSAGE_SIGN state)
std::vector<uint8_t> sig(sigLen);
fn->C_SignMessageNext(session, nullptr, 0,
    (CK_BYTE_PTR)msg1, sizeof(msg1) - 1, sig.data(), &sigLen);

fn->C_MessageSignFinal(session);
```

### 6.4 ML-KEM: key encapsulation and decapsulation

ML-KEM uses `C_EncapsulateKey` and `C_DecapsulateKey` rather than sign/verify.

```cpp
// Key type: "ML-KEM-768"
const char* kemParam   = "ML-KEM-768";
CK_KEY_TYPE kemType    = CKK_ML_KEM;
CK_OBJECT_CLASS kemPub = CKO_PUBLIC_KEY;
CK_OBJECT_CLASS kemPri = CKO_PRIVATE_KEY;

CK_ATTRIBUTE kemPubTmpl[] = {
    { CKA_CLASS,               &kemPub,  sizeof(kemPub)  },
    { CKA_KEY_TYPE,            &kemType, sizeof(kemType) },
    { CKA_TOKEN,               &ckFalse, sizeof(ckFalse) },
    { CKA_ENCRYPT,             &ckTrue,  sizeof(ckTrue)  },
    { CKA_ML_KEM_PARAMETER_SET,(void*)kemParam, strlen(kemParam) },
};
CK_ATTRIBUTE kemPrivTmpl[] = {
    { CKA_CLASS,    &kemPri,  sizeof(kemPri)  },
    { CKA_KEY_TYPE, &kemType, sizeof(kemType) },
    { CKA_TOKEN,    &ckFalse, sizeof(ckFalse) },
    { CKA_DECRYPT,  &ckTrue,  sizeof(ckTrue)  },
    { CKA_SENSITIVE,&ckTrue,  sizeof(ckTrue)  },
};

CK_MECHANISM mlkem_gen = { CKM_ML_KEM_KEY_PAIR_GEN, nullptr, 0 };
CK_OBJECT_HANDLE hKemPub, hKemPriv;
fn->C_GenerateKeyPair(session, &mlkem_gen,
    kemPubTmpl,  sizeof(kemPubTmpl)  / sizeof(CK_ATTRIBUTE),
    kemPrivTmpl, sizeof(kemPrivTmpl) / sizeof(CK_ATTRIBUTE),
    &hKemPub, &hKemPriv);

// Encapsulate — produces ciphertext + shared secret handle
CK_MECHANISM mlkem_mech = { CKM_ML_KEM, nullptr, 0 };

// Template for the derived shared-secret key object
CK_KEY_TYPE   ssType    = CKK_GENERIC_SECRET;
CK_OBJECT_CLASS ssClass = CKO_SECRET_KEY;
CK_ULONG      ssLen     = 32; // ML-KEM shared secret is always 32 bytes
CK_ATTRIBUTE  ssTmpl[]  = {
    { CKA_CLASS,     &ssClass, sizeof(ssClass) },
    { CKA_KEY_TYPE,  &ssType,  sizeof(ssType)  },
    { CKA_VALUE_LEN, &ssLen,   sizeof(ssLen)   },
    { CKA_TOKEN,     &ckFalse, sizeof(ckFalse) },
    { CKA_DERIVE,    &ckTrue,  sizeof(ckTrue)  },
};

uint8_t  ciphertext[1088]; // ML-KEM-768 ciphertext size
CK_ULONG ctLen = sizeof(ciphertext);
CK_OBJECT_HANDLE hSharedSecretEnc;

fn->C_EncapsulateKey(session, &mlkem_mech, hKemPub,
    ssTmpl, sizeof(ssTmpl) / sizeof(CK_ATTRIBUTE),
    &hSharedSecretEnc,
    ciphertext, &ctLen);

// Decapsulate — recipient recovers same shared secret
CK_OBJECT_HANDLE hSharedSecretDec;
fn->C_DecapsulateKey(session, &mlkem_mech, hKemPriv,
    ssTmpl, sizeof(ssTmpl) / sizeof(CK_ATTRIBUTE),
    &hSharedSecretDec,
    ciphertext, ctLen);

// Both hSharedSecretEnc and hSharedSecretDec hold the same 32-byte secret.
// Extract with C_GetAttributeValue(CKA_VALUE) or feed directly into a KDF.
```

---

## 7. Error Handling

softhsmv3 returns standard `CKR_*` codes. The behaviours below differ from generic PKCS#11 or are worth calling out explicitly:

| Scenario                                           | CKR code returned                      |
|----------------------------------------------------|----------------------------------------|
| Call ML-DSA `C_SignUpdate` after `C_SignInit`       | `CKR_OPERATION_NOT_INITIALIZED`        |
| Call `C_SignMessage` when session is in SIGN_BEGIN state | `CKR_OPERATION_NOT_INITIALIZED`   |
| Pass `pData == NULL` to `C_SignMessage` or `C_SignMessageNext` | `CKR_ARGUMENTS_BAD`         |
| Pass `pulSignatureLen == NULL` to `C_SignMessageNext` | `CKR_ARGUMENTS_BAD`                 |
| Call stub functions (G3–G6)                         | `CKR_FUNCTION_NOT_SUPPORTED`           |
| Call `C_SignRecover` / `C_DigestKey`                | `CKR_FUNCTION_NOT_SUPPORTED`           |
| OpenSSL EVP operation failure                       | `CKR_FUNCTION_FAILED`                  |
| `session->setParameters` heap allocation fails      | `CKR_HOST_MEMORY`                      |
| Wrong session op-type for the called function       | `CKR_OPERATION_NOT_INITIALIZED`        |
| Key attribute `CKA_SIGN` / `CKA_VERIFY` not set    | `CKR_KEY_FUNCTION_NOT_PERMITTED`       |

### Error path after a failed operation

After any non-`CKR_OK` return from a sign or verify call, the session's crypto operation is reset (`resetOp()` is called internally). You must call `C_SignInit` / `C_MessageSignInit` again before retrying. There is no partial-retry mechanism.

For the message API, a failure in `C_SignMessageNext` leaves the session in an indeterminate state — call `C_MessageSignFinal` (which calls `resetOp`) and reinitialise the session.

---

## 8. Session State Machine Reference

Relevant session operation type constants (from `Session.h`):

```
SESSION_OP_NONE                 0x0   — no active operation
SESSION_OP_SIGN                 0x5   — C_SignInit active
SESSION_OP_VERIFY               0x6   — C_VerifyInit active
SESSION_OP_MESSAGE_SIGN         0x11  — C_MessageSignInit active; accepts C_SignMessage / C_SignMessageBegin
SESSION_OP_MESSAGE_VERIFY       0x12  — C_MessageVerifyInit active; accepts C_VerifyMessage / C_VerifyMessageBegin
SESSION_OP_MESSAGE_SIGN_BEGIN   0x13  — C_SignMessageBegin committed; accepts C_SignMessageNext
SESSION_OP_MESSAGE_VERIFY_BEGIN 0x14  — C_VerifyMessageBegin committed; accepts C_VerifyMessageNext
```

Valid transitions:

```
C_MessageSignInit  → 0x11
  C_SignMessage    → 0x11 (stays; one-shot)
  C_SignMessageBegin → 0x13
    C_SignMessageNext(NULL, size query) → 0x13 (stays)
    C_SignMessageNext(buf,  real sign)  → 0x11 (back to message sign)
  C_MessageSignFinal → 0x0
```

The verify side is identical with `0x12` / `0x14`.

---

## 9. SLH-DSA Parameter Sets

softhsmv3 exposes all 12 NIST-standardised SLH-DSA parameter sets via OpenSSL's `EVP_PKEY` interface. The parameter set is selected by `CKA_SLH_DSA_PARAMETER_SET` on the key template:

| Parameter set string | Security level | Small-fast | Signature size (approx.) |
|----------------------|---------------|-----------|--------------------------|
| `"SLH-DSA-SHA2-128s"` | 128-bit      | Small      | 7,856 bytes              |
| `"SLH-DSA-SHA2-128f"` | 128-bit      | Fast       | 17,088 bytes             |
| `"SLH-DSA-SHA2-192s"` | 192-bit      | Small      | 16,224 bytes             |
| `"SLH-DSA-SHA2-192f"` | 192-bit      | Fast       | 35,664 bytes             |
| `"SLH-DSA-SHA2-256s"` | 256-bit      | Small      | 29,792 bytes             |
| `"SLH-DSA-SHA2-256f"` | 256-bit      | Fast       | 49,856 bytes             |
| `"SLH-DSA-SHAKE-128s"`| 128-bit      | Small      | 7,856 bytes              |
| `"SLH-DSA-SHAKE-128f"`| 128-bit      | Fast       | 17,088 bytes             |
| `"SLH-DSA-SHAKE-192s"`| 192-bit      | Small      | 16,224 bytes             |
| `"SLH-DSA-SHAKE-192f"`| 192-bit      | Fast       | 35,664 bytes             |
| `"SLH-DSA-SHAKE-256s"`| 256-bit      | Small      | 29,792 bytes             |
| `"SLH-DSA-SHAKE-256f"`| 256-bit      | Fast       | 49,856 bytes             |

SLH-DSA signing is always probabilistic (randomised). The `hedgeVariant` field in `CK_SIGN_ADDITIONAL_CONTEXT` is accepted but has no effect on SLH-DSA operations.

---

## 10. Pre-Hash Encoding Reference

When a `CKM_HASH_ML_DSA_*` or `CKM_HASH_SLH_DSA_*` mechanism is used, softhsmv3 constructs the pre-hash message encoding internally before passing it to OpenSSL's EVP signer. The encoding follows FIPS 204 §5.4 (ML-DSA) and FIPS 205 §10.1 (SLH-DSA):

```
M' = domain_separator || len(ctx) || ctx || AlgId_DER || H(M)
```

Where:
- `domain_separator` = `0x01` (one byte)
- `len(ctx)` = context length in bytes (one byte, 0–255)
- `ctx` = context bytes (up to 255 bytes)
- `AlgId_DER` = DER-encoded `AlgorithmIdentifier` for the hash algorithm
- `H(M)` = hash of the original message under the specified hash algorithm

This encoding is transparent to callers — pass the raw message to `C_Sign` or `C_SignMessage` and softhsmv3 handles the pre-hash construction.

---

*Repository: [https://github.com/pqctoday/softhsmv3](https://github.com/pqctoday/softhsmv3)*
