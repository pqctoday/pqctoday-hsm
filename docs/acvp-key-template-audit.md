# ACVP Key Template — PKCS#11 v3.2 Compliance Audit

**Date**: 2026-03-22
**Scope**: `tests/helpers.mjs` + `tests/acvp-wasm.mjs`
**Status**: All issues resolved (see fix column)
**Release Target**: 0.3.0

---

## Per-Template Attribute Table

| Function | Test(s) | `CKA_LOCAL` | `CKA_SENSITIVE` | `CKA_EXTRACTABLE` | `CKA_VALUE_LEN` | `CKA_EC_PARAMS` (priv) | Status |
|---|---|---|---|---|---|---|---|
| `importAESKey` | 1,11,12,19,20 | ~~⚠️ missing~~ ✅ fixed | ✅ | ✅ | ~~⚠️ missing~~ ✅ fixed | n/a | ✅ |
| `importHMACKey` | 2,13,14 | ~~⚠️ missing~~ ✅ fixed | ~~⚠️ missing~~ ✅ fixed | ~~⚠️ missing~~ ✅ fixed | ~~⚠️ missing~~ ✅ fixed | n/a | ✅ |
| `importRSAPublicKey` | 3 | ~~⚠️ missing~~ ✅ fixed | n/a | n/a | n/a | n/a | ✅ |
| `importECPublicKey` | 4,15 | ~~⚠️ missing~~ ✅ fixed | n/a | n/a | n/a | n/a | ✅ |
| `importMLDSAPublicKey` | 5 | ~~⚠️ missing~~ ✅ fixed | n/a | n/a | n/a | n/a | ✅ |
| `importMLKEMPrivateKey` | 7 | ~~⚠️ missing~~ ✅ fixed | ~~⚠️ missing~~ ✅ fixed | ✅ (=true) | n/a | n/a | ✅ |
| `generateAESKey` | 18,20 | server sets | ✅ | ✅ | ✅ | n/a | ✅ |
| `generateMLDSAKeyPair` | 6 | server sets | server default | server default | n/a | n/a | ✅ |
| `generateMLKEMKeyPair` | 8 | server sets | ~~🔴 ignored~~ ✅ removed | ~~🔴 ignored~~ ✅ removed | n/a | n/a | ✅ |
| `generateSLHDSAKeyPair` | 9 | server sets | server default | server default | n/a | n/a | ✅ |
| `generateEdDSAKeyPair` | 16 | server sets | server default | server default | n/a | ~~⚠️ missing~~ ✅ fixed | ✅ |
| `encapsulate`/`decapsulate` SS | 7,8 | server sets | ✅ | ✅ | ✅ | n/a | ✅ |
| AES-KWP unwrap (acvp-wasm.mjs) | 20 | server sets | ~~⚠️ missing~~ ✅ fixed | ✅ | ✅ absent (correct) | n/a | ✅ |

---

## Issues Fixed

### 1. `importAESKey` — Added `CKA_LOCAL=false`, `CKA_VALUE_LEN`
- **PKCS#11 ref**: §4.3 — imported keys MUST have `CKA_LOCAL=FALSE`; secret key MUST have `CKA_VALUE_LEN`
- **Fix**: Added both attributes to template

### 2. `importHMACKey` — Added `CKA_EXTRACTABLE`, `CKA_SENSITIVE`, `CKA_LOCAL=false`, `CKA_VALUE_LEN`
- **PKCS#11 ref**: §4.3 — `CKA_EXTRACTABLE` and `CKA_SENSITIVE` mandatory for all secret keys; `CKA_LOCAL=FALSE` for imports; `CKA_VALUE_LEN` mandatory for secret keys
- **Fix**: Added all four missing attributes

### 3. `importRSAPublicKey` — Added `CKA_LOCAL=false`
- **PKCS#11 ref**: §4.3 — `CKA_LOCAL=FALSE` for imported keys
- **Fix**: Added attribute

### 4. `importECPublicKey` — Added `CKA_LOCAL=false`
- Same as above

### 5. `importMLDSAPublicKey` — Added `CKA_LOCAL=false`
- Same as above

### 6. `importMLKEMPrivateKey` — Added `CKA_LOCAL=false`, `CKA_SENSITIVE=false`
- **PKCS#11 ref**: §4.3 — `CKA_LOCAL=FALSE` for imports; `CKA_SENSITIVE` mandatory for private keys; with `CKA_EXTRACTABLE=TRUE` the correct value is `FALSE`
- **Fix**: Added both

### 7. `generateMLKEMKeyPair` — Removed `CKA_SENSITIVE=false` and `CKA_EXTRACTABLE=true` from private template
- **PKCS#11 ref**: §4.3.2 — both engines override these unconditionally (force SENSITIVE=true/EXTRACTABLE=false) regardless of template; misleading caller-side values removed
- **Fix**: Removed both attributes from private template

### 8. `generateEdDSAKeyPair` — Added `CKA_EC_PARAMS` to private template
- **PKCS#11 ref**: §2.3.6 — `CKA_EC_PARAMS` is mandatory for `CKO_PRIVATE_KEY / CKK_EC_EDWARDS`
- **Fix**: Added `CKA_EC_PARAMS` with Ed25519 OID to private template

### 9. `encapsulate` / `decapsulate` shared secret — Added explicit usage attributes
- **PKCS#11 ref**: §4.3 — Usage attributes (ENCRYPT/DECRYPT/SIGN/VERIFY/WRAP/UNWRAP/DERIVE) should be explicit in template; undefined state is implementation-defined
- **Fix**: Added all usage attrs as `false` (shared secret is only extracted, not used for crypto ops in ACVP test)

### 10. AES-KWP unwrap template (`acvp-wasm.mjs`) — Added `CKA_SENSITIVE=false`
- **PKCS#11 ref**: §4.3 — `CKA_SENSITIVE` mandatory for secret keys; with `CKA_EXTRACTABLE=TRUE` the correct value is `FALSE`
- **Fix**: Added `CKA_SENSITIVE=false`

---

## Server-Side Gap Resolution (2026-03-22)

All previously-open server-side gaps have been resolved, except the RSA key attribute gaps (Rust-only, not exercised by ACVP KAT vectors):

| Gap | Scope | Status |
|---|---|---|
| `CKA_MODIFIABLE` (0x170) not set on any generated key | Rust + C++ | ~~Open~~ ✅ fixed |
| `CKA_DESTROYABLE` (0x172) not set on any generated key | Rust + C++ | ~~Open~~ ✅ fixed |
| `CKA_COPYABLE` (0x171) not set on any generated key | Rust + C++ | ~~Open~~ ✅ fixed |
| `CKA_KEY_GEN_MECHANISM` not set for AES / GENERIC_SECRET via `C_GenerateKey` | Rust + C++ | ~~Open~~ ✅ fixed |
| `CKA_LOCAL=FALSE` not enforced by `C_CreateObject` for imported keys | Rust + C++ | ~~Open~~ ✅ fixed |
| `CKA_LOCAL=TRUE` not set for keys derived via `C_EncapsulateKey` / `C_DecapsulateKey` | Rust + C++ | ~~Open~~ ✅ fixed |
| RSA public key: `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` not stored by `C_GenerateKeyPair` (only `CKA_VALUE` with custom encoding) | Rust | Open (Rust only; not exercised by ACVP KAT) |
| RSA private key: CRT components not stored (`C_PRIME_1`, `CKA_PRIME_2`, `CKA_EXPONENT_1`, `CKA_EXPONENT_2`, `CKA_COEFFICIENT`) | Rust | Open (Rust only; not exercised by ACVP KAT) |
| `generateMLKEMKeyPair` private template values `CKA_SENSITIVE=false/CKA_EXTRACTABLE=true` silently ignored | Rust + C++ | Mitigated (misleading attrs removed from template) |

### Fix Details

| Fix | File | Change |
|---|---|---|
| `CKA_MODIFIABLE/COPYABLE/DESTROYABLE` Rust | `rust/src/state.rs` | `apply_object_defaults()` called inside `allocate_handle()` — all keys now get lifecycle defaults |
| `CKA_MODIFIABLE/COPYABLE/DESTROYABLE` C++ | `src/lib/P11Attributes.cpp` | Already set via `P11AttrModifiable/Copyable/Destroyable::setDefault()` (pre-existing, confirmed correct) |
| `CKA_KEY_GEN_MECHANISM` AES Rust | `rust/src/ffi.rs:C_GenerateKey` | Added `store_ulong(..., CKM_AES_KEY_GEN)` |
| `CKA_KEY_GEN_MECHANISM` GENERIC_SECRET Rust | `rust/src/ffi.rs:C_GenerateKey` | Added `store_ulong(..., CKM_GENERIC_SECRET_KEY_GEN)` |
| `CKA_KEY_GEN_MECHANISM` AES/GENERIC_SECRET C++ | `src/lib/SoftHSM_keygen.cpp` | Already set (lines 3013, 3207 etc.) — pre-existing, confirmed correct |
| `CKA_LOCAL=FALSE` in `C_CreateObject` Rust | `rust/src/ffi.rs:C_CreateObject` | Added `store_bool(..., CKA_LOCAL, false)` after template absorption |
| `CKA_LOCAL=FALSE` in `C_CreateObject` C++ | `src/lib/SoftHSM_objects.cpp` | Already set (lines 949, 957) — pre-existing, confirmed correct |
| `CKA_LOCAL=TRUE` encap/decap Rust | `rust/src/ffi.rs` | Added `store_bool(&mut ss_attrs, CKA_LOCAL, true)` to both C_EncapsulateKey and C_DecapsulateKey |
| `CKA_LOCAL=TRUE` encap/decap C++ | `src/lib/SoftHSM_kem.cpp` | Changed `CKA_LOCAL=false` → `CKA_LOCAL=true` for shared secret in both encapsulate and decapsulate |
| AES-KWP unwrap `CKA_SENSITIVE` | `tests/acvp-wasm.mjs` | Added `CKA_SENSITIVE=false` to unwrap template |
