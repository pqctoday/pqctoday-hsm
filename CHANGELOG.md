# Changelog

All notable changes to `@pqctoday/softhsm-wasm` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

---

## [0.4.18] — 2026-04-08

### Fixed

- **`CKA_PUBLIC_KEY_INFO` transparency — C++ engine**: Added `P11AttrPublicKeyInfo::retrieve()`
  override that always passes `isPrivate=false` to the base retrieval, ensuring
  `CKA_PUBLIC_KEY_INFO` is returned in clear regardless of the object's private flag.
  Per PKCS#11 v3.2 §4.14: "The value of this attribute can be retrieved by any application."

- **KEM derived key operation type — C++ engine**: `C_EncapsulateKey` and `C_DecapsulateKey`
  now create the output shared-secret key object with `OBJECT_OP_DERIVE` instead of
  `OBJECT_OP_GENERATE`. KEM-produced secrets are derived keys, not generated keys — this
  affects which template validation rules apply (§5.18.5 vs §5.18.3).

- **KEM output key `CKA_LOCAL` — C++ and Rust engines**: `C_EncapsulateKey` and
  `C_DecapsulateKey` now set `CKA_LOCAL = CK_FALSE` on the output shared-secret key per
  PKCS#11 v3.2 §5.18.8 and §5.18.9. Previously set to `CK_TRUE`, which is only correct for
  keys produced by `C_GenerateKey` / `C_GenerateKeyPair`.

- **KEM output key `CKA_ALWAYS_SENSITIVE` / `CKA_NEVER_EXTRACTABLE` — C++ and Rust engines**:
  Both attributes are now unconditionally `CK_FALSE` for KEM-derived secret keys per spec
  §5.18.8 and §5.18.9. Previously `C_DecapsulateKey` (C++) inherited `CKA_ALWAYS_SENSITIVE`
  from the source private key; Rust engine derived both from the key's own `CKA_SENSITIVE` /
  `CKA_EXTRACTABLE` via `finalize_private_key_attrs()`.

- **`C_DecapsulateKey` error codes — C++ engine**: Replaced `CKR_GENERAL_ERROR` with
  spec-compliant error codes per §5.18.9 return value list: `CKR_WRAPPED_KEY_LEN_RANGE` when
  the ciphertext length does not match any ML-KEM variant (768/1088/1568 bytes), and
  `CKR_WRAPPED_KEY_INVALID` for cryptographic decapsulation failures. The spec uses the
  unwrap error family for KEM operations, not the decrypt family.

- **Removed debug `printf`** from `P11Object::loadTemplate()` — diagnostic output for
  `CKR_ATTRIBUTE_SENSITIVE` should not appear in release builds.

### Added

- **`p11_v32_compliance_test` build target**: Added CMake target for the standalone PKCS#11
  v3.2 compliance test executable (native builds only, excluded from Emscripten).

---

## [0.4.17] — 2026-04-08

### Fixed

- **Rust WASM binary now reflects v0.4.16 source changes**: v0.4.16 added `CKM_HASH_ML_DSA`,
  `CKM_HASH_SLH_DSA`, and `CKM_EDDSA_PH` to `SUPPORTED_MECHS` in `rust/src/constants.rs` but
  did not rebuild and commit the WASM binary. This release rebuilds the Rust crate (now at
  `version = "0.4.17"` in `Cargo.toml`) and commits the new `softhsmrustv3_bg.wasm` and
  `softhsmrustv3.js` artifacts. Browsers and Node.js consumers will now see all three mechanisms
  in `C_GetMechanismList`.

- **`wasm-bindgen` upgraded from `0.2.92` → `0.2.117`** (`rust/Cargo.toml`): Required to
  match the installed `wasm-bindgen-cli` used to produce the shim. No functional API changes.

---

## [0.4.16] — 2026-04-08

### Added

- **`CKM_HASH_ML_DSA` (0x1F) + `CKM_HASH_SLH_DSA` (0x34) in Rust `SUPPORTED_MECHS`**: The
  base HashML-DSA and HashSLH-DSA mechanism constants were present in `constants.rs` but absent
  from the `SUPPORTED_MECHS` slice, so `C_GetMechanismList` did not expose them. Added to both
  `SUPPORTED_MECHS` and `constants.js`.

- **`CKM_EDDSA_PH` (0xffff1057) — Ed25519ph pre-hash mode**: Ed25519 pre-hash signing per
  RFC 8032 §5.1 and PKCS#11 v3.2 §6.3.15. Added to `constants.rs` `SUPPORTED_MECHS` and
  `constants.js`.

- **`CKM_SHA3_256` (0x000002b0) + `CKM_SHA3_256_HMAC` (0x000002b1)**: SHA3-256 digest and
  HMAC-SHA3-256 constants added to `constants.js`.

- **`CKM_KMAC_128` (0x80000100) + `CKM_KMAC_256` (0x80000101)**: KMAC constants (vendor-defined
  range) added to `constants.js` for FIPS 202 / SP 800-185 keyed MAC.

### Added (ACVP test suite — `tests/acvp-wasm.mjs`)

- **§6.5 HashML-DSA functional sign+verify** (FIPS 204): Three test cases covering
  HashML-DSA-44-SHA256, HashML-DSA-65-SHA512, and HashML-DSA-87-SHA512 via
  `CKM_HASH_ML_DSA_SHA256` / `CKM_HASH_ML_DSA_SHA512`. Skips gracefully when
  `CKM_HASH_ML_DSA` is absent from the mechanism list.

- **§9.5 HashSLH-DSA functional sign+verify**: Two test cases covering
  HashSLH-DSA-SHA2-128f-SHA256 and HashSLH-DSA-SHA2-256f-SHA512 via
  `CKM_HASH_SLH_DSA_SHA256` / `CKM_HASH_SLH_DSA_SHA512`. Skips gracefully when
  `CKM_HASH_SLH_DSA` is absent.

- **§10.5 SHA3-256 digest empty-string KAT** (FIPS 202): Validates
  `digest([], CKM_SHA3_256) == a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`.
  Skips when `CKM_SHA3_256` absent.

- **§16.5 Ed25519ph functional sign+verify**: Round-trip test using `CKM_EDDSA_PH`. Generates
  Ed25519 key pair, signs with pre-hash mode, verifies. Skips when `CKM_EDDSA_PH` absent.

Total ACVP test vectors: **37 per engine, 74 in dual-HSM mode** (was 31 / 62).

### Removed

- **`rust/tests/pqc_api_test.rs`**: Pure-Rust unit tests for ML-KEM and SLH-DSA context/
  deterministic signing removed. Superseded by the WASM-layer ACVP test suite
  (`tests/acvp-wasm.mjs`) which validates these paths against real PKCS#11 dispatch.

- **`rust/tests/test_xmss.rs`**: Stub XMSS unit test removed. XMSS is tested end-to-end in
  the WASM integration suite.

---

## [0.4.15] — 2026-04-07

### Fixed

- **RSA public key: `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` per PKCS#11 v3.2 §2.1.2 — Rust engine**:
  RSA public keys generated by `C_GenerateKeyPair` were stored as `CKA_VALUE` with a custom
  `[n_len:4LE][n_bytes][e_bytes]` packed format. PKCS#11 v3.2 §2.1.2 (Table 37) requires
  `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT` as distinct attributes; `CKA_VALUE` is not defined for
  `CKO_PUBLIC_KEY / CKK_RSA` objects.

  **Impact of the bug:**
  - `C_GetAttributeValue` returned `CK_UNAVAILABLE_INFORMATION` (0xFFFFFFFF) for both
    `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT`, causing a JavaScript `RangeError: Length out of
    range of buffer` crash in callers that allocated based on the returned length.
  - `C_Verify` for `CKM_SHA256_RSA_PKCS` / `CKM_SHA256_RSA_PKCS_PSS` always failed with
    `CKR_KEY_TYPE_INCONSISTENT` because `get_rsa_public_components()` reads `CKA_MODULUS` and
    `CKA_PUBLIC_EXPONENT` from the object store and returned `None`.

  **Fix:** store `n_bytes` as `CKA_MODULUS`, `e_bytes` as `CKA_PUBLIC_EXPONENT`, and the key
  size as `CKA_MODULUS_BITS`. Removed `CKA_VALUE` from RSA public key objects. Private key
  `CKA_VALUE` (PKCS#8 DER) is unchanged.

---

## [0.4.10] — 2026-04-07

### Added

- **`CKM_ECDSA_SHA512` (0x1046) — Rust engine**: ECDSA with SHA-512 prehash on P-256 and P-384.
  Required for the `id-MLDSA65-ECDSA-P256-SHA512` composite certificate OID
  (draft-ietf-lamps-pq-composite-sigs). Previously returned `CKR_MECHANISM_INVALID`.

- **Message Encrypt/Decrypt API — Rust engine** (PKCS#11 v3.0 per-message AEAD, 10 functions):
  `C_MessageEncryptInit`, `C_EncryptMessage`, `C_EncryptMessageBegin`, `C_EncryptMessageNext`,
  `C_MessageEncryptFinal`, `C_MessageDecryptInit`, `C_DecryptMessage`, `C_DecryptMessageBegin`,
  `C_DecryptMessageNext`, `C_MessageDecryptFinal`. AES-GCM with per-message IV and AAD.
  State tracked in `MsgAeadCtx` (key, IV, AAD, tag bits, payload accumulator, `in_message` guard).

- **`C_VerifySignatureUpdate` / `C_VerifySignatureFinal` — Rust engine**: Streaming pre-bound
  verify (PKCS#11 v3.2 §11.15). Accumulates message parts in `VerifySigCtx.msg_acc`, then
  delegates to `C_Verify` on `Final`. Completes the multi-part pre-bound verify surface
  introduced in v0.4.8.

- **PKCS#11 v3.2 async stubs — Rust engine**: `C_GetSessionValidationFlags`, `C_AsyncComplete`,
  `C_AsyncGetID` return `CKR_FUNCTION_NOT_SUPPORTED`. Brings total Rust exports to **85 PKCS#11
  functions** (plus `set_kat_seed`).

### Fixed

- **`CKM_ECDSA_SHA512` hash truncation (FIPS 186-5 §6.4)**: SHA-512 produces 64 bytes but
  `p256::PrehashSigner` requires exactly 32 bytes (P-256 field size). Sign and verify now
  truncate to the leftmost 32 bytes for P-256, 48 bytes for P-384, per spec.

- **G-ATTR1a — ML-DSA public key `CKA_VALUE` — C++ engine**: Was `checks=0`; corrected to
  `ck1|ck4` per PKCS#11 v3.2 Table 280 (`^1` required for `C_CreateObject`, `^4` MUST NOT for
  `C_GenerateKeyPair`). `CKA_PARAMETER_SET` corrected to `ck1|ck3` (was `ck3` only, missing `^1`).

- **G-ATTR1b — SLH-DSA public key `CKA_VALUE` — C++ engine**: Same fix as G-ATTR1a; references
  spec Table 287. `CKA_PARAMETER_SET` corrected to `ck1|ck3`.

- **G-ATTR1c — ML-KEM public key `CKA_VALUE` — C++ engine**: Same fix; references spec Table 290.
  `CKA_PARAMETER_SET` corrected to `ck1|ck3`.

- **HSS public key attribute flags — C++ engine**: `CKA_VALUE` corrected to `ck1|ck4`;
  `CKA_HSS_LEVELS`, `CKA_HSS_LMS_TYPE`, `CKA_HSS_LMOTS_TYPE`, `CKA_HSS_LMS_TYPES`,
  `CKA_HSS_LMOTS_TYPES` corrected to `ck2|ck4` (MUST NOT for both create and generate) per
  PKCS#11 v3.2 Table 269. HSS private key `CKA_VALUE` corrected to `ck1|ck4|ck6|ck7`.

- **XMSS / XMSS-MT attribute flags — C++ engine**: Public key `CKA_VALUE` corrected to `ck1|ck4`,
  `CKA_PARAMETER_SET` to `ck1|ck3`. Private key `CKA_VALUE` corrected to `ck1|ck4|ck6|ck7`,
  `CKA_PARAMETER_SET` to `ck1|ck4|ck6`. Same corrections applied to XMSS-MT objects. Per
  PKCS#11 v3.2 Tables 273, 275 (and XMSS-MT equivalents).

- **`P11AttrParameterSet`, `P11AttrHssLevels/LmsType/LmotsType/LmsTypes/LmotsTypes` base
  constructors — C++ engine**: Removed erroneous `ck1` from default `checks` in base constructor
  bodies. Flags are now set exclusively at the call site in `P11Objects.cpp` via the `inchecks`
  parameter, eliminating double-application of `ck1` that could cause spurious
  `CKR_TEMPLATE_INCOMPLETE` on `C_GenerateKeyPair`.

- **`Slot::isTokenPresent()` — C++ engine**: Now returns `token->isInitialized()` instead of
  unconditional `true`. Uninitialized placeholder slots are no longer reported as token-present,
  fixing `C_GetSlotList(tokenPresent=CK_TRUE)` to correctly exclude empty slots per PKCS#11
  v3.2 §4.2.2.

---

## [0.4.8] — 2026-04-06

### Added

- **`CKA_XMSS_KEYS_REMAINING` (vendor attr 0x80000106)**: Separate from `CKA_HSS_KEYS_REMAINING`;
  tracks remaining XMSS signature operations as a `u32` LE value per PKCS#11 v3.2 §6.15.
- **`xmss_param_max_sigs()` / `xmss_keys_remaining()`**: Compute XMSS signature capacity (2^H)
  and derive remaining count by reading the leaf index directly from the serialised key blob
  (big-endian at offset 4 after OID), tolerating crate-internal leaf skipping.
- **`CKR_ATTRIBUTE_TYPE_INVALID` (0x00000012)**: Exported constant per PKCS#11 v3.2 §11.7.

### Fixed

- **`C_GetSlotList` token-present filter**: Now correctly filters on `token.initialized` when
  `tokenPresent = CK_TRUE` (was always returning all slots regardless of flag).
- **`C_GetAttributeValue` PKCS#11 v3.2 §5.7.5 compliance**:
  - Public keys (`CKO_PUBLIC_KEY`) are always fully readable — `CKA_SENSITIVE` / `CKA_EXTRACTABLE`
    restrictions now apply only to private and secret keys.
  - Absent attributes now set `ulValueLen = CK_UNAVAILABLE_INFORMATION` and the function returns
    `CKR_ATTRIBUTE_TYPE_INVALID` as required (was silently returning `CKR_OK`).
- **`C_Sign` XMSS state tracking**: Updates `CKA_XMSS_KEYS_REMAINING` by re-reading the leaf
  index from the updated key blob after each sign — avoids off-by-one from simple decrement.
- **`C_Sign` HSS state update**: `new_state` clone now stored correctly; leaf index and
  keys-remaining tracked in separate HSS vs XMSS code paths.
- **HSS keygen `CKA_HSS_KEYS_REMAINING`**: Computes actual capacity (∏ 2^H_i across levels,
  capped at `u32::MAX`) instead of hardcoded placeholder value of 32.
- **XMSS keygen `CKA_XMSS_KEYS_REMAINING`**: Stored under the new vendor attribute
  `CKA_XMSS_KEYS_REMAINING` (0x80000106) — was incorrectly aliased to `CKA_HSS_KEYS_REMAINING`.
- **`hss_sign()` hash-family dispatch**: Now takes `lms_param` and routes to the correct
  `hbs-lms` generic (`Sha256_256 / Sha256_192 / Shake256_256 / Shake256_192`) — previously
  always used `Sha256_256`, causing silent `CKR_KEY_EXHAUSTED` on M24/SHAKE parameter sets.
- **`lms_single_sig_len()` full SP 800-208 coverage**: Derives `n` and `p` from IANA type-ID
  ranges — correct for all 20 LMS × 16 LMOTS combinations (SHA-256 N24, SHAKE-256 N32/N24
  were previously returning wrong lengths).
- **`hss_sig_len()` LMS public key size**: Corrected 52 → 56 bytes per RFC 8554 §5.4
  (`lms_type(4) + lmots_type(4) + I(16) + T[1](32)`).
- **`get_sig_len()` XMSS support**: Added `CKM_XMSS` case; removed duplicate unreachable
  `CKM_HSS` match arm.
- **`C_GetMechanismInfo` ML-KEM key sizes**: Corrected from security-bit values (128/256) to
  actual encapsulation key byte lengths (800/1568 per FIPS 203).

---

## [0.4.7] — 2026-04-05

### Added

- **SP 800-208 full parameter coverage**: All 20 LMS and 16 LMOTS parameter sets now supported
  across C++ and Rust engines (SHA-256 N32/N24, SHAKE-256 N32/N24).
- **C++ `StatefulVerifyInit` / `StatefulVerify`**: HSS/LMS/XMSS/XMSS^MT signature verification
  through PKCS#11 `C_VerifyInit` / `C_Verify`. Previously only signing was implemented in C++.
- **C++ SHAKE-256 hash type**: Added `HASH_SHAKE256` to hash-sigs library using OpenSSL
  `EVP_shake256()` for SHAKE-256 XOF output (32-byte and 24-byte modes).
- **C++ XMSS/XMSS^MT in `C_GetMechanismInfo`**: Registered `CKM_XMSS_KEY_PAIR_GEN`,
  `CKM_XMSS`, `CKM_XMSSMT_KEY_PAIR_GEN`, `CKM_XMSSMT` with `CKF_SIGN | CKF_VERIFY`.
- **Rust N24/SHAKE dispatch**: `lms_keygen` dispatches to `Sha256_192`, `Shake256_256`,
  `Shake256_192` hash types via hbs-lms 0.1.1 built-in support.
- **NIST ACVP LMS sigVer validation**: 320/320 official demo vectors validated
  ([usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)) covering all
  80 parameter combinations. Test runner: `tests/test_acvp_lms_sigver.py`.
- **ACVP vector files**: `tests/acvp/lms_keygen_*`, `lms_sigver_*`, `lms_siggen_*` from NIST.

### Fixed

- **XMSS keygen buffer overflow**: Public/private key buffers now correctly allocate
  `XMSS_OID_LEN + pk/sk_bytes` (was `pk/sk_bytes` only — missing 4-byte OID prefix caused
  truncation and verify failure).
- **XMSS `C_Sign` PKCS#11 v3.2 compliance**: Stripped appended message from signature output.
  `xmss_sign()` returns `[sig || msg]`; `C_Sign` now returns signature-only as required by spec.
- **XMSS^MT keygen OID parsing**: Changed from `xmss_parse_oid` to `xmssmt_parse_oid` for
  XMSS^MT parameter sets.
- **CKP_ constants corrected to IANA registry values**: LMS constants used tree-height values
  (e.g., `CKP_LMS_SHA256_M32_H10 = 10`) instead of IANA type IDs (`0x06`). LMOTS constants
  used Winternitz W values (e.g., `CKP_LMOTS_SHA256_N32_W4 = 4`) instead of type IDs (`0x03`).
  All corrected to match RFC 8554 + SP 800-208 IANA registry.
- **C++ dead code removed**: Unreachable XMSS keygen stub at `SoftHSM_keygen.cpp:649`.
- **Session `verifyKeyHandle` initialization**: Both constructors now initialize
  `signKeyHandle` and `verifyKeyHandle` to `CK_INVALID_HANDLE`.

### Changed

- **Gap analysis G10 resolved**: `docs/gap-analysis-pkcs11-v3.2.md` §3.4 updated from
  "out of scope" to "RESOLVED" with implementation details for C++ and Rust engines.

---

## [0.4.6] — 2026-04-04

### Added

- **C++ Native Stateful Hash Signatures Bounds**: Integrated explicit fallback object-generation mapping in `SoftHSM_keygen.cpp` for native CKM_HSS_KEY_PAIR_GEN tracking, bounding `CKA_HSS_KEYS_REMAINING` properties directly in the object store.
- **WASM v3.2 Strict Mapping Attributes**: Mapped exactly `CKA_HSS_KEYS_REMAINING` with ID `0x0000061cUL` strictly enforcing exact signature deductions within C_Sign loop execution to guarantee PKCS#11 backend exhaustion on WebAssembly integrations.

---

## [0.4.5] — 2026-04-03

### Fixed

- **WASM session exclusivity checks:** Fixed CKR return codes and token tracking logic in `C_Login` and `C_OpenSession` within the Rust engine to correctly conform to PKCS#11 v3.2 boundaries (`CKR_SESSION_READ_ONLY_EXISTS` and `CKR_USER_ANOTHER_ALREADY_LOGGED_IN`).
- **WASM PIN hashing:** Implemented PKCS#11 compliant PBKDF2 hashing for PINs across the WASM layer.

---

## [0.4.4] — 2026-04-03

### Added

- **G10 — LMS/HSS stateful hash-based signatures (NIST SP 800-208, RFC 8554)**
  - `CKM_LMS_KEY_PAIR_GEN` / `CKM_LMS` (vendor, single-level LMS) via Rust hbs-lms 0.1.1
  - `CKM_HSS_KEY_PAIR_GEN` / `CKM_HSS` (PKCS#11 v3.2 §6.14, multi-level HSS, 1–8 levels)
  - Vendor key type `CKK_LMS`; standard `CKK_HSS`, `CKK_XMSS`, `CKK_XMSSMT`
  - Vendor attributes: `CKA_STATEFUL_KEY_STATE`, `CKA_LMS_PARAM_SET`, `CKA_LMOTS_PARAM_SET`,
    `CKA_XMSS_PARAM_SET`, `CKA_LEAF_INDEX` (range 0x80000101–0x80000105)
  - All 5 LMS tree-height parameter sets (H5/H10/H15/H20/H25) and 4 LMOTS Winternitz
    parameter sets (W1/W2/W4/W8) via `CKP_*` constants mirroring SP 800-208 Table 1
  - Key exhaustion: `CKR_KEY_EXHAUSTED` (0x203) returned on sign attempt past capacity
    — LMS: pre-check via `CKA_LEAF_INDEX ≥ 2^H`; HSS: callback_fired pattern
  - `C_Sign` / `C_Verify` dispatch for `CKM_LMS` and `CKM_HSS` via early-return path
    before standard object-value lookup; state atomically persisted via PKCS#11 callback
  - `CK_HSS_KEY_PAIR_GEN_PARAMS` struct (68 bytes) in `vendor_mechanisms.h` for HSS keygen
  - New C++ header `src/lib/vendor_mechanisms.h` — all vendor CKM/CKA/CKP constants,
    mirrored in `rust/src/constants.rs` and `src/wasm/softhsm/constants.ts`
  - Mechanism entries in `prepareSupportedMechanisms()` and `C_GetMechanismInfo` for
    CKM_LMS_KEY_PAIR_GEN, CKM_HSS_KEY_PAIR_GEN, CKM_LMS, CKM_HSS
  - TypeScript helpers in `src/wasm/softhsm/stateful.ts`: `hsm_generateLMSKeyPair`,
    `hsm_generateHSSKeyPair`, `hsm_lmsSign`, `hsm_lmsVerify`, `hsm_lmsGetLeafIndex`,
    `hsm_hssSign`, `hsm_hssVerify`

- **G11 — Keccak-256 (Ethereum address derivation)**
  - `CKM_KECCAK_256` (vendor 0x80000010) — Rust engine only via tiny-keccak 2.0
  - Streaming `C_DigestInit` / `C_DigestUpdate` / `C_DigestFinal` + one-shot `C_Digest`
  - C++ engine returns `CKR_MECHANISM_INVALID` (non-standard Keccak padding not in OpenSSL)
  - `DigestCtx::Keccak256(Vec<u8>)` variant in the Rust digest state machine
  - TypeScript helper `hsm_keccak256` in `src/wasm/softhsm/stateful.ts`
  - Mechanism entry in `prepareSupportedMechanisms()` for `CKM_KECCAK_256` (Rust engine only)

---

## [0.4.3] — 2026-04-02

### Added

- **X448 Diffie-Hellman** (PKCS#11 v3.2 §6.7, RFC 7748 §6.2) via x448 0.14 crate
  - `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` now dispatches X25519 vs X448 by last OID byte
  - RFC 7748 clamping applied at keygen; 56-byte shared secret from `diffie_hellman()`
  - `build_x448_spki()` helper: AlgId OID 1.3.101.111 (id-X448, RFC 8410)
- **X9.63 KDF SHA3 variants** (PKCS#11 v3.2 §5.2.12)
  - `CKD_SHA3_256_KDF` and `CKD_SHA3_512_KDF` counter-mode KDF loops
- **C_GetMechanismInfo**: Montgomery key-size range extended to 255–448

---

## [0.4.1] — 2026-03-29

### Security

- **OpenSSL 3.6.0 → 3.6.1:** 9 CVE fixes including TLS 1.3 CompressedCertificate
  excessive memory allocation (CVE-2025-66199), CMS AuthEnvelopedData stack buffer
  overflow (CVE-2025-15467), and OCSP stapling regression.

### Fixed

- **C_EncapsulateKey / C_DecapsulateKey template rejection (CKR 0x13):**
  `extractObjectInformation()` parsed CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, and
  CKA_KEY_TYPE from the caller's template, then a subsequent loop rejected those
  same attributes with `CKR_ATTRIBUTE_VALUE_INVALID` instead of skipping them.
  Full ML-KEM-768 encapsulate → decapsulate → shared-secret-match flow now passes.
- **handle_mgr missing OpenSSL include path:** `HandleManager.cpp` includes
  `<openssl/rand.h>` but `CMakeLists.txt` was missing `${CRYPTO_INCLUDES}`,
  causing `fatal error: 'openssl/rand.h' file not found` on clean WASM builds.

---

## [0.4.0] — 2026-03-22

### Security

Full remediation of the March 2026 security audit (`docs/security_audit_03222026.md`).
All 62 ACVP test vectors pass across both C++ and Rust WASM engines (31 per engine,
zero failures, zero skips) after these changes.

**Full audit report:** [`docs/security_audit_03222026.md`](docs/security_audit_03222026.md)

#### HIGH severity — fixed

- **RSA X.509 integer underflow (NEW-H1):** `size - ulDataLen` could underflow to
  `SIZE_MAX` when `ulDataLen > size`, causing a heap buffer overread. Added an explicit
  `ulDataLen > size → CKR_DATA_LEN_RANGE` guard in both sign and verify paths.
- **AES-CBC IV length not validated (NEW-H2):** `EncryptInit` / `DecryptInit` only
  rejected a NULL IV pointer; a non-16-byte IV silently used garbage memory as the
  remainder. Now returns `CKR_MECHANISM_PARAM_INVALID` unless `ulParameterLen == 16`.
- **WrapKeySym mode variable left zero (NEW-H3):** `CKM_AES_CBC` and `CKM_AES_CBC_PAD`
  cases in both `WrapKeySym` and `UnwrapKeySym` set `algo` but never set `mode`, leaving
  it at zero (`SymWrap::Unknown`). Now sets `mode = SymWrap::AES_KEYWRAP` /
  `AES_KEYWRAP_PAD` so the correct cipher path is selected.
- **pValue NULL dereference in object creation (NEW-H4):** Five required attributes
  (`CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_CERTIFICATE_TYPE`, `CKA_TOKEN`, `CKA_PRIVATE`)
  dereferenced `pTemplate[i].pValue` without a NULL check. Now returns
  `CKR_ATTRIBUTE_VALUE_INVALID` for any of these with a NULL value pointer.

#### MEDIUM severity — fixed

- **GcmMsgCtx param not wiped on reset (NEW-M1):** `Session::resetOp` called `free(param)`
  without zeroing first; the freed region retained GCM key material until reallocated.
  Now uses `memset(param, 0, paramLen)` before `free`.
- **Unbounded string read in object store (NEW-M2):** `File::readString` allocates a
  `std::vector<char>` of the on-disk `len` field; a malformed file could request GBs.
  Capped at 64 MiB — legitimate serialised strings never approach this.
- **Path traversal and symlink follow in Directory (NEW-M3):** `Directory::refresh` did
  not reject entries containing `..` or `/`, and followed symlinks. Now rejects both
  and explicitly skips `DT_LNK` entries (with `S_ISLNK` fallback for filesystems
  that return `DT_UNKNOWN`).
- **ML-KEM shared secret not wiped (NEW-M4):** After `C_EncapsulateKey` /
  `C_DecapsulateKey`, both `sharedSecret` and `storedValue` are now explicitly wiped
  via `ByteString::wipe()` before going out of scope.
- **RSA-PSS salt length unbounded (NEW-M5):** A caller-supplied `sLen > 512` could
  exceed the maximum salt length OpenSSL accepts, causing an EVP error or signed output
  inconsistency. Now returns `CKR_MECHANISM_PARAM_INVALID` for `sLen > 512` at all
  20 PSS parameter sites in `SignInit` and `VerifyInit`.
- **Predictable PKCS#11 handle counter (NEW-M6):** `HandleManager` previously started
  at handle 1 on every process start. A 20-bit random offset (via `RAND_bytes`) is now
  applied at construction, making handles non-predictable across sessions.
- **SLH-DSA pure mode accepted non-NULL parameters (NEW-M7):** `CKM_SLH_DSA` cases
  in `SignInit` / `VerifyInit` passed without checking `pParameter`. Since the pure
  mode takes no parameters, a non-NULL `pParameter` is now rejected with
  `CKR_MECHANISM_PARAM_INVALID`.
- **Rust NULL output pointer dereferences (NEW-M8/9/10):** Several Rust FFI entry
  points (`C_GetSlotList`, `C_OpenSession`, `C_GenerateKeyPair`, `C_GenerateKey`,
  `C_EncapsulateKey`, `C_DecapsulateKey`) wrote to caller-supplied output pointers
  without checking for NULL. Added `.is_null()` guards returning `CKR_ARGUMENTS_BAD`.
- **HMAC timing side-channel (NEW-M11):** `verify_hmac` used `==` comparison, which
  short-circuits on the first mismatching byte. Replaced with
  `subtle::ConstantTimeEq::ct_eq()` for a branch-free constant-time comparison.
- **KMAC timing side-channel (NEW-M12):** Same issue in the KMAC verify path in
  `ffi.rs`. Fixed with `subtle::ConstantTimeEq`.
- **SymDecryptUpdate length overflow (NEW-M13):** `ulEncryptedDataLen + remainingSize`
  could overflow `CK_ULONG` for large inputs. Added an explicit overflow check before
  the addition, returning `CKR_ENCRYPTED_DATA_LEN_RANGE` on overflow.
- **IV not zeroized on error paths (CR-05):** Six error exit paths in
  `OSSLEVPSymmetricAlgorithm::encryptInit` and `decryptInit` returned without
  calling `iv.wipe()`. The local `iv` ByteString now wipes on all error paths.

#### Build and supply chain — fixed

- **Default build type changed to Release (SC-09):** `CMakeLists.txt` now defaults
  to `Release` instead of `RelWithDebInfo`, removing DWARF debug info from production
  binaries.
- **`package-lock.json` added (SC-03):** Lock file committed for reproducible `npm ci`
  installs.
- **Cargo files added to npm package manifest (SC-08):** `rust/Cargo.toml` and
  `rust/Cargo.lock` included in the published `files` array.
- **Optional GPG verification for OpenSSL (SC-01):** `build-openssl-wasm.sh` now
  downloads the detached `.asc` signature and verifies it with `gpg --verify` when
  GPG is available. Emits a warning rather than a hard error when GPG is absent.
- **Cargo audit CI job (SC-04):** New `rust-audit` GitHub Actions job runs
  `cargo audit --deny warnings` to catch known CVEs in Rust dependencies on every push.
- **Compiler hardening flags (SC-05):** `-fstack-protector-strong` added for all
  non-Emscripten / non-MSVC targets; `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`
  added for Linux builds.
- **WASM maximum memory limit (WS-01):** Emscripten link flags now include
  `-sMAXIMUM_MEMORY=536870912` (512 MiB) to prevent unbounded WASM heap growth.
- **SECURITY.md WASM limitations section (WS-02/03):** New section documents inherent
  WASM security constraints: no secure memory, exposed linear memory API, no ASLR,
  recommended HTTP headers.

---

## [0.3.0] — 2026-03-22

### Added

- ACVP Validation Suite with deterministic PRNG support for both C++ and Rust engines
- `CKA_CHECK_VALUE` (KCV) on all generated and imported keys — both engines
- Rust WASM engine: pre-hash ML-DSA / SLH-DSA (10 variants each), KMAC-128/256,
  SP 800-108 Counter/Feedback KDF, HKDF
- `C_VerifySignatureInit` / `C_VerifySignature` pre-bound verification (PKCS#11 v3.2)
- `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated` (PKCS#11 v3.2)
- `C_MessageEncryptInit` / `C_EncryptMessage` / `C_DecryptMessage` (PKCS#11 v3.0)
- `C_SignMessageBegin` / `C_SignMessageNext` streaming message sign/verify
- `CKA_PUBLIC_KEY_INFO` (SPKI/DER encoding for public keys)
- `CKM_HKDF_DERIVE`, `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`
- ECDSA + RSA SHA-3 signature variants (`CKM_ECDSA_SHA3_*`, `CKM_RSA_SHA3_*_PKCS`,
  `CKM_RSA_SHA3_*_PKCS_PSS`)
- `CKM_PKCS5_PBKD2` — password-based key derivation (PKCS#5 v2.1)

### Fixed

- ACVP deterministic PRNG correctness (C++ and Rust engines)
- `C_DecryptMessageNext` null-buffer query consumed ciphertext
- `C_VerifySignatureFinal` did not work with ML-DSA mechanisms
- `CKP_SLH_DSA_*` and `CKM_HASH_SLH_DSA_*` constant values aligned with OASIS pkcs11t.h

---

## [0.2.0] — 2026-03-22

### Added

#### Rust WASM Engine

A second WASM engine built entirely in Rust (RustCrypto backend, no C/OpenSSL dependency).
Both engines expose the same `SoftHSMModule` interface, so existing code works with either one.

| | C++ / Emscripten | Rust |
| --- | --- | --- |
| Binary size | ~2.2 MB | **~1.4 MB** |
| Crypto backend | OpenSSL 3.6 | RustCrypto crates |
| Pre-hash ML-DSA / SLH-DSA | Yes (10 variants each) | **Yes (10 variants each)** |
| Build toolchain | Emscripten + CMake | `wasm-pack` |

**Selecting an engine:**

```js
// C++ engine (default)
import { getSoftHSMCppModule } from '@pqctoday/softhsm-wasm'
const M = await getSoftHSMCppModule()

// Rust engine
import { getSoftHSMRustModule } from '@pqctoday/softhsm-wasm'
const M = await getSoftHSMRustModule()
```

Both return the same `SoftHSMModule` type — all `_C_*` function calls, `_malloc`, `_free`,
`HEAPU8`, `setValue`, and `getValue` work identically.

**Algorithms supported by the Rust engine:**

- **Post-quantum:** ML-KEM-512/768/1024, ML-DSA-44/65/87 (pure + 10 pre-hash variants each),
  SLH-DSA (all 12 parameter sets, pure + 10 pre-hash variants each)
- **Classical:** RSA (PKCS#1 v1.5 / OAEP / PSS), ECDSA P-256/P-384 (+ SHA-3 variants), Ed25519, ECDH P-256, X25519
- **Symmetric:** AES-128/192/256 (GCM, CBC, Key Wrap)
- **Digest / MAC:** SHA-256/384/512, SHA3-256/512, HMAC-SHA256/384/512, HMAC-SHA3-256/512, KMAC-128/256
- **Key derivation:** HKDF (RFC 5869), PKCS#5 PBKDF2, SP 800-108 Counter/Feedback KDF

#### New mechanisms (C++ engine)

**Key derivation:**

- **HKDF** (`CKM_HKDF_DERIVE`) — HMAC-based extract-and-expand key derivation (RFC 5869)
- **SP 800-108 Counter KDF** (`CKM_SP800_108_COUNTER_KDF`) — NIST key-based KDF using
  counter mode, commonly used for deriving multiple keys from a master key
- **SP 800-108 Feedback KDF** (`CKM_SP800_108_FEEDBACK_KDF`) — NIST key-based KDF using
  feedback mode, where each block's output feeds into the next derivation
- **Cofactor ECDH** (`CKM_ECDH1_COFACTOR_DERIVE`) — ECDH key agreement that multiplies
  the shared secret by the curve cofactor, preventing small-subgroup attacks

**Pre-hash signatures — SLH-DSA:**

10 pre-hash variants that hash the message before signing, useful when the message
is large or when you need a specific hash algorithm for compliance:
`CKM_HASH_SLH_DSA_SHA224`, `CKM_HASH_SLH_DSA_SHA256`, `CKM_HASH_SLH_DSA_SHA384`,
`CKM_HASH_SLH_DSA_SHA512`, `CKM_HASH_SLH_DSA_SHA3_224`, `CKM_HASH_SLH_DSA_SHA3_256`,
`CKM_HASH_SLH_DSA_SHA3_384`, `CKM_HASH_SLH_DSA_SHA3_512`, `CKM_HASH_SLH_DSA_SHAKE128`,
`CKM_HASH_SLH_DSA_SHAKE256`

**SHA-3 signature variants:**

- ECDSA with SHA-3: `CKM_ECDSA_SHA3_224/256/384/512`
- RSA PKCS#1 v1.5 with SHA-3: `CKM_RSA_SHA3_224/256/384/512_PKCS`
- RSA-PSS with SHA-3: `CKM_RSA_SHA3_224/256/384/512_PKCS_PSS`
- Password-based key derivation: `CKM_PKCS5_PBKD2`

#### New PKCS#11 APIs (C++ engine)

**Streaming message sign/verify** (PKCS#11 v3.2 §5.8) — sign or verify data in
chunks without buffering the entire message:

- `C_SignMessageBegin` / `C_SignMessageNext`
- `C_VerifyMessageBegin` / `C_VerifyMessageNext`

**Per-message AES-GCM encrypt/decrypt** (PKCS#11 v3.0) — encrypt multiple messages
under the same key in a single session, with automatic per-message IV management:

- `C_MessageEncryptInit` → `C_EncryptMessage` (one-shot) or
  `C_EncryptMessageBegin` / `C_EncryptMessageNext` (streaming) → `C_MessageEncryptFinal`
- Matching decrypt: `C_MessageDecryptInit` → `C_DecryptMessage` /
  `C_DecryptMessageBegin` / `C_DecryptMessageNext` → `C_MessageDecryptFinal`

**Pre-bound signature verification** (PKCS#11 v3.2) — bind a signature to the session
first, then supply data to verify against. Useful when the signature arrives before the data:

- `C_VerifySignatureInit` / `C_VerifySignature` (one-shot)
- `C_VerifySignatureUpdate` / `C_VerifySignatureFinal` (multi-part)

**Authenticated key wrap/unwrap** (PKCS#11 v3.2) — export and import keys with
AES-GCM integrity protection, ensuring the wrapped key hasn't been tampered with:

- `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated`

**Session management** (PKCS#11 v3.0):

- `C_LoginUser` — extended login with user type parameter
- `C_SessionCancel` — cancel an active multi-part operation

**Other:**

- `CKA_PUBLIC_KEY_INFO` attribute — retrieve a public key in standard SubjectPublicKeyInfo
  (SPKI / DER) encoding, as used in X.509 certificates

#### CKA_CHECK_VALUE (KCV) — both engines

All generated and imported keys now include a `CKA_CHECK_VALUE` attribute
(PKCS#11 v3.2 §4.10.2), enabling key integrity and identity verification without
exposing the key material:

- **Symmetric keys (AES):** first 3 bytes of AES-ECB encryption of a 16-byte zero block
- **Asymmetric keys (RSA, EC, EdDSA, ML-DSA, ML-KEM, SLH-DSA):** first 3 bytes of
  SHA-256 over the primary key material (modulus for RSA; public point for EC/EdDSA;
  raw bytes for PQC keys)
- **Imported keys** via `C_CreateObject` also receive a computed KCV
- Supported by both the C++ engine (`SoftHSM_keygen.cpp`, `SoftHSM_objects.cpp`)
  and the Rust engine (`state.rs: compute_kcv`)

#### ACVP test infrastructure — C++ engine

- Added `OSSLRNG_disableACVP()` to restore OpenSSL's default `RAND_OpenSSL()` method
  and release the internal cipher context after ACVP testing completes

### Fixed

- **ACVP deterministic PRNG — C++ engine:** Previous implementation repeated the
  32-byte seed cyclically with `buf[i] = seed[i % 32]` rather than generating a
  proper key-stream; now uses a ChaCha20 stream cipher (`EVP_chacha20`) seeded once
  and streamed continuously, matching the NIST ACVP test-vector generation process
- **ACVP deterministic PRNG — Rust engine:** Previous `with_rng!` macro created a
  fresh `ChaCha20Rng::from_seed(seed)` on every invocation, resetting the counter
  before each operation; now stores a persistent per-thread `ChaCha20Rng` in
  `ACVP_RNG` that advances its counter across operations, matching C++ engine behaviour
- Calling `C_DecryptMessageNext` with a null output buffer to query the required output
  size incorrectly performed the actual decryption, consuming the ciphertext
- `C_VerifySignatureFinal` / `C_VerifySignatureUpdate` did not work with ML-DSA mechanisms
- `C_DeriveKey` returned `CKR_MECHANISM_INVALID` for HKDF, SP 800-108, and cofactor ECDH
  mechanisms — these were registered but unreachable due to missing dispatch entries
- `C_GetMechanismInfo` returned incorrect capabilities for several SLH-DSA mechanisms
- `CKP_SLH_DSA_*` and `CKM_HASH_SLH_DSA_*` constant values aligned with the canonical
  `pkcs11t.h` header from OASIS (values were previously non-standard)

### Security

- **GCM authentication bypass in key unwrap** — `C_UnwrapKeyAuthenticated` did not
  validate the GCM authentication tag, allowing tampered wrapped keys to be imported.
  Now returns `CKR_ENCRYPTED_DATA_INVALID` on tag mismatch
- **Integer underflow in RSA-AES key unwrap** — crafted wrapped-key lengths could
  cause a negative-size subtraction leading to heap corruption
- **Integer overflow in symmetric encrypt** — large input buffers could overflow the
  output size calculation, causing an undersized allocation
- **Unbounded heap allocation from object store** — a malformed on-disk object file
  could trigger a multi-gigabyte allocation. Now capped at 64 MiB
- **Thread-safety race in token encryption** — concurrent access to the same token
  could corrupt internal AES cipher state. Each operation now uses an isolated cipher instance
- **Session state leak** — error paths in `C_FindObjectsInit` left the session locked
  in a find-operation state, preventing further operations until session close
- **Sensitive key material not wiped** — key data was not zeroed on object destruction.
  Now explicitly cleared from memory

---

## [0.1.0] — 2026

First public release of `@pqctoday/softhsm-wasm` — a PKCS#11 HSM emulator for
browsers and Node.js, with post-quantum cryptography support.

### Highlights

- **PKCS#11 v3.2** compliant interface (71 exported functions)
- **ML-KEM** (FIPS 203) — key encapsulation via `C_EncapsulateKey` / `C_DecapsulateKey`,
  ML-KEM-512/768/1024
- **ML-DSA** (FIPS 204) — digital signatures via `C_Sign` / `C_Verify`,
  ML-DSA-44/65/87, plus 10 pre-hash variants (`CKM_HASH_ML_DSA_*`)
- **SLH-DSA** (FIPS 205) — stateless hash-based signatures, all 12 SHA2/SHAKE parameter sets
- **One-shot message signing** — `C_MessageSignInit` / `C_SignMessage` /
  `C_MessageVerifyInit` / `C_VerifyMessage` (PKCS#11 v3.0)
- **Interface negotiation** — `C_GetInterfaceList` / `C_GetInterface` for
  runtime PKCS#11 version discovery
- **TypeScript declarations** included — full `SoftHSMModule` type with all `_C_*` functions
- **Constants module** — `import CK from '@pqctoday/softhsm-wasm/constants'` for all
  `CKM_*`, `CKA_*`, `CKR_*`, `CKK_*` values
- Works in modern browsers (Chrome, Firefox, Safari, Edge) and Node.js 18+

### Removed (vs SoftHSM2)

- GOST R 34.10 / R 34.11 algorithms
- DES / 3DES mechanisms
- Classical DSA and Diffie-Hellman key agreement
- OpenSSL ENGINE API (replaced with EVP-only backend)
- Autotools build system (replaced with CMake)

[Unreleased]: https://github.com/pqctoday/softhsmv3/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/pqctoday/softhsmv3/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pqctoday/softhsmv3/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pqctoday/softhsmv3/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pqctoday/softhsmv3/releases/tag/v0.1.0
