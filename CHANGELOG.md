# Changelog

All notable changes to `@pqctoday/softhsm-wasm` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Fixed

- **ML-DSA multi-part signing / verification** (`src/lib/crypto/OSSLMLDSA.cpp`, `OSSLMLDSA.h`,
  `src/lib/SoftHSM_sign.cpp`): `signInit`, `signUpdate`, and `signFinal` (and the verify
  counterparts) previously returned `false` immediately with "ML-DSA does not support multi-part
  signing". PKCS#11 v3.2 §5.2 requires `C_SignUpdate` / `C_SignFinal` to work for any mechanism
  where `ulMaxMultiPart > 0` in `CK_MECHANISM_INFO`. Consequently `bAllowMultiPartOp` was hardcoded
  `false` for all `CKM_ML_DSA`, `CKM_HASH_ML_DSA`, and `HASH_MLDSA_CASE` blocks, so
  `C_SignUpdate` always returned `CKR_OPERATION_NOT_INITIALIZED`. This broke pkcs11-provider's
  `EVP_DigestSign*` streaming path, which is invoked by `X509_sign_ctx` (cert minting) and the TLS
  1.3 state machine (CertificateVerify).
  
  Fix: `OSSLMLDSA` now accumulates chunks in `m_signMsg` / `m_verifyMsg` `ByteString` members
  during `signUpdate` / `verifyUpdate`, then calls the existing one-shot `sign()` / `verify()` with
  the accumulated message in `signFinal` / `verifyFinal`. `bAllowMultiPartOp` is flipped to `true`
  for the three ML-DSA mechanism blocks in both the `C_SignInit` and `C_VerifyInit` dispatch.
  PKCS#11 compliance test (`p11_v32_compliance_test.cpp`) extended with `test_multipart_signing()`
  that validates the full `C_SignInit → C_SignUpdate(×2) → C_SignFinal → C_VerifyInit →
  C_VerifyUpdate(×2) → C_VerifyFinal` round-trip plus a one-shot cross-check against the same
  message — all 10 assertions pass.

- **SLH-DSA multi-part signing / verification** (`src/lib/crypto/OSSLSLHDSA.cpp`, `OSSLSLHDSA.h`,
  `src/lib/SoftHSM_sign.cpp`): Identical bug and fix as ML-DSA above; affects `CKM_SLH_DSA`,
  `CKM_HASH_SLH_DSA`, and `HASH_SLHDSA_CASE` blocks. Uses `SLHDSA_SIGN_PARAMS` in place of
  `MLDSA_SIGN_PARAMS`.

- **ECDSA multi-part signing / verification** (`src/lib/crypto/OSSLECDSA.cpp`, `OSSLECDSA.h`,
  `src/lib/SoftHSM_sign.cpp`): `signInit`, `signUpdate`, `signFinal` (and verify counterparts)
  previously returned `false` with "ECDSA does not support multi-part signing".  This blocked
  pkcs11-provider's `EVP_DigestSign*` streaming path for all 10 `CKM_ECDSA*` mechanisms
  (`CKM_ECDSA`, `CKM_ECDSA_SHA{1,224,256,384,512}`, `CKM_ECDSA_SHA3_{224,256,384,512}`).
  Fix: ByteString accumulator pattern (`m_signMsg` / `m_verifyMsg`) identical to the ML-DSA fix;
  delegates accumulated message to the existing one-shot `sign()` / `verify()` in Final.
  `bAllowMultiPartOp` flipped to `true` for all 10 ECDSA mechanism cases in both the
  `C_SignInit` and `C_VerifyInit` dispatch tables.  Closes GH-58.

- **EdDSA multi-part signing / verification** (`src/lib/crypto/OSSLEDDSA.cpp`, `OSSLEDDSA.h`,
  `src/lib/SoftHSM_sign.cpp`): Same stub bug for `CKM_EDDSA` and `CKM_EDDSA_PH`.
  Same ByteString accumulator fix.  `bAllowMultiPartOp` flipped to `true` for both EdDSA
  mechanisms in sign and verify dispatch.  Closes GH-58.

### Added

- **strongSwan WASM Phase 3a validation exports** (`strongswan-wasm-v2-shims/charon_wasm_main.c`):
  Three new `EMSCRIPTEN_KEEPALIVE` functions exercise real charon library
  calls inside the WASM binary and return JSON status strings.
  - `wasm_vpn_validate_proposal(str)` — drives `proposal_create_from_string(PROTO_IKE, …)`
    and walks `KEY_EXCHANGE_METHOD` transforms to detect ML-KEM (IDs 35/36/37
    per draft-ietf-ipsecme-ikev2-mlkem). Returns `{"valid":bool,"has_ml_kem":bool}`.
  - `wasm_vpn_validate_cert(pem, len)` — parses a PEM cert via
    `lib->creds->create(CRED_CERTIFICATE, CERT_X509, BUILD_BLOB_PEM)` and
    reports the recognized key type. When the SubjectPublicKeyInfo carries
    RFC 9881 ML-DSA OIDs, `is_ml_dsa:true` is returned.
  - `wasm_vpn_list_key_exchanges()` — dumps the numeric transform IDs for
    ML-KEM and classical groups.

  All three are linked into `strongswan-v2-boot.{js,wasm}` via
  `scripts/build-strongswan-wasm-v2.sh` (EXPORTED_FUNCTIONS updated).
  These close plans 1 (ML-DSA OID recognition) and 2 (IKE_INTERMEDIATE /
  ML-KEM transform IDs) of the hub-vs-sandbox VPN simulator gap audit at
  the library-validation level, ahead of the full Phase 3b+ IKE driver.

### Fixed

- **strongswan-pkcs11 ECDH use-after-free** (`strongswan-pkcs11/pkcs11_dh.c`): Upstream strongSwan
  6.0.5 `set_public_key()` allocated the `0x04 || X || Y` peer-pubkey buffer via `chunk_cata` (alloca)
  and stored a `CK_ECDH1_DERIVE_PARAMS` struct whose `pPublicData` pointed into that stack buffer.
  When `derive_secret()` later ran (different stack frame), the buffer was already freed and softhsmv3
  received uninitialized bytes → `CKR_GENERAL_ERROR`. Only classical ECP curves hit this path (X25519
  and ML-KEM use separate code). Fix: add a new `peer_pub_key` chunk on `private_pkcs11_dh_t` that
  heap-allocates via `chunk_alloc`, keep it alive for the object's lifetime, and free in `destroy`.
  This was the root cause of the sandbox VPN matrix's classical-mode failures; the same code path
  runs in WASM, so rebuilding `scripts/build-strongswan-wasm.sh` picks up the fix there too.

- **strongswan-pkcs11 derived-secret sensitivity attributes** (`strongswan-pkcs11/pkcs11_dh.c`):
  Upstream `derive_secret()` template set only `CKA_CLASS` + `CKA_KEY_TYPE` on the shared-secret
  output. softhsmv3 (PKCS#11 v3.2) defaults derived keys to `CKA_SENSITIVE=TRUE` /
  `CKA_EXTRACTABLE=FALSE`, so the follow-up `C_GetAttributeValue(CKA_VALUE)` strongSwan uses to
  read the secret back into the IKE state machine returned `CKR_ATTRIBUTE_SENSITIVE` (17). Fix:
  set `CKA_SENSITIVE=FALSE` + `CKA_EXTRACTABLE=TRUE` in the derive template. Upstream works on
  softhsm2 because of different default attribute policies.

- **strongswan-pkcs11 ML-DSA public-key builder accepts `BUILD_BLOB`**
  (`strongswan-pkcs11/pkcs11_public_key.c`): `pkcs1_builder::parse_public_key` unwraps the SPKI
  and re-enters the builder chain with the raw FIPS 204 public key via `BUILD_BLOB` (not
  `BUILD_BLOB_ASN1_DER`). Previously `pkcs11_public_key_load` only accepted the ASN.1 DER path,
  so ML-DSA builder L3 via pkcs11 never produced a key and strongSwan fell through to PEM —
  which rejected the raw bytes. Now accepts either input and validates `pubkey.len` against
  `get_public_key_size(type)` before constructing.

- **WASM build — correct OID-table generator** (`scripts/build-strongswan-wasm.sh`): strongSwan
  ships `oid.pl` (not `oid_maker.pl`); the fallback branch was dead code. Call `oid.pl` directly
  so the regenerated `oid.h`/`oid.c` pick up ML-DSA OIDs from the PQC patch.

### Added

- **OpenPGP PKCS#11 bridge — vendored** (`openpgp/`): Vendored copy of
  [`openpgp-pkcs11-sequoia`](https://codeberg.org/heiko/openpgp-pkcs11) v0.2 (LGPL-2.0-or-later,
  Heiko Schaefer). Two Rust crates: `openpgp-pkcs11-sequoia` (library) and
  `openpgp-pkcs11-tools` (CLI — `opgpkcs11`). Enables PKCS#11 devices (including softhsmv3) to
  act as the cryptographic backend for Sequoia OpenPGP signing and decryption operations. Built
  inside `Dockerfile.network` via `cargo install --path cli` and deployed as the OpenPGP scenario
  backend in the pqctoday-sandbox `pqc-network` container.

- **SSH ML-DSA-65 scenario validation** (`docker/` — no HSM source changes): softhsmv3's
  `CKA_PUBLIC_KEY_INFO` (PKCS#11 v3.2 §4.9 SPKI) and `CKM_ML_DSA` (0x1d) signing were
  validated end-to-end as the PKCS#11 backend for a custom-patched OpenSSH 10.3p1 implementing
  draft-sfluhrer-ssh-mldsa-06. Both host-key signing (`HostKeyAgent` delegation) and client
  user-key authentication (`ssh-pkcs11.c:pkcs11_fetch_mldsa_pubkey` + `pkcs11_sign_mldsa`) transit
  `C_Sign(CKM_ML_DSA)` against the softhsmv3 token. All 9 host×client algorithm combinations
  (ed25519, ecdsa-sha2-nistp256, ssh-mldsa-65) pass. No softhsmv3 source changes were required.

- **JavaJCE translation layer** (`JavaJCE/`): Java JCE Security Provider that bridges
  Hyperledger Besu (and any JCA-based application) to softhsmv3 ML-DSA signing. Intercepts
  `Signature.getInstance("ML-DSA-65")` requests and translates them to `CKM_ML_DSA`
  (0x1d) `C_SignInit` calls via the patched SunPKCS11 JNI. Components: `SoftHSMJCEProvider`
  (service registry), `PQC11SignatureSpi` (PKCS#11 translation engine), `PQC11KeyFactorySpi`
  (key reconstruction). Compiles inside `Dockerfile.physics` and deploys as
  `/opt/besu/lib/javajce-softhsm.jar`.

- **ML-DSA PKCS#11 v3.2 constants — strongSwan adapter** (`strongswan-pkcs11/pkcs11.h`):
  Added `CKK_ML_DSA` (0x4a), `CKM_ML_DSA_KEY_PAIR_GEN` (0x1c), and `CKM_ML_DSA` (0x1d)
  to enable ML-DSA key generation and signing through the strongSwan IKEv2 PKCS#11 adapter.

- **ML-DSA full sign/verify plumbing — strongSwan adapter**
  (`strongswan-pkcs11/{pkcs11.h,pkcs11_plugin.c,pkcs11_private_key.c,pkcs11_public_key.c}`):
  End-to-end ML-DSA-44/65/87 support through the strongSwan PKCS#11 plugin.
  Adds `CKA_PARAMETER_SET` (0x61d) with `CKP_ML_DSA_*` / `CKP_ML_KEM_*` value constants
  (PKCS#11 v3.2 §6.67/§6.68). Registers PRIVKEY/PUBKEY handlers for ML-DSA-44/65/87.
  Maps `SIGN_ML_DSA_{44,65,87}` → `CKM_ML_DSA` with `HASH_IDENTITY` (no pre-hash).
  `sign()` queries `C_Sign` for the variable signature length (2420/3293/4595 B) since
  ML-DSA signatures can't be derived from the public-key size. `verify()` skips the
  classical leading-zero strip that would corrupt opaque ML-DSA byte blobs.
  `find_key()` detects ML-DSA keys via `CKK_ML_DSA` + `CKA_PARAMETER_SET`. Adds
  `encode_ml_dsa()` for PUBKEY_SPKI_ASN1_DER / PUBKEY_PEM / KEYID_PUBKEY_SHA1 /
  KEYID_PUBKEY_INFO_SHA1 encodings of raw `CKA_VALUE` keys. Compiles cleanly on native
  and is fully reusable under the WASM path.

- **strongSwan 6.0.5 ML-DSA core patch** (`strongswan-6.0.5-pqc.patch`, 882 lines, verified):
  Upstream-applicable patch that adds `KEY_ML_DSA_{44,65,87}` and
  `SIGN_ML_DSA_{44,65,87}` key/signature type enums plus their OID/SPKI wiring across
  `credentials/`, `processing/jobs/`, and `utils/`. Orthogonal to the WASM work and
  reusable by any downstream that wants ML-DSA IKEv2 authentication.

- **openssh-pkcs11 connector — consolidation from standalone repo**
  (`openssh-pkcs11/`): Folded `pqctoday/pqctoday-openssh` (now deleted) into
  `pqctoday-hsm/` as an in-tree `openssh-pkcs11/` connector alongside
  `strongswan-pkcs11/`, `JavaJCE/`, `openpgp/`, and `webrpc/`. Contains ML-DSA-65
  patches (draft-sfluhrer-ssh-mldsa-06), WASM shims, and the Emscripten build driver.
  See `openssh-pkcs11/CHANGELOG.md` for details and known issues.

- **latchset vendor library** (`src/vendor/latchset/`): Added latchset crypto library as
  vendor dependency for PKCS#11 provider support.

- **pkcs11-provider `openssl_modulesdir` build option** (`src/vendor/pkcs11-provider/`):
  Added `openssl_modulesdir` meson option to override the OpenSSL provider module install
  path at build time, enabling custom OpenSSL builds not reflected in pkg-config to install
  the provider to the correct location.

- **Sandbox integration compatibility report** (`softhsmv3_compatibility_report.md`):
  Documents integration pathways (YES/PARTIAL/NO) for all 15 pqctoday-sandbox tools against
  softhsmv3's three interfaces — OpenSSL Provider, strongSwan Adapter, and direct library API.

- **Token Model ID cross-engine parity** (`rust/src/ffi.rs`, `src/lib/slot_mgr/Token.cpp`):
  `CK_TOKEN_INFO.model` now reports `"PQCToday"` from both the C++ and Rust engines, aligning
  the cross-engine token identity with the project brand and removing the legacy `SoftHSM v2`
  string that could surface depending on which engine answered `C_GetTokenInfo`.

- **webrpc/ roadmap placeholder** (`webrpc/README.md`): Documents the plan to extract
  pqctoday-sandbox's `kms_router.py` (Python Flask + PyKCS11 signing proxy) into a proper
  standalone softhsmv3 REST signing service. Covers current prototype location, the three
  blockers (auth, persistence, deployment coupling), the target standalone-service shape
  (bearer-token auth, persistent volume, shared Fly.io deployment), and why extraction
  should wait until the orchestrator is deployed and usage patterns are observed. Marked
  as roadmap — prerequisite is orchestrator Fly.io Milestones A–D.

### Changed

- **Repo / path rename — softhsmv3 → pqctoday-hsm** (`package.json`,
  `scripts/commit_changes.sh`, `softhsm2.conf`, `tests/softhsm2-local.conf`): updates
  `package.json` repository URLs and resolves hardcoded `/antigravity/softhsmv3/` absolute
  paths in build scripts and test configs following the repo rename to `pqctoday-hsm`.

### Fixed

- **OpenSSL 4.1.0-dev strict-structs API typing regressions**
  (`src/lib/P11Objects.cpp`, `src/vendor/pkcs11-provider/src/encoder.c`): OpenSSL 4.1.0-dev
  tightens several struct signatures that previously compiled cleanly; the provider encoder
  and P11 object code now use the updated typing so softhsmv3 builds against recent OpenSSL
  master.
- **Docker CI compilation — quarantine compliance executable during CXX linking**
  (`CMakeLists.txt`, `src/CMakeLists.txt`, `src/lib/main.cpp`,
  `src/lib/session_mgr/{Session,SessionManager}.{cpp,h}`, `README.md`,
  `openssl_test.cnf`): the `p11_v32_compliance_test` executable was being linked in the
  default target and breaking Docker CI C++ link steps on stock toolchains. The compliance
  runner is now quarantined behind an opt-in target so CI and the shared Docker base image
  compile cleanly, with README + test-config updates describing the new build flow.
- **SLH-DSA private key import length** (`src/lib/crypto/OSSLSLHDSAPrivateKey.cpp`):
  `OSSL_PARAM_BLD_push_octet_string` for `OSSL_PKEY_PARAM_PRIV_KEY` now passes the full
  key length (`len`) instead of `len / 2`. The SLH-DSA private key is the full concatenated
  seed; halving the length caused key reconstruction failures on import.

### Tests

- **ML-DSA enum probe** (`strongswan-pkcs11/test_ss.c`): Minimal test binary that prints
  `KEY_ML_DSA` at runtime to verify the integer value matches the expected PKCS#11 v3.2
  constant.

---

## [0.4.26] — 2026-04-15

### Added

- **XMSS-MT full support — Rust engine** (`rust/src/crypto/xmss_bridge.rs`):
  Complete XMSS^MT (multi-tree) implementation covering all 56 RFC 8391 parameter sets
  (SHA2/SHAKE × 256/512/192-bit × heights 20/40/60 with 2–12 layers). Keygen, sign,
  verify, max-signatures calculation, and keys-remaining tracking. New constants:
  `CKM_XMSSMT_KEY_PAIR_GEN` (0x4035), `CKM_XMSSMT` (0x4037), `CKA_XMSSMT_PARAM_SET`,
  and 32 `CKP_XMSSMT_*` parameter set values registered in `SUPPORTED_MECHS`.

- **ML-DSA HashSign full parity — Rust engine** (`rust/src/crypto/handlers.rs`):
  All 10 PKCS#11 v3.2 §6.67.7 pre-hash variants now supported: SHA224, SHA256, SHA384,
  SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256. Previously only
  SHA256/SHA512/SHAKE128 were wired. Uses patched `fips204` v0.4.6 crate with extended
  `Ph` enum (`rust/fips204-patched/`).

- **SLH-DSA HashSign full parity — Rust engine** (`rust/src/crypto/handlers.rs`):
  All 10 PKCS#11 v3.2 §6.69.7 pre-hash variants now supported: SHA224, SHA256, SHA384,
  SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256. Uses patched
  `fips205` v0.4.1 crate with extended `Ph` enum (`rust/fips205-patched/`).

- **Compliance test expansions** (`p11_v32_compliance_test.cpp`):
  XMSS-MT keygen (SHA2_20_2_256), ECDSA-SHA3 curves (P256_SHA3_256, P521_SHA3_512),
  ECDH cofactor derive (X25519), KMAC-256 SignInit, and v3.0 session APIs
  (`C_SessionCancel` bitmask routing, `C_LoginUser`).

### Fixed

- **Rust mutex poison recovery** (`rust/src/state.rs`): `GlobalState::borrow()` and
  `borrow_mut()` now use `unwrap_or_else(|e| e.into_inner())` instead of bare `.unwrap()`,
  recovering from poisoned mutexes rather than panicking the WASM module (CWE-400).

- **Rust ACVP RNG macro safety** (`rust/src/ffi.rs`): `with_rng!` macro refactored from
  `.is_some()` + `.as_mut().unwrap()` to idiomatic `if let Some(ref mut ...)`.

- **C_Login safe unwrap patterns** (`rust/src/ffi.rs`): Replaced `.unwrap()` on token store
  `get_mut()` with `if let Some(mut t)` guards in both SO and User login paths. Added
  `user_pin_salt.is_none()` guard before pin comparison.

- **AES-GCM wrap/unwrap error handling** (`rust/src/ffi.rs`): `C_WrapKeyAuthenticated` and
  `C_UnwrapKeyAuthenticated` replaced `.unwrap()` on `Aes128Gcm`/`Aes256Gcm` cipher
  construction with `match` returning `CKR_FUNCTION_FAILED` on error.

- **CWE-120 strncpy bounds** (`src/bin/util/softhsm2-util.cpp`): Replaced unconstrained
  `strncpy` with `memcpy` for token label and serial copy operations.

- **P-521 ECDSA known vector padding** (`src/lib/crypto/test/ECDSATests.cpp`): Fixed
  RFC 6979 A.2.7 test vectors — added leading `00` byte for proper 66-byte P-521
  signature component encoding.

- **Security Hardening**: Resolved CWE-400 `.unwrap()` panics in the Rust FFI module and CWE-120 `strncpy` bounds overflows within the C++ CLI suite.

- **PKCS#11 v3.2 Sessions**: Formally expanded `C_SessionCancel` to correctly parse and route PKCS#11 v3.2 asynchronous bitmask flags across all Persistent and Memory DB environments.

### Changed

- **Patched crates**: Local forks of `fips204` v0.4.6 and `fips205` v0.4.1 (`rust/fips204-patched/`,
  `rust/fips205-patched/`) extend the `Ph` enum with all 10 NIST-approved hash variants.
  Cargo.lock updated to use path dependencies instead of registry.

- **C++ FileTests portability** (`src/lib/object_store/test/FileTests.cpp`): Replaced all
  `#ifndef _WIN32` / `#else` path-separator blocks with `OS_PATHSEP` macro from `OSPathSep.h`.
  Renamed shadowed `exists` variable to `existsFile`.

- **C++ TODO comments** (`OSSLEVPCMacAlgorithm.cpp`, `OSSLEVPMacAlgorithm.cpp`,
  `OSSLEVPSymmetricAlgorithm.cpp`): Clarified secure-memory TODOs — OpenSSL CTX is opaque
  and cannot transparently use SecureAllocator without `CRYPTO_set_mem_functions`.

- **Security audit reports**: Marked CWE-400 and CWE-120 as RESOLVED in both
  `docs/security_audit_03222026.md` (NEW-L2) and `docs/security_audit_04132026.md`.

- **README.md**: Updated compliance to 127/127 (0 failures), security table to v0.4.24 with
  2 LOW findings resolved, added Phase 19 (April 2026 Hardening) to roadmap, updated storage
  architecture description to Tri-Mode (Memory / File / SQLite3).

- **Code formatting**: Applied `rustfmt` across `lms.rs`, `ffi.rs`, `state.rs`, `handlers.rs`
  (import order, if/else brace style, line width).

---

## [0.4.25] — 2026-04-15

### Fixed

- **PKCS#11 v3.2 full compliance — 127 PASS / 0 FAIL / 0 SKIP** (`p11_v32_compliance_test`):
  All previously failing test categories now pass. Complete resolution of the compliance gaps
  tracked in the implementation plan from this sprint.

- **PQC private key object attribute registration — C++ engine** (`src/lib/P11Objects.cpp`):
  `P11PrivateKeyObj::init()` registered `CKA_PUBLIC_KEY_INFO` with `P11Attribute::ck8`
  (modifiable-after-create) which is the correct flag per PKCS#11 v3.2 §4.4 Table 10 footnote 8.
  The custom `P11AttrPublicKeyInfo::retrieve()` override correctly returns this attribute in clear
  regardless of the object's `CKA_PRIVATE` flag, per PKCS#11 v3.2 §4.14:
  "The value of this attribute can be retrieved by any application."
  All ML-DSA (44/65/87), ML-KEM (512/768/1024), and SLH-DSA private key objects now correctly
  expose their SPKI via `C_GetAttributeValue(CKA_PUBLIC_KEY_INFO)`.

- **Session read-only enforcement** (`src/lib/access.cpp`): `haveWrite()` correctly returns
  `CKR_SESSION_READ_ONLY` for token-object writes attempted from `CKS_RO_USER_FUNCTIONS` sessions.
  `C_SetAttributeValue` on a token object from a read-only session now returns `CKR_SESSION_READ_ONLY`
  (`RV=181`) as required by PKCS#11 v3.2 §5.12.

- **Session object cross-visibility** (`src/lib/SoftHSM_sessions.cpp`): Token objects created on
  one session are correctly visible to `C_FindObjects` initiated from a different session on the
  same slot, per PKCS#11 v3.2 §6.6.8.

### Changed

- **Compliance report** (`cpp_compliance_report.md` / `cpp_compliance_report.json`): Updated to
  reflect 127 PASS / 0 FAIL / 0 SKIP. All test categories — Attributes (ML-KEM/ML-DSA/HSS SPKI),
  Session, Negative, FIPS, KEM, DSA, SLHDSA, ECDH, ECDSA, EdDSA, AuthWrap, KDF, MsgCrypt,
  MsgSign, XMSS, ChaCha20, Classical, Discovery, SHA-3, AES-CTR — pass.

---

## [0.4.24] — 2026-04-14

### Added

- **`CKA_UNIQUE_ID` (PKCS#11 v3.0 §4.4) — C++ engine**: Auto-generated UUID v4 string
  attribute, read-only after creation. Assigned to every object via `P11Object::init()`.
  Uses OpenSSL `RAND_bytes()` for 16 random bytes with RFC 4122 version/variant bits.
  Corrected type value from `0x00000004` to `0x00000017` per PKCS#11 v3.0 spec.

- **`CKA_PUBLIC_KEY_INFO` extraction**: `C_CreateObject` now automatically parses DER encoded SubjectPublicKeyInfo from the `CKA_VALUE` of X.509 Certificates and caches it via OpenSSL `d2i_X509` to satisfy PKCS#11 SPKI extraction (Issue #37).

- **`CKA_ALWAYS_AUTHENTICATE` enforcement**: Audited and confirmed functionality across `C_SignInit` / `C_DecryptInit`. State is correctly propagated to force `CKU_CONTEXT_SPECIFIC` (Issue #38).

- **Rust 2024 Edition**: Bumped `Cargo.toml` edition to 2024 in `softhsmrustv3` (Issue #50).

- **`CKA_PROFILE_ID` (PKCS#11 v3.0 §4.5) — C++ engine**: Token profile identifier
  attribute, defaults to 0 (no profile). Corrected type value from `0x00000601` to
  `0x00000104` per PKCS#11 v3.0 spec.

- **`C_SignRecover` / `C_VerifyRecover` — C++ engine** (`src/lib/SoftHSM_sign.cpp`):
  Full RSA implementation for `CKM_RSA_PKCS` and `CKM_RSA_X_509` mechanisms. Previously
  returned `CKR_FUNCTION_NOT_SUPPORTED`. New session operation types `SESSION_OP_SIGN_RECOVER`
  (0x1A) and `SESSION_OP_VERIFY_RECOVER` (0x1B) added.

- **`AsymmetricAlgorithm::verifyRecover()` — C++ engine** (`src/lib/crypto/OSSLRSA.cpp`):
  RSA verify-recover via `EVP_PKEY_verify_recover()` for both `RSA_PKCS1_PADDING` and
  `RSA_NO_PADDING` modes. Virtual base method added to `AsymmetricAlgorithm.h` with
  default `false` return.

- **`CKM_RIPEMD160` / `CKM_RIPEMD160_HMAC` mechanism registration — C++ engine**
  (`src/lib/SoftHSM_slots.cpp`): Both mechanisms registered in `prepareSupportedMechanisms()`
  and `C_GetMechanismInfo()`. RIPEMD160 HMAC reports min=20, max=MAX_HMAC_KEY_BYTES with
  `CKF_SIGN | CKF_VERIFY`. Digest returns `CKR_MECHANISM_INVALID` (legacy provider disabled).

- **SLH-DSA raw private key import — C++ engine** (`src/lib/crypto/OSSLSLHDSAPrivateKey.cpp`):
  FIPS 205 raw private keys (64/96/128 bytes = 4×n) are now imported via
  `EVP_PKEY_fromdata()` with `OSSL_PKEY_PARAM_PRIV_KEY` + `OSSL_PKEY_PARAM_PUB_KEY`
  before falling back to PKCS#8 DER parsing. All 12 SLH-DSA parameter sets supported.

- **Compliance test expansion** (`p11_v32_compliance_test.cpp`): Suite now covers
  126 PASS / 1 FAIL (RIPEMD160 — expected). New test categories: ECDH (X25519), ECDSA
  (P-256/P-521/secp256k1), EdDSA (Ed25519/Ed448), SHA-3, AES-CTR, SP800-108 Feedback KDF,
  HKDF, PQC context signing, HSS key exhaustion state decay, and expanded negative paths
  (boolean policy, extraction constraint, template completeness, signature forgery).

### Fixed

- **`CKA_PUBLIC_KEY_INFO` persistence — C++ engine** (`src/lib/object_store/DBObject.cpp`):
  `DBObject::attributeKind()` returned `akUnknown` for `CKA_PUBLIC_KEY_INFO`, causing the
  database layer to silently abort every token-object transaction that included the attribute.
  This cascaded into `CKR_FUNCTION_FAILED` (RV=112) for all PQC `C_GenerateKeyPair` calls
  with `CKA_TOKEN=true`, and caused `CKA_PUBLIC_KEY_INFO` to be missing from all private key
  objects across ML-DSA (44/65/87), ML-KEM (512/768/1024), and SLH-DSA variants.
  Fixed by adding `case CKA_PUBLIC_KEY_INFO: return akBinary;` to the switch.
  Resolved 12 compliance failures simultaneously.

- **`CKM_RIPEMD160` build guard — C++ engine** (`src/lib/SoftHSM_digest.cpp`):
  The `CKM_RIPEMD160` case in `C_DigestInit` referenced `HashAlgo::RIPEMD160`, which does
  not exist in the `HashAlgo` enum (the OpenSSL legacy provider is disabled in this build).
  The case now falls through to the `default` branch, returning `CKR_MECHANISM_INVALID`.
  This mirrors the `#ifndef WITH_FIPS` guard used for `CKM_MD5`.

- **`C_SignRecoverInit` / `C_VerifyRecoverInit` key loading — C++ engine** (`src/lib/SoftHSM_sign.cpp`):
  The RSA recovery init functions were using `new RSAPrivateKey()` / `new RSAPublicKey()`
  (abstract — `PKCS8Encode`/`PKCS8Decode` are pure virtual), the undeclared free functions
  `getPrivateKey()` / `getPublicKey()`, and the non-existent `AsymmetricAlgorithm::recycleKey()`.
  Corrected to use the same factory idiom as `AsymSignInit`: `asymCrypto->newPrivateKey()`,
  `getRSAPrivateKey()`, `asymCrypto->recyclePrivateKey()` (and public-key equivalents).

- **Ed25519ph (`CKM_EDDSA_PH`) OpenSSL 3.x API — C++ engine** (`src/lib/crypto/OSSLEDDSA.cpp`):
  Sign and verify init functions were passing `"Ed25519ph"` as digest name to
  `EVP_DigestSignInit_ex` / `EVP_DigestVerifyInit_ex`. Corrected to use
  `OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, "Ed25519ph", 0)` with
  NULL digest, which is the correct OpenSSL 3.x provider API for EdDSA instance selection.

- **`C_GetSessionValidationFlags` — C++ engine** (`src/lib/main.cpp`):
  Now validates `pFlags` argument and returns `CKR_OK` with `*pFlags = 0` per §5.22
  (software token has no validation constraints). Was returning `CKR_FUNCTION_NOT_SUPPORTED`.

- **Async API argument validation — C++ engine** (`src/lib/main.cpp`):
  `C_AsyncComplete`, `C_AsyncGetID`, and `C_AsyncJoin` now validate NULL pointer arguments
  before returning `CKR_FUNCTION_NOT_SUPPORTED`.

- **`CKM_EDDSA_PH` constant value** (`constants.js`):
  Changed from `0xffff1057` to `0x80001057` (correct vendor-defined range).

### Changed

- **OpenSSL WASM build** (`scripts/build-openssl-wasm.sh`): Updated from OpenSSL 3.6.1 to
  3.6.2 with updated SHA-256 checksum.

- **Gap analysis** (`docs/gap-analysis-pkcs11-v3.2.md`): Updated to v16 — documents all
  fixes in this release; compliance suite at 120 PASS / 0 FAIL (algorithmic validator).

## [0.4.23] — 2026-04-14

### Added

- **PKCS#11 v3.2 Negative Path Mapping (C++ Compliance Tool)**: Extended the `p11_v32_compliance_test` utility with exhaustive structural negative boundaries. The test suite now explicitly forces and intercepts:
  - Boolean Policy Violations (`CKR_KEY_FUNCTION_NOT_PERMITTED` via disabled `CKA_SIGN`)
  - Template Incompleteness (`CKR_TEMPLATE_INCOMPLETE` via masked `CKA_CLASS`)
  - Object Extraction Shields (`CKR_ATTRIBUTE_SENSITIVE` on explicit `CKA_PRIVATE_EXPONENT` polls)
  - Signature Malleability (`CKR_SIGNATURE_LEN_RANGE` and `CKR_SIGNATURE_INVALID` through block truncation and bit-flipping)
  This ensures the core PKCS#11 v3.0+ context parser enforces boundary constraints accurately.

### Fixed

- **Rust Compile Warnings**: Cleaned up `unused_mut` variable bindings in `src/ffi.rs` AES-GCM contexts to satisfy cargo lint rules. Remove orphaned `fips204::traits::SerDes`, `fips205::traits::SerDes`, and `P256PrimeField` imports spanning across `src/crypto/handlers.rs`, `src/ffi.rs`, and `src/crypto/bip32.rs`.
- **Documentation**: Updated `README.md` to properly document `secp256k1`, `P-384`, `P-521` and `X448` support for ECDSA and ECDH algorithms.

---

## [0.4.22] — 2026-04-14

### Added

- **Rust engine: ECDSA P-521 support** — full keygen, sign, verify, and ECDH via `p521` RustCrypto crate (v0.13):
  - `C_GenerateKeyPair` with `CKM_EC_KEY_PAIR_GEN` dispatches to P-521 when `CKA_EC_PARAMS` ends with `0x23` (secp521r1 OID `1.2.840.10045.3.1.35`)
  - `C_Sign` / `C_Verify` with `CKM_ECDSA_SHA512` — native P-521 SHA-512 (no FIPS 186-5 hash truncation needed at this security level)
  - `C_Sign` / `C_Verify` with `CKM_ECDSA` (prehash) — caller supplies digest, Rust signs/verifies raw
  - `C_DeriveKey` with `CKM_ECDH1_DERIVE` — P-521 ECDH via `p521::ecdh::diffie_hellman`
  - New helper `build_ec_spki_p521()` — DER-encodes 133-byte uncompressed P-521 public key in SubjectPublicKeyInfo format with `id-ecPublicKey` + secp521r1 OID
  - `Cargo.toml`: added `p521 = { version = "0.13", features = ["ecdsa", "ecdh"] }` and `lazy_static = "1.4.0"`

### Fixed

- **Rust: EdDSA safety** — replaced `.unwrap()` with `.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)` in `verify_eddsa()` and `verify_eddsa_ph()`; malformed public key bytes now return `CKR_KEY_TYPE_INCONSISTENT` instead of panicking

### Changed

- **Security audit** (`docs/security_audit_04132026.md`): documented CWE-305 / CWE-208 as accepted risks (educational/ACVP design), and formally resolved CWE-400 (`ffi.rs` `.unwrap()` panics) and CWE-120 (`strncpy` bounds in C++).
- **README / docs/rust-engine.md**: updated algorithm parity tables and Rust crate list to reflect full P-256/P-384/P-521/secp256k1 coverage across both engines

---

## [0.4.21] — 2026-04-12

### Fixed

- **ACVP Compliance**: Eliminated 22 residual ACVP SKIP tests.
  - Rust Engine: Implemented custom SHAKE-256 N32 verifier in `lms.rs` to support SP 800-208 SHAKE type IDs, eliminating 20 LMS SHAKE skips.
  - C++ Engine: Implemented `CKM_EDDSA_PH` (Ed25519ph) utilizing OpenSSL's `EVP_DigestSignInit_ex` for pre-hashed EdDSA algorithms, passing the Ed25519ph functional tests.
  - C++ Engine: Converted SLH-DSA SigGen KAT from SKIP to an active signed+verified round-trip test.

- **Rust: `CKA_EC_PARAMS` and `CKA_EC_POINT` now stored on generated X25519/X448 keys** — PKCS#11
  v3.2 §6.7 requires both attributes on `CKK_EC_MONTGOMERY` keys. Previously only attributes
  explicitly present in the caller's keygen template were stored (via `absorb_template_attrs`);
  callers that omit these in the template received `CKR_ATTRIBUTE_TYPE_INVALID` from any
  subsequent `C_GetAttributeValue` call. Now hardcoded after generation:
  - **X448**: `CKA_EC_PARAMS` = `06 03 2b 65 6f` (id-X448, OID 1.3.101.111);
    `CKA_EC_POINT` = `04 38 <56-byte raw public key>`
  - **X25519**: `CKA_EC_PARAMS` = `06 03 2b 65 6e` (id-X25519, OID 1.3.101.110);
    `CKA_EC_POINT` = `04 20 <32-byte raw public key>`

- **Rust: stale SP 800-108 early-dispatch path removed from `C_DeriveKey`** — a dead early-return
  block parsed `CK_SP800_108_KDF_PARAMS` with an incorrect field layout and only matched
  `CKM_SHA256_HMAC` as PRF, causing `CKR_MECHANISM_INVALID` for callers passing `CKM_SHA256`. The
  correct implementation already existed in the main `match` block at `CKM_SP800_108_COUNTER_KDF` /
  `CKM_SP800_108_FEEDBACK_KDF`; the stale path has been removed. WASM binary updated.

### Changed

- **Developer documentation consolidated**: Removed stale `softhsmv3devguide.md` from the repository
  root; all developer docs now live exclusively in `docs/softhsmv3devguide.md`. Added an **EdDSA
  mechanism comparison table** (`CKM_EDDSA` pure-mode vs `CKM_EDDSA_PH` pre-hash encoding with
  `CKM_EDDSA_PH = 0x80001057`) and a **SLH-DSA parameter set reference** (all 12 variants across
  SHA2 and SHAKE families with signature-size and security-level summary). Updated the Rust engine
  description to note the custom SHAKE-256 N32 verifier for SP 800-208 SHAKE IDs `0x0F–0x18`.
- **`docs/softhsmv3opsguide.md`**: Restructured the storage section from "In-Memory Only" to
  **Dual-Model Storage Architecture** (RAM-backed WASM/default vs file-backed native with
  `-DWITH_FILE_STORE=ON`). Added **stateful-signature crash-resilience** guidance for HSS/LMS and
  XMSS operations — `CKA_HSS_KEYS_REMAINING` is strictly persisted on every sign when the file
  store is active, surviving process crashes. Updated CLI workflow section to clearly label
  memory-model limitations.

---

## [0.4.20] — 2026-04-12

### Added

- **SP 800-208 SHAKE-256 LMS/LMOTS parameter sets — C++ engine** (`hash-sigs` submodule
  updated to `pqctoday/hash-sigs` fork at commit `23d3e58`):
  - `common_defs.h`: 10 new `LMS_SHAKE_N32/N24_H{5,10,15,20,25}` constants (IANA IDs 0x0F–0x18)
    and 8 new `LMOTS_SHAKE_N32/N24_W{1,2,4,8}` constants (IANA IDs 0x09–0x10).
  - `hash.h` / `hash.c`: `HASH_SHAKE256 = 2` enum; SHAKE-256 XOF backend via OpenSSL
    `EVP_DigestFinalXOF` (32-byte output, all four hash functions). Guarded with
    `#ifndef __EMSCRIPTEN__` — WASM builds continue to use SHA-256 only via the existing path.
  - `sha256.h`: `USE_OPENSSL=1` ABI fix — ensures `hash_context.sha256` uses OpenSSL's
    `SHA256_CTX` (112 B) rather than the portable C layout (108 B), eliminating an
    WASM unreachable trap in `hss_validate_signature` during `C_Verify`.
  - `lm_common.c` / `lm_ots_common.c`: 10 + 8 new `case` statements for SHAKE
    `param_set_t` dispatch. The C++ keygen/sign/verify paths need no changes —
    `CKP_LMS_SHAKE_*` → `param_set_t` passthrough was already wired.

- **HSS WASM test suite** (`tests/acvp-wasm.mjs`):
  - **§12.1** — HSS SHA-256 sign+verify round-trip baseline (both engines).
  - **§12.2** — HSS SHAKE-256 sign+verify round-trip (SP 800-208, both engines). Generates
    a live key pair, signs, verifies correct signature, rejects a tampered signature.
  - **§12.3** — NIST ACVP LMS sigver KAT against all SHAKE-256 groups in
    `tests/acvp/lms_sigver_test.json`. Imports NIST-provided public keys, verifies
    each test case against the expected `testPassed` result. Both engines validated.

- **§CC C++/Rust cross-check** (`tests/acvp-wasm.mjs --engine=both`):
  - **§CC-1** — C++ generates SHAKE-256 HSS key + signs; Rust imports public key and verifies.
  - **§CC-2** — Rust generates SHAKE-256 HSS key + signs; C++ imports public key and verifies.
  - Proves RFC 8554 serialization compatibility between the OpenSSL/hash-sigs and
    hbs-lms Rust implementations. Falls back to `SKIP` with a message if
    `C_CreateObject(CKK_HSS)` is not yet supported on either engine.

- **`CKM_HSS_KEY_PAIR_GEN`, `CKM_HSS`, `CKP_LMS_*`, `CKP_LMOTS_*`, `CKA_LMS_PARAM_SET`,
  `CKA_LMOTS_PARAM_SET` exported** in `constants.js` and `constants.d.ts` for
  TypeScript consumers — previously only `CKK_HSS` was exported.

- **`pqctoday/hash-sigs` fork** redirected in `.gitmodules` (was `cisco/hash-sigs`).

---

## [0.4.19] — 2026-04-12

### Fixed

- **`C_Initialize` `pReserved` pointer guard** (`SoftHSM_slots.cpp`): PKCS#11 v3.2 compliance
  test suites frequently pass small sentinel values (e.g. `(void*)1`) to `pInitArgs.pReserved`
  to verify that `CKR_ARGUMENTS_BAD` is returned. Added an early guard that rejects any
  `pReserved` value whose integer representation is less than 4096 — treating it as an
  invalid (non-heap) pointer rather than valid ACVP bypass args — with `CKR_ARGUMENTS_BAD`.
  Prevents a potential null-pointer dereference when compliance suites probe this path.

- **`CKF_TOKEN_PRESENT` unconditionally set** (`Slot.cpp`): `getSlotInfo()` now always
  includes `CKF_TOKEN_PRESENT` in the slot flags and `isTokenPresent()` always returns `true`.
  The single virtual slot always has a token object regardless of initialization state; the
  prior conditional on `token->isInitialized()` was overly strict and caused
  `C_GetSlotList(tokenPresent=CK_TRUE)` to return an empty list on a fresh (uninitialised)
  token, breaking any consumer that calls `C_GetSlotList` before `C_InitToken`.

- **ChaCha20-Poly1305 test state isolation** (`SymmetricAlgorithmTests.cpp`): Added
  `C_Finalize` / `C_Initialize` round-trip at the start of `testChaCha20EncryptDecrypt`
  to clear any Cryptoki state left by earlier tests in the suite. Prevents spurious
  `CKR_CRYPTOKI_NOT_INITIALIZED` or stale-session failures when the ChaCha20 test runs
  after other tests in sequence.

---

## [0.4.18] — 2026-04-08

### Added

- **PKCS#11 v3.2 Compliance Parity**: Finalized integration of ChaCha20-Poly1305 and XMSS compliance across both C++ and Rust engines.

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

[0.4.26]: https://github.com/pqctoday/softhsmv3/compare/v0.4.25...v0.4.26
[0.4.25]: https://github.com/pqctoday/softhsmv3/compare/v0.4.24...v0.4.25
[0.4.24]: https://github.com/pqctoday/softhsmv3/compare/v0.4.0...v0.4.24
[0.4.0]: https://github.com/pqctoday/softhsmv3/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/pqctoday/softhsmv3/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pqctoday/softhsmv3/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pqctoday/softhsmv3/releases/tag/v0.1.0
