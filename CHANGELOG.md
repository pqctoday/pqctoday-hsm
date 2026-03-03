# Changelog

All notable changes to SoftHSMv3 are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `CONTRIBUTING.md` — PR process, code style, sanitizer build instructions
- `SECURITY.md` — vulnerability disclosure channel and security design notes
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1
- `CHANGELOG.md` — this file
- `softhsmv3.pc.in` — pkg-config template; `cmake --install` now installs
  `<libdir>/pkgconfig/softhsmv3.pc` so consumers can use `pkg-config --cflags --libs softhsmv3`
- Header install target: `cmake --install` now copies `pkcs11.h`, `pkcs11f.h`,
  `pkcs11t.h`, `cryptoki.h` to `<includedir>/softhsm/`
- `cmake/modules/CompilerSanitizers.cmake` — `-DENABLE_ASAN=ON`,
  `-DENABLE_UBSAN=ON`, `-DENABLE_TSAN=ON` options for debug/CI builds

### Fixed
- **P0 — Integer underflow in `UnwrapMechRsaAesKw`** (`SoftHSM.cpp`): Added
  bounds check before unsigned subtraction `wrappedLen2 = ulWrappedKeyLen -
  wrappedLen1`; returns `CKR_WRAPPED_KEY_LEN_RANGE` on underflow
- **P0 — Integer overflow in `SymEncryptUpdate`** (`SoftHSM.cpp`): Added
  overflow guard on `ulDataLen + remainingSize` before buffer allocation;
  returns `CKR_DATA_LEN_RANGE` on overflow
- **P1 — Session stuck in `SESSION_OP_FIND`** (`SoftHSM.cpp`): Three error
  paths in `C_FindObjectsInit` now call `session->resetOp()` before returning
  so that callers can retry the operation
- **P1 — `SecureDataManager` AES cipher race** (`SecureDataManager.cpp`):
  Removed shared `SymmetricAlgorithm* aes` member; each function now creates
  a per-call local AES instance eliminating use-without-lock races in
  multi-threaded token access
- **P2 — Unbounded heap allocation in `File::readByteString`** (`File.cpp`):
  Added 64 MiB sanity cap on length field read from untrusted on-disk object
  store; returns `false` with `ERROR_MSG` instead of calling `resize(len)` on
  a gigabyte-scale attacker-controlled value
- **P2 — `assert()` in production code** (`SlotManager.cpp`): Replaced two
  `assert()` calls (no-op in release builds) with defensive `ERROR_MSG` +
  `return CKR_GENERAL_ERROR` / slot discard; removed `<cassert>` include

---

## [3.0.0] — 2025-Q4

### Added
- **Phase 0**: Import SoftHSM2 v2.7.0 baseline; replace legacy autotools with
  CMake; drop ENGINE API; OpenSSL 3.x EVP-only backend
- **Phase 1**: Full OpenSSL 3.x EVP API migration; require OpenSSL ≥ 3.3;
  CI deprecated-API scan
- **Phase 2**: ML-DSA (FIPS 204 / PKCS#11 v3.2) sign/verify via OpenSSL EVP;
  `C_SignMessage` / `C_VerifyMessage` multi-part variants
- **Phase 3**: ML-KEM (FIPS 203 / PKCS#11 v3.2) `C_EncapsulateKey` /
  `C_DecapsulateKey`; SLH-DSA support
- **Phase 4**: Emscripten WASM target (`softhsm.js` + `softhsm.wasm`);
  Modularize=1 factory; PKCS11 v3.2 export list (71 C_* functions + malloc/free)
- **Phase 5**: npm package `@pqctoday/softhsm-wasm` with TypeScript declarations

[Unreleased]: https://github.com/pqctoday/softhsmv3/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/pqctoday/softhsmv3/releases/tag/v3.0.0
