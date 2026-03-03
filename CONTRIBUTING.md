# Contributing to SoftHSMv3

Thank you for your interest in contributing. SoftHSMv3 is a security-critical
library — please read this guide before opening a pull request.

## Code of Conduct

All participants must follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to Contribute

- **Bug reports** — open a GitHub Issue with reproduction steps
- **Security vulnerabilities** — follow [SECURITY.md](SECURITY.md), do **not** file a public issue
- **Documentation** — typos, clarifications, and new examples are always welcome
- **Code** — see the process below

## Development Setup

### Prerequisites

| Tool | Minimum version |
|------|----------------|
| CMake | 3.16 |
| OpenSSL | 3.3 (native build) |
| Emscripten | 3.1.x (WASM build) |
| C++ compiler | C++17 (GCC 10+, Clang 14+, MSVC 2022+) |

### Native build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

### WASM build

```bash
bash scripts/build-wasm.sh
node tests/smoke-wasm.mjs
```

### Sanitizer build (strongly recommended before submitting)

```bash
cmake -B build-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_ASAN=ON \
  -DENABLE_UBSAN=ON \
  -DBUILD_TESTS=ON
cmake --build build-asan -j$(nproc)
ctest --test-dir build-asan --output-on-failure
```

## Pull Request Process

1. **Branch from `main`** — name your branch `feat/<topic>`, `fix/<topic>`, or `docs/<topic>`.
2. **One logical change per PR** — reviewers should be able to understand the purpose in one sentence.
3. **Add or update tests** — all new code paths must have corresponding CppUnit tests.
4. **Pass CI** — the PR must pass: build → lint → unit tests → E2E smoke test.
5. **Sign your commits** — by submitting you certify that you wrote the code and have the right to submit it under the BSD-2-Clause license.
6. **Update CHANGELOG.md** — add a line under `[Unreleased]` describing your change.

## Code Style

- **C++17** — no C++20 features (WASM toolchain constraint)
- **Indentation** — tabs, matching the existing source
- **Error handling** — use `ERROR_MSG(...)` for all error paths; return `CKR_*` codes from PKCS#11 functions
- **No `assert()` in production code** — use defensive checks with `ERROR_MSG` + `return CKR_GENERAL_ERROR`
- **Memory** — prefer `ByteString` and RAII; call `CryptoFactory::i()->recycle*()` at every exit path when holding crypto objects
- **No shared mutable state** — per-call local crypto algorithm instances (see `SecureDataManager` for the pattern)

## Roadmap

Feature work follows the phase roadmap tracked in GitHub Issues:

- Phase 0–6 are described in [README.md](README.md)
- New PQC algorithm support lands in Phase 2+
- WASM-specific changes go in Phase 4–5

## License

By contributing, you agree that your contributions will be licensed under the
[BSD 2-Clause License](LICENSE).
