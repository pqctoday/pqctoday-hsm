# Changelog

All notable changes to the `openssh-pkcs11` connector are documented in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Changed

- **Relocated into `pqctoday-hsm` as `openssh-pkcs11/`.** Previously maintained
  in the standalone `pqctoday/pqctoday-openssh` repo; consolidated alongside
  the other PKCS#11 connectors (`strongswan-pkcs11/`, `JavaJCE/`, `openpgp/`,
  `webrpc/`). Build now runs from the hsm root:
  `bash openssh-pkcs11/scripts/build-wasm.sh`.

### Added

- **Initial release** — ML-DSA-65 patches and WASM build scaffolding for
  OpenSSH, implementing
  [draft-sfluhrer-ssh-mldsa-06](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/).
- **`patches/ssh-mldsa.c`** — new OpenSSH key-type module implementing the
  `ssh-mldsa-65` algorithm (NIST Category 3, FIPS 204). Public-key format is
  the raw 1,952-byte ML-DSA pk; signing is PKCS#11-only and delegates to
  `pqctoday-hsm` softhsmv3 via `CKM_ML_DSA` (0x1d).
- **`patches/apply_mldsa_patches.py`** — Python driver that applies the full
  set of source-tree patches to an extracted `openssh-portable` tree
  (`sshkey.c`, `ssh-pkcs11.c`, `Makefile.in`, etc.).
- **`wasm-shims/sshd_wasm_main.c`** — privsep-free `sshd` entry point for the
  WASM build. Replaces `fork()` / PAM / PTY / `setuid()` with a single-transport
  handshake running over a SharedArrayBuffer socket shim.
- **`wasm-shims/pkcs11_static.c`** — static `C_GetFunctionList` linkage against
  softhsmv3 so the WASM bundle ships self-contained without `dlopen`.
- **`wasm-shims/{posix_stubs,socket_wasm}.c`** — POSIX/networking stubs for
  Emscripten, bridging OpenSSH's file-descriptor I/O to the browser's
  SharedArrayBuffer transport.
- **`scripts/build-wasm.sh`** — end-to-end Emscripten build driver producing
  `openssh-client.{js,wasm}` and `openssh-server.{js,wasm}` bundles.
- **`scripts/copy-to-hub.sh`** — deploys built WASM bundles into the
  `pqctoday-hub` repo for the SSH ML-DSA-65 learning scenario.
