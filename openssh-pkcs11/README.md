# openssh-pkcs11

OpenSSH PKCS#11 connector for softhsmv3. ML-DSA-65 patches and WASM build
scaffolding implementing [draft-sfluhrer-ssh-mldsa-06](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/).

This subfolder contains the minimal custom code needed to:

1. Patch `openssh-portable` with an ML-DSA-65 key/signature type
   (`ssh-mldsa-65`).
2. Drive signing through the softhsmv3 PKCS#11 backend provided by the parent
   `pqctoday-hsm` repo (`CKM_ML_DSA`, 0x1d).
3. Compile both the client (`ssh`) and a privsep-free server
   (`sshd_wasm_main.c`) to WebAssembly for in-browser demos in
   [`pqctoday-hub`](https://github.com/pqctoday/pqctoday-hub).

## Layout

| Path | Description |
| --- | --- |
| [`patches/`](patches/) | `ssh-mldsa.c` (new key-type module) + `apply_mldsa_patches.py` (applies the source-tree patches to `openssh-portable`) |
| [`wasm-shims/`](wasm-shims/) | WASM-specific shims: `pkcs11_static.c` (static softhsmv3 linkage), `posix_stubs.c`, `socket_wasm.c` (SharedArrayBuffer transport), `sshd_wasm_main.c` (privsep-free server entry point) |
| [`scripts/`](scripts/) | `build-wasm.sh` (Emscripten build driver), `copy-to-hub.sh` (deploy WASM bundles to the hub app) |

`build/` and `dist/` are `.gitignore`'d — upstream OpenSSH sources and
generated WASM bundles live there but are rebuilt on demand (bundles ship via
the hub deploy pipeline, not git history).

## Build

Run from the `pqctoday-hsm/` repo root (after the softhsmv3 WASM archive and
OpenSSL WASM prefix have been built):

```bash
bash openssh-pkcs11/scripts/build-wasm.sh
bash openssh-pkcs11/scripts/copy-to-hub.sh
```

See the script headers for required environment variables (`OPENSSL_WASM`,
`SOFTHSM_WASM`, `HUB`).

## History

This connector previously lived as the standalone repo
`pqctoday/pqctoday-openssh`. It has been folded into `pqctoday-hsm` alongside
the other PKCS#11 consumers (`strongswan-pkcs11/`, `JavaJCE/`, `openpgp/`,
`webrpc/`) so that all HSM connectors are maintained together.

## License

BSD 2-Clause — see [`LICENSE`](LICENSE). Files derived from `openssh-portable`
retain their upstream BSD/ISC terms.
