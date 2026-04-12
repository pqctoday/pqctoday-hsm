# Issue: Implement File-Based Persistence for Token Vault

## Component
Core Native C++ Build (`SoftHSM.cpp`, `ObjectStore.cpp`)

## Description
SoftHSMv3 was redesigned heavily around ephemeral WebAssembly (WASM) execution, migrating the entire object store exclusively to RAM. While this design is perfect for browsers and serverless JavaScript environments, it severely degrades the usability of the native `libsofthsm2.so` build for systems operations.

Currently, if an operator attempts to configure a Web Server (e.g. NGINX) or OpenVPN via standard PKCS#11 URIs, the daemon process spins up a completely blank `libsofthsm2.so` instance. All previously generated keys using `pkcs11-tool` or `softhsm2-util` disappear instantly upon CLI exit.

## Proposed Resolution
We need to re-introduce an optional file-based backing store for the native C++ build.

1. **Serialization Layer:** Implement a fast binary serialization format for `CKA_PARAMETER_SET` attributes and the massive PQC private key blobs (ML-DSA-87, XMSS, etc.).
2. **softhsm2.conf Registry:** Bring back logic to map `directories.tokendir=/var/lib/softhsm/tokens/` upon `C_Initialize`.
3. **Write-on-Commit:** Operations like `C_CreateObject` or `C_GenerateKeyPair` should asynchronously commit to the disk via SQLite (or flat files) strictly when the process runs with `-DWITH_FILE_STORE=ON`.
4. **WASM Independence:** Ensure that this macro logic entirely compiles *out* of the Emscripten workflow, guaranteeing our WASM binaries do not blow up in size with FS stubs.

## Impact
This restores total backward compatibility for Ops teams transitioning from SoftHSMv2, bypassing the requirement to wrap the tool in complex `p11-kit` IPC daemons.
