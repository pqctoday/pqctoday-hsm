# PQCToday Sandbox Tools ↔ SoftHSMv3 Integration Strategy

This document answers the core question: **Can we integrate the 15 tools listed in the Sandbox `/docs` with `softhsmv3`?** 

Using the specific components available in your `softhsmv3` repository — the **OpenSSL Provider**, the **strongSwan Adapter**, and the **SoftHSMv3 Library** directly — here is the definitive integration pathway for every tool.

### 🟢 YES - Can be integrated completely

| Tool / Document | Integration Interface | How it integrates with your softhsmv3 repo |
| :--- | :--- | :--- |
| **01-tls-openssl** (`OpenSSL CLI`) | **OpenSSL Provider** | OpenSSL v3.6.2 natively delegates `OSSL_OP_KEM` queries to your `pkcs11-provider`, which proxies to `SoftHSMv3`. |
| **03-vpn-strongswan** (`strongSwan`) | **strongSwan Adapter** | Integrates directly via your `strongswan-pkcs11` adapter. The adapter intercepts IKEv2 Key Exchange and calls `C_EncapsulateKey` on the `SoftHSMv3 Library`. |
| **04-pki-easyrsa** (`Easy-RSA`) | **OpenSSL Provider** | Since `easyrsa` is purely a bash wrapper for the `openssl` binary, it automatically routes through your `pkcs11-provider` to perform PKI operations. |
| **11-nginx-pqc-tls** (`Nginx`) | **OpenSSL Provider** | Nginx statically links to OpenSSL. Configuring `nginx.conf` to utilize the `pkcs11-provider` forces all TLS 1.3 KEM and ML-DSA signatures to run in `SoftHSMv3`. |
| **12-dnssec-pqc** (`ldnsutils`) | **OpenSSL Provider** | `ldnsutils` inherently utilizes OpenSSL's EVP framework. It transparently uses the `pkcs11-provider` to execute ML-DSA signing in the token. |
| **13-smime-pqc** (`S/MIME`) | **OpenSSL Provider** | Executed purely through the OpenSSL CLI, securely routing through the `pkcs11-provider`. |
| **14-cloud-kms-pqc** (`pkcs11-tool`) | **SoftHSMv3 API Directly** | Integrates *directly* against the native PKCS#11 `libsofthsm3.so` interface to test native `C_EncapsulateKey` functionality. |

### 🟡 PARTIAL - Can be integrated with limitations
| Tool / Document | Integration Interface | How it integrates with your softhsmv3 repo |
| :--- | :--- | :--- |
| **02-ssh-openssh** (`OpenSSH`) | **OpenSSL Provider** *(Warning)* | OpenSSH relies on OpenSSL but explicitly hardcodes its supported KEM logic. While the `pkcs11-provider` is available, OpenSSH suppresses generic KEM offloading. Code patching of `ssh-agent` is required. |
| **10-openqkd-network** (`cqptoolkit`) | **OpenSSL Provider** *(Indirect)* | If the QKD Toolkit calls `openssl` binaries to wrap its derived strings with ML-KEM, it can route through the `pkcs11-provider`. |
| **15-crypto-discovery** (`testssl.sh`) | **Passive Monitoring** | These are inspection tools. They do not connect to `SoftHSMv3` directly. They verify that the tools above (like Nginx) *did* negotiate PQC correctly. |

### 🔴 NO - Cannot be integrated with these interfaces
These 5 tools use entirely different software paradigms (Rust WASM, Go Cgo, Python Simulators) that structurally bypass PKCS#11 and OpenSSL Providers.

| Tool / Document | Why it cannot interface with `softhsmv3` |
| :--- | :--- |
| **05-codesigning-sequoia** (`Sequoia`) | Written in Rust parsing native `cryptoki`. It completely bypasses OpenSSL, and its PKCS#11 logic lacks the v3.2 mapping macros. |
| **06-did-iota** (`IOTA identity.rs`) | Rust-based WASM library using static `ring` and `dalek`. Cannot map to `libsofthsm3.so` without a custom Rust FFI wrapper. |
| **07-web3-ethereum** (`Geth Clef`) | Written in Go utilizing hardcoded `secp256k1` Cgo wrappers. It fundamentally lacks a PKCS#11 dynamic linkage module. |
| **08-qkd-netsim** (`ns-3`) | A pure C++ physics simulator measuring photon loss. Does not instantiate cryptographic keys. |
| **09-sequence-network** (`SeQUeNCe`) | A pure Python simulator of quantum repeaters. No integration point for HSM cryptographic offloading. |
