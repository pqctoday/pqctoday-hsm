# Systems Operations & Integration Guide

Welcome to the SoftHSMv3 Operations Guide. This document is intended for Systems Administrators, DevOps Engineers, and SREs looking to integrate `libsofthsm2.so` natively into third-party infrastructure components like OpenSSL, NGINX, or OpenVPN.

Because SoftHSMv3 was heavily modernized to support WebAssembly (WASM) and purely ephemeral cryptographic boundaries, its runtime architecture differs significantly from the legacy file-backed SoftHSMv2.

---

## 1. Critical Architectural Limitations

Before deploying SoftHSMv3 into a production pipeline, operators must understand the following structural shifts:

### A. In-Memory Only (Ephemeral Vault)
* **SoftHSMv2:** Managed an SQLite or flat-file state directory (`/var/lib/softhsm/tokens/`). Keys created by a CLI tool like `softhsm2-util` were permanently saved to the disk.
* **SoftHSMv3:** The token vault exists **exclusively in RAM**. If the host process attached to `libsofthsm2.so` terminates, the vault and all cryptographic materials inside it are instantly destroyed.

### B. Broken CLI Workflows
Because the token is ephemeral, using standalone command-line executions to configure the HSM will not work:
```bash
# THIS WILL NO LONGER WORK AS EXPECTED:
softhsm2-util --init-token --slot 0 --label "ProdToken"
pkcs11-tool --module libsofthsm2.so --keypairgen ...
```
When `pkcs11-tool` or `softhsm2-util` exits, the RAM boundary dies. If NGINX subsequently loads `libsofthsm2.so`, it boots into a completely blank, empty vault.

---

## 2. Daemonizing SoftHSMv3 via p11-kit

To use SoftHSMv3 with stateless third-party software (like a web server or short-lived scripts), you must wrap the library inside a dedicated, long-running daemon process. This daemon maps the RAM vault and serves it securely over a UNIX socket to your applications.

**1. Register the module with p11-kit**
Create `/etc/pkcs11/modules/softhsmv3.module`:
```ini
module: /usr/local/lib/libsofthsm2.so
managed: no
```

**2. Start a persistent p11-kit server**
```bash
# Submitting this to a systemd service is recommended
p11-kit server --provider /usr/local/lib/libsofthsm2.so \
    --name "softhsmv3-daemon" \
    pkcs11:
```

**3. Configure client processes**
The `p11-kit server` will emit a `PKCS11_MODULE_PATH` environment variable pointing to its socket bridge. Inject this variable into NGINX, OpenVPN, or OpenSSL. Those applications will now transparently talk to the daemon’s persistent RAM boundary over IPC rather than spinning up empty local vaults.

---

## 3. OpenSSL 3.x Provider Integration

SoftHSMv2 historically utilized `engine_pkcs11`, which is now strictly deprecated in OpenSSL 3.0+. SoftHSMv3 mandates **OpenSSL 3.6+** compliance, requiring the modern `pkcs11-provider` architecture.

**1. Install the Provider**
Ensure [pkcs11-provider](https://github.com/latchset/pkcs11-provider) (LATCHSET) is compiled and installed for your OpenSSL 3.x ecosystem.

**2. Update `openssl.cnf`**
Add the provider to your global OpenSSL configuration:
```ini
[provider_sect]
default = default_sect
pkcs11  = pkcs11_sect

[pkcs11_sect]
module = /usr/lib64/ossl-modules/pkcs11.so
pkcs11-module-path = /usr/local/lib/libsofthsm2.so # Or the p11-kit client proxy
```

**3. PKCS#11 URIs**
Once the OpenSSL provider is active, all 3.x compatible utilities (like NGINX) can reference key material purely by URI:
```text
ssl_certificate_key "pkcs11:token=ProdToken;object=MyPQCKey;type=private;";
```

---

## 4. Workarounds for Key Import

Because keys are lost on restart, Ops architectures currently demand a "bootstrapper" process:
1. The `p11-kit` server starts.
2. A bootstrap script uses `pkcs11-tool` against the daemon socket to inject static keys or generate fresh keypairs.
3. The dependent application (NGINX) is subsequently launched.

**Roadmap Note:** Engineering issues have been created to re-integrate persistent flat-file backing into the v3 C++ core to alleviate this complex daemon requirement.
