# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x (main) | Yes |
| 2.x (upstream SoftHSM2) | No — report to [opendnssec/SoftHSMv2](https://github.com/opendnssec/SoftHSMv2) |

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Please report security issues via **GitHub's private security advisory** feature:

1. Go to <https://github.com/pqctoday/softhsmv3/security/advisories>
2. Click **"New draft security advisory"**
3. Fill in the title, severity, description, and steps to reproduce

We aim to acknowledge reports within **2 business days** and provide a fix
timeline within **7 business days** for critical issues.

## Scope

Issues in scope:
- Memory safety bugs (use-after-free, buffer overflow, integer overflow/underflow) in the PKCS#11 layer or crypto backend
- Cryptographic weaknesses introduced by this fork (not upstream OpenSSL/SoftHSM2 issues)
- PIN or key material leakage via timing side-channels, logging, or improper memory clearing
- WASM build issues that expose secret key material to JavaScript callers beyond the intended API

Out of scope:
- Vulnerabilities in OpenSSL itself (report to <https://openssl.org/policies/general/security-policy.html>)
- Attacks requiring physical access to the host system
- Denial-of-service via resource exhaustion (treat as a regular bug)

## Security Design Notes

- Key material is stored masked in memory (`SecureDataManager`) with per-operation local AES instances to avoid shared cipher state races
- `SecureAllocator` + `mlock()` prevent secret buffers from being swapped to disk
- PBE key derivation uses PBKDF2-SHA256 with a random 256-bit salt per wrapped key blob
- PKCS#11 v3.2 `C_EncapsulateKey` / `C_DecapsulateKey` use ML-KEM (FIPS 203) via OpenSSL EVP
- All EVP contexts are freed on every code path; no ENGINE API is used

## Disclosure Policy

Once a fix is merged and released, we will:
1. Publish a GitHub Security Advisory with full details
2. Add an entry to [CHANGELOG.md](CHANGELOG.md) under the release version
3. Tag a new release within 24 hours of the advisory publication
