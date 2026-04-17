# PQC Migration Guide: Porting SLH-DSA to Upstream Latchset

This guide formally scopes the steps required to port the proprietary **SLH-DSA** mechanisms from your legacy `softhsmv3` PQC fork into the newly vendored upstream `latchset` codebase.

## 1. Mechanism Identification (`pkcs11.h`)
The upstream `latchset` provider strictly targets OASIS PKCS#11 v3.0+.
You must define the proprietary `CKM_SLHDSA_...` and `CKK_SLHDSA` macro constants inside `src/pkcs11.h` (or wherever your `p11-kit` headers are pulled from) so the mechanisms are legally recognized by the routing logic.

## 2. Key Management (`src/kmgmt/slhdsa.c`)
Upstream `latchset` has completely refactored their Key Management engine into the modular `src/kmgmt/` subdirectory.
- Create `src/kmgmt/slhdsa.c`.
- Hook it up to `src/kmgmt/common.c` to register the `EVP_PKEY_SLHDSA` algorithm identifier.
- Map the OSSL parameters (public key bounds, private key bounds, security categories) identical to how `mlkem.c` currently functions.

## 3. Signature Interface (`src/sig/slhdsa.c`)
The signature execution layer must be registered.
- Port your old `src/sig/slhdsa.c` logic into the new upstream structure.
- You must bind `slhdsa_sign_init` and `slhdsa_sign` to OpenSSL's provider dispatch tables natively inside `src/provider.c`.

## 4. Meson Build System (`src/meson.build`)
Add the newly created `src/kmgmt/slhdsa.c` and `src/sig/slhdsa.c` source files to the `pkcs11_provider_sources` array so they are compiled natively when `-Dopenssl_modulesdir` is executed.
