# openssh-pkcs11 WASM build status

## Build infrastructure

**Status: working** as of 2026-04-26.

- `emcc 5.0.2` (Homebrew) tested; `OpenSSL 3.6.x WASM` and `softhsmv3` static
  archive both present at the paths the script expects.
- `bash openssh-pkcs11/scripts/build-wasm.sh` clones OpenSSH 10.3p1, applies
  the ML-DSA patches, runs autoreconf, runs emconfigure, and builds.
- A previously-blocking config.h leak (`HAVE_GETRRSETBYNAME 1` injected
  despite the `ac_cv_func_getrrsetbyname=no` cache override) is now patched
  out automatically in the build script (see Step 3.5).

## Current artifact state

The build produces `dist/openssh-server.{js,wasm}` and `dist/openssh-client.{js,wasm}`,
but the WASM is currently **structurally minimal** because:

1. `__wrap_sshd_main` (in `wasm-shims/sshd_wasm_main.c`) is the documented
   linker-`--wrap` entry point but only emits a `connection_ok:false`
   "scaffold" event — see lines 142–150 of that file.
2. The Emscripten link does not export `___wrap_sshd_main` to JS, so the
   resulting WASM cannot actually be driven from a JS worker even if the C
   code did the right thing.

## Hub-side fallback (already shipped)

While the WASM is incomplete, the hub at
`pqctoday-hub/src/wasm/openssh.ts` runs an honest TypeScript-driven
substitute:

- Real softhsmv3 PKCS#11 calls for every primitive (Ed25519, X25519, ML-KEM-768,
  ML-DSA-65, SHA-256).
- Real wire byte counts (1216 B hybrid KEX init, 1120 B reply, 3309 B ML-DSA
  signature, 32 / 64 B Ed25519).
- Real per-phase timings.
- All RFC 4253 / 4252 / draft-kampanakis / draft-sfluhrer message numbers and
  framing.

So the demo is not blocked on this WASM rebuild. The TS engine is the
operative production path; this WASM rebuild is a future credibility upgrade
that lets us claim "real OpenSSH C code in the browser" rather than
"real PKCS#11 calls behind synthesized SSH framing".

## What's left

To turn the build artifact into a JS-driveable real SSH stack:

1. **Export the entry point.** Add `'_main'` (or `'___wrap_sshd_main'`) to
   `EXPORTED_FUNCTIONS` in the `SHARED_LDFLAGS` array of `build-wasm.sh` so
   the linker preserves it. Without this, `__wrap_sshd_main` is dead code
   and stripped.

2. **Implement the SSH transport loop in `__wrap_sshd_main`.** The current
   placeholder needs to call into `kex_setup`, `kex_input_kexinit`,
   `kex_input_kex_dh_init`, `kex_send_kex_dh_reply`, etc. — driving the
   regular OpenSSH state machine over the SAB socket shim. Reference:
   `kex.c` and `serverloop.c` in the upstream tree.

3. **Wire the ML-DSA-65 host key.** Replace the privsep `mm_answer_sign`
   path with a direct `pkcs11_sign_mldsa` call against `g_host_key`
   (already loaded in `pkcs11_init`). Patch `auth-pubkey.c`'s
   `userauth_pubkey` to allow the static `authorized_keys` lookup.

4. **Surface PKCS#11 calls to JS.** Wrap the static `g_p11->C_Sign` etc.
   pointers with thin shims that emit `pkcs11_call` events through the
   existing `wasm_emit_event` callback so the hub UI can show real PKCS#11
   sequences (rather than relying on the JS-side logging proxy).

5. **Drive from JS.** Replace `pqctoday-hub/src/wasm/openssh.ts` with a
   thin wrapper that loads `createSshdModule()` + `createSshModule()`,
   creates two SharedArrayBuffer rings, and calls the exported
   `___wrap_sshd_main` / `__wrap_main` symbols.

Estimated effort: 1-2 days of focused OpenSSH-internals work for an
experienced contributor. The TS engine in the hub remains the operative
path until then.
