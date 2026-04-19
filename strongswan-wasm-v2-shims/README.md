# strongswan-wasm-v2-shims

Clean-slate Emscripten shims for strongSwan charon, modeled on the proven
`openssh-pkcs11/wasm-shims/` pattern (ASYNCIFY + MODULARIZE, single-thread
per WASM instance, SAB+Atomics ring buffer between two Web Workers).

Supersedes the (broken) `../strongswan-wasm-shims/` reconstruction.

## Files

| File | Role |
|---|---|
| `charon_wasm_main.c` | Replaces charon's `main()`. Custom init: `library_init`, plugin load, softhsmv3 static init, config injection from JS, single-daemon dispatch loop. |
| `socket_wasm.c` | POSIX socket API backed by two SABs between peer Workers (`init` ↔ `resp`). Each WASM instance sees one `FAKE_SOCKFD` (= 42) that `read()/write()` to the SAB ring. |
| `pkcs11_static.c` | Intercepts `dlopen("…softhsm…")` / `dlsym("C_GetFunctionList")` and routes to the statically-linked softhsmv3 symbol. |
| `posix_stubs.c` | No-op stubs for POSIX calls absent from Emscripten sysroot (res_*, initgroups, setgroups, utmp/wtmp, ptrace-adjacent). |

## Design notes

- **Threading:** single-threaded WASM + `charon.threads=1` in injected config.
  ASYNCIFY unwinds blocking reads. Each role (init, resp) runs in its own
  Web Worker; the two Workers exchange IKE packets via a pair of SABs.
- **Link strategy:** exclude `src/charon/charon.o` from the native `main`,
  wire our `charon_wasm_main.c` instead. Exported entry points
  (`wasm_vpn_boot`, `wasm_vpn_configure_json`, `wasm_vpn_initiate`,
  `wasm_vpn_get_result`, `wasm_vpn_shutdown`) are marked
  `EMSCRIPTEN_KEEPALIVE`.
- **No `strongswan-6.0.5-wasm.patch`.** The v1 reconstruction applied a
  682-line core patch that duplicated `settings_parser_load_string` with
  conflicting return types, causing the `array_destroy_function`
  invalid-function-pointer crash at `library_init` time. Clean upstream
  6.0.5 + `strongswan-6.0.5-pqc.patch` is sufficient.
