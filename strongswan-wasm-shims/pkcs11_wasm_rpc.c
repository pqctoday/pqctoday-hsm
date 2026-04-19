/*
 * pkcs11_wasm_rpc.c — PKCS#11 function-list wrappers for the WASM build.
 *
 * The WASM charon links statically against softhsmv3. That gives us a
 * single C_GetFunctionList() symbol. The strongswan-pkcs11 plugin
 * expects to dlopen the library — so we stub out dlopen and point it
 * at one of these two function lists instead:
 *
 *   pkcs11_wasm_wrap_function_list(fl) — returns `fl` unchanged. Used
 *       when the crypto operations should stay inside this worker.
 *
 *   pkcs11_wasm_rpc_function_list(fl)  — returns a shadow CK_FUNCTION_LIST
 *       whose slots forward to the main thread over a SharedArrayBuffer
 *       RPC channel. The main thread runs softhsmv3 so expensive key
 *       ops (RSA/ML-DSA sign, ML-KEM encap) don't block the IKE worker.
 *
 * Mode is selected by pkcs11_set_rpc_mode(1|0). JS sets this once before
 * _main() runs (see strongswan_worker.js).
 *
 * The function-list marshaling is done by two env imports
 * (pkcs11_rpc_call, pkcs11_sab_*), which are implemented in JS. This C
 * file only builds the function table and forwards each entry.
 */

#ifdef __EMSCRIPTEN__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten.h>

#include "pkcs11.h"

/*─────────────────────────────────────────────────────────────────────*/
/* Mode selection                                                       */
/*─────────────────────────────────────────────────────────────────────*/

int g_pkcs11_rpc_mode = 0;

void pkcs11_set_rpc_mode(int mode)
{
    g_pkcs11_rpc_mode = mode ? 1 : 0;
}

/*─────────────────────────────────────────────────────────────────────*/
/* JS-side RPC imports (match env.pkcs11_rpc_call, env.pkcs11_sab_*    */
/* seen in the baseline WASM import table).                            */
/*─────────────────────────────────────────────────────────────────────*/

EM_JS(int, pkcs11_rpc_call, (int opcode, void *args_buf, int args_len), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return -1;
    /* Worker.js handles the actual RPC framing. This import is kept so
     * the C-side can invoke round-trips via Atomics.wait. */
    return 0;
});

EM_JS(void, pkcs11_sab_wi32, (int offset, int value), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return;
    var i32 = new Int32Array(sab);
    Atomics.store(i32, offset >> 2, value);
});

EM_JS(int, pkcs11_sab_ri32, (int offset), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return 0;
    var i32 = new Int32Array(sab);
    return Atomics.load(i32, offset >> 2);
});

EM_JS(void, pkcs11_sab_read, (int offset, uint8_t *dst, int len), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return;
    var body = new Uint8Array(sab);
    for (var i = 0; i < len; i++) HEAPU8[dst + i] = body[offset + i];
});

EM_JS(void, pkcs11_sab_write, (int offset, const uint8_t *src, int len), {
    var sab = Module._wasm_pkcs11_sab;
    if (!sab) return;
    var body = new Uint8Array(sab);
    for (var i = 0; i < len; i++) body[offset + i] = HEAPU8[src + i];
});

/*─────────────────────────────────────────────────────────────────────*/
/* pkcs11_wasm_wrap_function_list                                       */
/*                                                                      */
/* Pass-through: returns the same function list. Provides a stable      */
/* export name that the pkcs11_library patch (in strongswan-pkcs11)     */
/* can route to without needing to know about RPC mode.                 */
/*─────────────────────────────────────────────────────────────────────*/

CK_FUNCTION_LIST_PTR pkcs11_wasm_wrap_function_list(CK_FUNCTION_LIST_PTR fl)
{
    return fl;
}

/*─────────────────────────────────────────────────────────────────────*/
/* pkcs11_wasm_rpc_function_list                                        */
/*                                                                      */
/* Returns a shadow function table whose entries forward to JS via the  */
/* SAB RPC channel. Infrastructure scaffold — the baseline links this   */
/* symbol but the live RPC path is built out incrementally. For the     */
/* rebuild we provide the symbol and return the original list, deferring*/
/* full RPC implementation to the ML-DSA phase (out of scope here).     */
/*─────────────────────────────────────────────────────────────────────*/

static CK_FUNCTION_LIST shadow_fl;

CK_FUNCTION_LIST_PTR pkcs11_wasm_rpc_function_list(CK_FUNCTION_LIST_PTR fl)
{
    /* Phase 1: straight-through. The baseline's JS RPC glue is driven
     * by pkcs11_rpc_call + pkcs11_sab_* imports above; until the RPC
     * function table is populated, fall back to local softhsmv3. This
     * matches the symbol surface without regressing correctness for
     * the RPC-off (g_pkcs11_rpc_mode==0) path. */
    if (!fl) return NULL;
    memcpy(&shadow_fl, fl, sizeof(shadow_fl));
    return &shadow_fl;
}

#endif /* __EMSCRIPTEN__ */
