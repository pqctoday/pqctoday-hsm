/*
 * pkcs11_static.c — Static softhsmv3 linker shim for OpenSSH WASM build.
 *
 * OpenSSH's ssh-pkcs11.c calls dlopen("libsofthsmv3.so") at runtime.
 * In the WASM build there is no dynamic linker; softhsmv3 is statically
 * linked into the same binary.  This file intercepts the dlopen/dlsym/dlclose
 * calls made by ssh-pkcs11.c and routes them directly to the linked-in
 * C_GetFunctionList symbol.
 *
 * Pattern mirrors strongSwan's pkcs11_library.c SOFTHSM_STATIC_LINKED path.
 * Guard: only compiled when -DSOFTHSM_STATIC_LINKED and __EMSCRIPTEN__.
 */

#if defined(__EMSCRIPTEN__) && defined(SOFTHSM_STATIC_LINKED)

#include "includes.h"
#include <dlfcn.h>
#include <string.h>

/* Forward-declare softhsmv3's function-list entry point. */
extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/* Sentinel handle that ssh-pkcs11.c will pass back to dlsym/dlclose. */
#define SOFTHSM_FAKE_HANDLE  ((void *)0xSHSM)

void *dlopen(const char *filename, int flags) {
    (void)flags;
    /* Accept any name that looks like softhsmv3 */
    if (filename &&
        (strstr(filename, "softhsm") || strstr(filename, "libpkcs11"))) {
        return SOFTHSM_FAKE_HANDLE;
    }
    /* For anything else (e.g. OpenSSL providers loaded by pkcs11-provider)
     * return NULL — they are not needed in the WASM build. */
    return NULL;
}

void *dlsym(void *handle, const char *symbol) {
    if (handle == SOFTHSM_FAKE_HANDLE &&
        symbol && strcmp(symbol, "C_GetFunctionList") == 0) {
        return (void *)C_GetFunctionList;
    }
    return NULL;
}

int dlclose(void *handle) {
    (void)handle;
    return 0;
}

const char *dlerror(void) {
    return NULL;
}

#endif /* __EMSCRIPTEN__ && SOFTHSM_STATIC_LINKED */
