/*
 * pkcs11_static.c — Static softhsmv3 linker shim for strongSwan WASM build.
 *
 * strongSwan's pkcs11_library.c calls dlopen("libsofthsmv3.so") at runtime
 * to bind a PKCS#11 module.  In the WASM build there is no dynamic linker;
 * softhsmv3 is statically archived into the same binary at link time.  This
 * shim intercepts dlopen/dlsym/dlclose and routes them to the linked-in
 * softhsmv3 C_GetFunctionList symbol.
 *
 * Guard: only compiled under Emscripten.
 */

#ifdef __EMSCRIPTEN__

#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

/* PKCS#11 types — pkcs11_library.c will #include <pkcs11.h> which we don't
 * need here; we just need CK_RV + the function-list typedef for the extern. */
typedef unsigned long CK_RV;
struct CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST **CK_FUNCTION_LIST_PTR_PTR;

/* Forward-declare softhsmv3's function-list entry point — statically linked. */
extern CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

/* Sentinel handle that strongSwan will pass back to dlsym/dlclose.
 * Any non-NULL value works; this one is mnemonic without being a valid hex. */
#define SOFTHSM_FAKE_HANDLE  ((void *)(uintptr_t)0x51050F03)  /* "SoftHsm3" */

void *dlopen(const char *filename, int flags) {
    (void)flags;
    if (filename &&
        (strstr(filename, "softhsm") ||
         strstr(filename, "libpkcs11") ||
         strstr(filename, "libsofthsmv3"))) {
        return SOFTHSM_FAKE_HANDLE;
    }
    /* Unknown module — the pkcs11 plugin will log and skip it. */
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

/* dlerror() intentionally not overridden — Emscripten's libc provides one
 * that returns NULL for successful dl* calls, which matches our behavior. */

#endif /* __EMSCRIPTEN__ */
