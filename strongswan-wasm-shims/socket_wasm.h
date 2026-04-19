/*
 * socket_wasm.h — strongSwan socket plugin for Emscripten/WASM builds.
 *
 * Provides a socket_t implementation backed by a JavaScript-allocated
 * SharedArrayBuffer (SAB). Replaces the default BSD-socket plugin in
 * WASM builds where the browser has no real network stack.
 *
 * The JS worker sets up the SAB and passes it in via wasm_net_set_sab().
 * The plugin factory socket_wasm_create() is registered as a static
 * feature in daemon.c (#ifdef __EMSCRIPTEN__).
 */

#ifndef SOCKET_WASM_H_
#define SOCKET_WASM_H_

#ifdef __EMSCRIPTEN__

#include <plugins/plugin.h>
#include <network/socket.h>

/**
 * Create a socket_t instance backed by a JS SharedArrayBuffer.
 *
 * Registered with the plugin loader as a static feature via
 * PLUGIN_CALLBACK(socket_register, socket_wasm_create). The returned
 * pointer conforms to the socket_t interface (send/receive/get_port/
 * supported_families/destroy).
 *
 * @return socket_t* on success, NULL on failure.
 */
socket_t *socket_wasm_create(void);

/**
 * Tear down any WASM socket state (no-op in typical use — the socket
 * plugin is destroyed by the plugin loader — but exported for symmetry
 * with the worker.js API surface).
 */
void wasm_socket_destroy(void *this);

/**
 * Register the JS-allocated SharedArrayBuffer with the WASM socket
 * plugin. MUST be called before charon's receive loop starts.
 * The SAB layout matches strongswan_worker.js:
 *   [0..3]   int32 state    (0 = empty, 1 = ready, 2 = dropped)
 *   [4..7]   int32 length   (bytes in payload)
 *   [8..11]  uint32 src_ip  (network byte order)
 *   [12..15] uint16 src_port + padding
 *   [16..]   packet bytes   (MTU-bounded)
 *
 * @param sab_ptr pointer to the SAB-backed memory in the WASM heap
 *                (Module._wasm_net_sab is set by the worker during
 *                instantiateWasm before onRuntimeInitialized fires)
 */
void wasm_net_set_sab(void *sab_ptr);

#endif /* __EMSCRIPTEN__ */

#endif /* SOCKET_WASM_H_ */
