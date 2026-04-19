/*
 * socket_wasm.c — strongSwan socket plugin for Emscripten/WASM builds.
 *
 * Implements a socket_t backed by a JS SharedArrayBuffer. All network
 * I/O goes through two env imports:
 *   wasm_net_receive(buf,len, srcIp*,srcPort*, dstIp*,dstPort*) — blocking
 *   wasm_net_send   (buf,len, srcIp,  srcPort,  dstIp,  dstPort ) — fire-and-forget
 *
 * These are provided as EM_JS functions so Emscripten emits proper env
 * imports that the worker.js maps to JS closures reading/writing the SAB.
 *
 * See socket_wasm.h for ABI details.
 */

#ifdef __EMSCRIPTEN__

#include "socket_wasm.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <emscripten.h>
#include <daemon.h>
#include <networking/packet.h>
#include <networking/host.h>
#include <utils/chunk.h>

/* Maximum IKE packet size we'll ever read/write. Keep in sync with
 * strongswan_worker.js netInboxBytes region (SAB total size minus 16-byte
 * header). 64 KiB is more than enough for any IKE or IKE fragment. */
#define WASM_PACKET_MAX 65536

/**
 * JS-side inbound packet read. Blocks via Atomics.wait on the SAB state
 * cell until a packet is available. Returns bytes written to buf, or 0
 * on shutdown. The caller (receive()) converts buf + src/dst into a
 * strongSwan packet_t.
 *
 * Signature must match the baseline import exactly:
 *   (i32 buf, i32 len, i32 srcIpOut, i32 srcPortOut,
 *    i32 dstIpOut, i32 dstPortOut) -> i32 bytesRead
 */
EM_JS(int, wasm_net_receive, (uint8_t *buf, int buflen,
                              uint32_t *src_ip_out, uint32_t *src_port_out,
                              uint32_t *dst_ip_out, uint32_t *dst_port_out), {
    var sab = Module._wasm_net_sab;
    if (!sab) return 0;
    var hdr = new Int32Array(sab, 0, 4);
    var body = new Uint8Array(sab, 16);
    // Wait for state==1 (ready).
    while (Atomics.load(hdr, 0) !== 1) {
        Atomics.wait(hdr, 0, 0);
    }
    var len = Atomics.load(hdr, 1);
    if (len > buflen) len = buflen;
    // srcIp at u32[2], srcPort at u16[6] (packed: lower 16 bits).
    var srcIp   = Atomics.load(hdr, 2);
    var srcPort = Atomics.load(hdr, 3) & 0xffff;
    for (var i = 0; i < len; i++) HEAPU8[buf + i] = body[i];
    HEAPU32[src_ip_out   >> 2] = srcIp;
    HEAPU32[src_port_out >> 2] = srcPort;
    // Destination is always us — loopback bound_ip/port (0 = any).
    HEAPU32[dst_ip_out   >> 2] = 0;
    HEAPU32[dst_port_out >> 2] = 500;
    // Mark consumed and notify senders.
    Atomics.store(hdr, 0, 0);
    Atomics.notify(hdr, 0, 1);
    return len;
});

/**
 * JS-side outbound packet send. Non-blocking — the peer worker's
 * wasm_net_receive() will wake on Atomics.notify. Returns bytes sent
 * (same as len on success), or 0 if the SAB isn't set up yet.
 */
EM_JS(int, wasm_net_send, (const uint8_t *buf, int buflen,
                           uint32_t src_ip, uint32_t src_port,
                           uint32_t dst_ip, uint32_t dst_port), {
    // Peer SAB is reachable via the worker's peer-channel. In this
    // architecture the _same_ SAB is read by the peer worker (shared
    // memory between workers) — Module._wasm_net_sab is the outbound
    // SAB for this direction. The worker bootstrap wires it up.
    var sab = Module._wasm_net_sab;
    if (!sab) return 0;
    var hdr = new Int32Array(sab, 0, 4);
    var body = new Uint8Array(sab, 16);
    // Wait for the outbound slot to be free (state == 0).
    while (Atomics.load(hdr, 0) !== 0) {
        Atomics.wait(hdr, 0, 1);
    }
    var len = buflen;
    if (len > body.byteLength) len = body.byteLength;
    for (var i = 0; i < len; i++) body[i] = HEAPU8[buf + i];
    Atomics.store(hdr, 1, len);
    Atomics.store(hdr, 2, src_ip);
    Atomics.store(hdr, 3, (dst_port & 0xffff));
    Atomics.store(hdr, 0, 1);          // ready
    Atomics.notify(hdr, 0, 1);
    return len;
});

/*─────────────────────────────────────────────────────────────────────*/
/* socket_t implementation                                             */
/*─────────────────────────────────────────────────────────────────────*/

typedef struct private_socket_wasm_t private_socket_wasm_t;

struct private_socket_wasm_t {
    socket_t public;
    uint16_t port;
};

/* Global pointer into JS-shared memory — set by wasm_net_set_sab(). The
 * EM_JS helpers above read it directly from Module._wasm_net_sab which
 * the worker's instantiateWasm hook populates before onRuntimeInitialized
 * fires, but we retain this pointer in case C code needs to inspect it. */
static void *g_wasm_net_sab = NULL;

void wasm_net_set_sab(void *sab_ptr)
{
    g_wasm_net_sab = sab_ptr;
}

METHOD(socket_t, wasm_receive, status_t,
    private_socket_wasm_t *this, packet_t **packet)
{
    uint8_t *buf;
    uint32_t src_ip = 0, src_port = 0, dst_ip = 0, dst_port = 0;
    host_t *src, *dst;
    packet_t *pkt;
    int len;

    buf = malloc(WASM_PACKET_MAX);
    if (!buf)
    {
        return FAILED;
    }

    len = wasm_net_receive(buf, WASM_PACKET_MAX,
                           &src_ip, &src_port,
                           &dst_ip, &dst_port);
    if (len <= 0)
    {
        free(buf);
        return FAILED;
    }

    {
        chunk_t data = chunk_create(buf, len);
        struct sockaddr_in sa_src = {0}, sa_dst = {0};

        sa_src.sin_family = AF_INET;
        sa_src.sin_addr.s_addr = src_ip;
        sa_src.sin_port = htons((uint16_t)src_port);
        sa_dst.sin_family = AF_INET;
        sa_dst.sin_addr.s_addr = dst_ip;
        sa_dst.sin_port = htons((uint16_t)(dst_port ? dst_port : this->port));

        src = host_create_from_sockaddr((struct sockaddr *)&sa_src);
        dst = host_create_from_sockaddr((struct sockaddr *)&sa_dst);
        pkt = packet_create_from_data(src, dst, chunk_clone(data));
        free(buf);
    }

    *packet = pkt;
    return SUCCESS;
}

METHOD(socket_t, wasm_send, status_t,
    private_socket_wasm_t *this, packet_t *packet)
{
    host_t *src, *dst;
    chunk_t data;
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    int sent;

    src  = packet->get_source(packet);
    dst  = packet->get_destination(packet);
    data = packet->get_data(packet);

    if (src)
    {
        chunk_t a = src->get_address(src);
        if (a.len >= 4) memcpy(&src_ip, a.ptr, 4);
        src_port = src->get_port(src);
    }
    if (dst)
    {
        chunk_t a = dst->get_address(dst);
        if (a.len >= 4) memcpy(&dst_ip, a.ptr, 4);
        dst_port = dst->get_port(dst);
    }

    sent = wasm_net_send(data.ptr, (int)data.len,
                         src_ip, src_port, dst_ip, dst_port);
    return (sent == (int)data.len) ? SUCCESS : FAILED;
}

METHOD(socket_t, wasm_get_port, uint16_t,
    private_socket_wasm_t *this, bool nat_t)
{
    return this->port;
}

METHOD(socket_t, wasm_supported_families, socket_family_t,
    private_socket_wasm_t *this)
{
    return SOCKET_FAMILY_IPV4;
}

METHOD(socket_t, wasm_destroy, void,
    private_socket_wasm_t *this)
{
    free(this);
}

void wasm_socket_destroy(void *this)
{
    if (this) wasm_destroy((private_socket_wasm_t *)this);
}

socket_t *socket_wasm_create(void)
{
    private_socket_wasm_t *this;

    INIT(this,
        .public = {
            .send = _wasm_send,
            .receive = _wasm_receive,
            .get_port = _wasm_get_port,
            .supported_families = _wasm_supported_families,
            .destroy = _wasm_destroy,
        },
        .port = 500,
    );

    return &this->public;
}

#endif /* __EMSCRIPTEN__ */
