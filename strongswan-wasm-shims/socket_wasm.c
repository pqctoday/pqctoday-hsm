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
    /* Layout — must match bridge.ts case 'PACKET_OUT':
     *   i32[0] state (0=free, 1=ready)
     *   i32[1] packet length
     *   i32[2] src_ip   (network-LE u32: memory bytes match network order)
     *   i32[3] src_port (lower 16 bits)
     *   i32[4] dst_ip   (network-LE u32)
     *   i32[5] dst_port (lower 16 bits)
     *   bytes 24..24+len = packet payload
     * dst_ip used to be hardcoded 0 (= 0.0.0.0 / %any in strongSwan's
     * config matcher) which made the responder reject every IKE_SA_INIT
     * with NO_PROPOSAL_CHOSEN even when the registered peer_cfg had
     * local=192.168.0.2. Plumbing the real dst from the SAB fixes this. */
    var hdr = new Int32Array(sab, 0, 6);
    var body = new Uint8Array(sab, 24);
    while (Atomics.load(hdr, 0) !== 1) {
        Atomics.wait(hdr, 0, 0);
    }
    var len = Atomics.load(hdr, 1);
    if (len > buflen) len = buflen;
    var srcIp   = Atomics.load(hdr, 2);
    var srcPort = Atomics.load(hdr, 3) & 0xffff;
    var dstIp   = Atomics.load(hdr, 4);
    var dstPort = Atomics.load(hdr, 5) & 0xffff;
    for (var i = 0; i < len; i++) HEAPU8[buf + i] = body[i];
    HEAPU32[src_ip_out   >> 2] = srcIp;
    HEAPU32[src_port_out >> 2] = srcPort;
    HEAPU32[dst_ip_out   >> 2] = dstIp;
    HEAPU32[dst_port_out >> 2] = dstPort || 500;
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
    /* Cross-worker routing via the bridge (main thread).
     *
     * Each worker has its own netInbox SAB (Module._wasm_net_sab). If
     * wasm_net_send wrote to that SAB, the same worker's wasm_net_receive
     * would consume it — i.e. self-loopback. The bridge has no polling
     * loop, so writing locally never reaches the peer worker.
     *
     * Instead we postMessage('PACKET_OUT') to the main thread; bridge.ts
     * case 'PACKET_OUT' routes the packet by destIp into the peer's
     * netInbox SAB (header layout: 6 × i32 + body at offset 24).
     *
     * src_ip / dst_ip are network-byte-order u32 (memcpy'd from
     * sin_addr.s_addr in socket_wasm.c::wasm_send) — bridge.ts uses the
     * same network-LE convention for RESPONDER_IP_U32 + destIpStr. */
    var pkt = new Uint8Array(buflen);
    for (var i = 0; i < buflen; i++) pkt[i] = HEAPU8[buf + i];
    self.postMessage({
        type: 'PACKET_OUT',
        payload: {
            srcIp: src_ip >>> 0,
            srcPort: src_port >>> 0,
            destIp: dst_ip >>> 0,
            destPort: dst_port >>> 0,
            data: pkt.buffer,
        },
    }, [pkt.buffer]);
    return buflen;
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
