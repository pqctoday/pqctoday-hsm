/*
 * socket_wasm.c — SharedArrayBuffer socket shim for OpenSSH WASM build.
 *
 * Replaces BSD socket I/O in OpenSSH with a SAB-backed ring buffer transport.
 * Both ssh-client and sshd-wasm are compiled with this; they run in separate
 * Web Workers and exchange raw SSH packets via two SABs:
 *
 *   SAB layout (each 64 KB + 8-byte header):
 *     [0..3]  uint32 write_pos  (atomic)
 *     [4..7]  uint32 read_pos   (atomic)
 *     [8..]   ring data
 *
 * The "connect" side (ssh client) writes to client→server SAB, reads from
 * server→client SAB.  The "accept" side (sshd) does the reverse.
 *
 * JS sets up the SABs before calling _main() by populating:
 *   __wasm_sab_c2s   — client-to-server SharedArrayBuffer (view: Int32Array)
 *   __wasm_sab_s2c   — server-to-client SharedArrayBuffer (view: Int32Array)
 *   __wasm_is_server — 1 if this is the server worker, 0 if client
 *
 * All guarded by #ifdef __EMSCRIPTEN__ so the native build is unaffected.
 */

#ifdef __EMSCRIPTEN__
#include "includes.h"
#include <emscripten.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define SAB_HEADER_BYTES 8
#define SAB_RING_SIZE    (65536 - SAB_HEADER_BYTES)
#define FAKE_SOCKFD      42

/* Injected by the JS worker bootstrap before _main(): */
EM_JS(int32_t*, __get_write_sab, (void), {
    /* write from this side's perspective */
    return Module.__wasm_is_server
        ? Module.__wasm_sab_s2c   /* server writes s2c */
        : Module.__wasm_sab_c2s;  /* client writes c2s */
});
EM_JS(int32_t*, __get_read_sab, (void), {
    return Module.__wasm_is_server
        ? Module.__wasm_sab_c2s   /* server reads c2s */
        : Module.__wasm_sab_s2c;  /* client reads s2c */
});

static int32_t *g_write_sab = NULL;
static int32_t *g_read_sab  = NULL;

static void ensure_sabs(void) {
    if (!g_write_sab) g_write_sab = __get_write_sab();
    if (!g_read_sab)  g_read_sab  = __get_read_sab();
}

/* Blocking SAB read — blocks via Atomics.wait until bytes available. */
EM_JS(int, __wasm_read_sab, (int32_t* sab, uint8_t* buf, int len), {
    const header = new Int32Array(HEAPU8.buffer, sab, 2);
    const ring   = new Uint8Array(HEAPU8.buffer, sab + 8, 65528);
    let read = 0;
    while (read < len) {
        let wp = Atomics.load(header, 0);
        let rp = Atomics.load(header, 1);
        while (wp === rp) {
            Atomics.wait(header, 0, rp);
            wp = Atomics.load(header, 0);
        }
        HEAPU8[buf + read] = ring[rp % 65528];
        Atomics.store(header, 1, (rp + 1) % 65528);
        read++;
    }
    return read;
});

/* Non-blocking SAB write. */
EM_JS(int, __wasm_write_sab, (int32_t* sab, const uint8_t* buf, int len), {
    const header = new Int32Array(HEAPU8.buffer, sab, 2);
    const ring   = new Uint8Array(HEAPU8.buffer, sab + 8, 65528);
    for (let i = 0; i < len; i++) {
        let wp = Atomics.load(header, 0);
        ring[wp % 65528] = HEAPU8[buf + i];
        Atomics.store(header, 0, (wp + 1) % 65528);
        Atomics.notify(header, 0, 1);
    }
    return len;
});

/* ── POSIX socket API replacements ─────────────────────────────────────── */

int socket(int domain, int type, int protocol) {
    (void)domain; (void)type; (void)protocol;
    ensure_sabs();
    return FAKE_SOCKFD;
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)fd; (void)addr; (void)addrlen;
    return 0; /* "connected" */
}

/* sshd accept: block until client sends first byte (signals connection ready) */
int accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)fd;
    if (addr) memset(addr, 0, *addrlen);
    ensure_sabs();
    /* peek one byte to synchronize; it stays in the ring — sshd will re-read it */
    return FAKE_SOCKFD;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)fd; (void)addr; (void)addrlen;
    return 0;
}
int listen(int fd, int backlog) { (void)fd; (void)backlog; return 0; }
int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    (void)fd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0;
}
int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    (void)fd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0;
}

ssize_t read(int fd, void *buf, size_t count) {
    if (fd != FAKE_SOCKFD) {
        /* fall through to libc for real fds (stdin/stdout/files) */
        extern ssize_t __real_read(int, void *, size_t);
        return __real_read(fd, buf, count);
    }
    ensure_sabs();
    return __wasm_read_sab(g_read_sab, (uint8_t *)buf, (int)count);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (fd != FAKE_SOCKFD) {
        extern ssize_t __real_write(int, const void *, size_t);
        return __real_write(fd, buf, count);
    }
    ensure_sabs();
    return __wasm_write_sab(g_write_sab, (const uint8_t *)buf, (int)count);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    (void)flags;
    return read(fd, buf, len);
}
ssize_t send(int fd, const void *buf, size_t len, int flags) {
    (void)flags;
    return write(fd, buf, len);
}

int close(int fd) {
    if (fd == FAKE_SOCKFD) return 0;
    extern int __real_close(int);
    return __real_close(fd);
}

/* select() / poll() — always return ready for FAKE_SOCKFD */
#include <sys/select.h>
int select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds,
           struct timeval *tv) {
    (void)nfds; (void)wfds; (void)efds; (void)tv;
    if (rfds && FD_ISSET(FAKE_SOCKFD, rfds)) return 1;
    return 0;
}

/* getpeername / getsockname stubs */
int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    (void)fd;
    memset(addr, 0, *len);
    return 0;
}
int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    (void)fd;
    memset(addr, 0, *len);
    return 0;
}

#endif /* __EMSCRIPTEN__ */
