/*
 * posix_stubs.c — Stubs for POSIX functions absent from Emscripten sysroot.
 *
 * Included in the WASM build to satisfy linker dependencies in OpenSSH source
 * files that are compiled but whose codepaths are never reached in WASM.
 */
#ifdef __EMSCRIPTEN__
#include <stddef.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <errno.h>

/* initgroups — used in misc.c for privilege separation (never called in WASM) */
int initgroups(const char *user, gid_t group) {
    (void)user; (void)group;
    return 0;
}

/* res_query — used in getrrsetbyname.c for SSHFP DNS lookup (disabled in WASM) */
int res_query(const char *dname, int class, int type,
              unsigned char *answer, int anslen) {
    (void)dname; (void)class; (void)type; (void)answer; (void)anslen;
    errno = ENONET;
    return -1;
}

/* res_search — same file, same stub */
int res_search(const char *dname, int class, int type,
               unsigned char *answer, int anslen) {
    return res_query(dname, class, type, answer, anslen);
}

/* res_init — resolver initialization */
int res_init(void) { return 0; }

/* setgroups — privilege management (never reached in WASM) */
int setgroups(size_t size, const gid_t *list) {
    (void)size; (void)list;
    return 0;
}

/* login / logout — session accounting (disabled in WASM) */
void login(const struct utmp *ut) { (void)ut; }
int logout(const char *line) { (void)line; return 0; }
void logwtmp(const char *line, const char *name, const char *host) {
    (void)line; (void)name; (void)host;
}

#endif /* __EMSCRIPTEN__ */
