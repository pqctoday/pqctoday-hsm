#ifndef XMSS_RANDOMBYTES_H
#define XMSS_RANDOMBYTES_H

/**
 * Tries to read xlen bytes from a source of randomness, and writes them to x.
 * In KAT mode, uses NIST AES-256-CTR-DRBG for deterministic output.
 */
void randombytes(unsigned char *x, unsigned long long xlen);

/**
 * Initialize NIST AES-256-CTR-DRBG for KAT validation.
 * entropy_input must be exactly 48 bytes.
 * After calling this, all randombytes() calls produce deterministic output
 * identical to NIST PQCgenKAT rng.c.
 */
void randombytes_kat_init(const unsigned char *entropy_input);

/**
 * Disable KAT mode and return to OpenSSL RAND_bytes.
 */
void randombytes_kat_disable(void);

#endif
