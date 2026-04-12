/*
 * randombytes.c — XMSS random byte source with NIST KAT DRBG support
 *
 * Default: OpenSSL RAND_bytes()
 * KAT mode: AES-256-CTR-DRBG matching NIST PQCgenKAT rng.c exactly
 *
 * The NIST KAT generation tool seeds a deterministic AES-256-CTR-DRBG
 * with a 48-byte entropy_input. This implementation mirrors that DRBG
 * so that randombytes() produces the identical byte stream, enabling
 * bit-exact KAT vector reproduction.
 */

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>

/* ── NIST AES-256-CTR-DRBG state ──────────────────────────────────── */

static int kat_mode = 0;

static unsigned char kat_key[32];          /* AES-256 key   */
static unsigned char kat_v[16];            /* CTR counter   */

/*
 * AES256_CTR_DRBG_Update — NIST SP 800-90A §10.2.1.2
 *   Provided_data: 48 bytes (or NULL → treated as zeros)
 */
static void AES256_CTR_DRBG_Update(const unsigned char *provided_data,
                                   unsigned char *Key, unsigned char *V)
{
    unsigned char temp[48];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, Key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (int i = 0; i < 3; i++) {
        /* V = (V + 1) mod 2^128 */
        for (int j = 15; j >= 0; j--) {
            if (V[j] == 0xff) {
                V[j] = 0x00;
            } else {
                V[j]++;
                break;
            }
        }
        EVP_EncryptUpdate(ctx, temp + 16 * i, &outlen, V, 16);
    }

    EVP_CIPHER_CTX_free(ctx);

    if (provided_data != NULL) {
        for (int i = 0; i < 48; i++) {
            temp[i] ^= provided_data[i];
        }
    }

    memcpy(Key, temp, 32);
    memcpy(V, temp + 32, 16);
}

/*
 * randombytes_kat_init — Seed the NIST AES-256-CTR-DRBG
 *   entropy_input: exactly 48 bytes
 *
 * Matches NIST PQCgenKAT rng.c: randombytes_init(entropy_input, NULL, 256)
 */
void randombytes_kat_init(const unsigned char *entropy_input)
{
    unsigned char seed_material[48];

    memcpy(seed_material, entropy_input, 48);
    /* personalization_string = NULL in NIST KAT generator */

    memset(kat_key, 0x00, 32);
    memset(kat_v,   0x00, 16);

    AES256_CTR_DRBG_Update(seed_material, kat_key, kat_v);

    kat_mode = 1;
}

/*
 * randombytes_kat_disable — Return to OpenSSL RAND_bytes
 */
void randombytes_kat_disable(void)
{
    memset(kat_key, 0, 32);
    memset(kat_v,   0, 16);
    kat_mode = 0;
}

/*
 * randombytes — Generate random bytes
 *   Normal mode: OpenSSL RAND_bytes
 *   KAT mode:    NIST AES-256-CTR-DRBG (identical to PQCgenKAT rng.c)
 */
void randombytes(unsigned char *x, unsigned long long xlen)
{
    if (!kat_mode) {
        RAND_bytes(x, (int)xlen);
        return;
    }

    /* NIST AES-256-CTR-DRBG Generate — SP 800-90A §10.2.1.5.1 */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;
    unsigned char block[16];
    unsigned long long i = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, kat_key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    while (xlen > 0) {
        /* V = (V + 1) mod 2^128 */
        for (int j = 15; j >= 0; j--) {
            if (kat_v[j] == 0xff) {
                kat_v[j] = 0x00;
            } else {
                kat_v[j]++;
                break;
            }
        }
        EVP_EncryptUpdate(ctx, block, &outlen, kat_v, 16);

        if (xlen > 15) {
            memcpy(x + i, block, 16);
            i += 16;
            xlen -= 16;
        } else {
            memcpy(x + i, block, xlen);
            xlen = 0;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    AES256_CTR_DRBG_Update(NULL, kat_key, kat_v);
}
