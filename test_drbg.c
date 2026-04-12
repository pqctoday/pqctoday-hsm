#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

static unsigned char kat_key[32];
static unsigned char kat_v[16];

static void AES256_CTR_DRBG_Update(const unsigned char *provided_data, unsigned char *Key, unsigned char *V) {
    unsigned char temp[48];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, Key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (int i = 0; i < 3; i++) {
        for (int j = 15; j >= 0; j--) {
            if (V[j] == 0xff) { V[j] = 0x00; } else { V[j]++; break; }
        }
        EVP_EncryptUpdate(ctx, temp + 16 * i, &outlen, V, 16);
    }
    EVP_CIPHER_CTX_free(ctx);

    if (provided_data != NULL) {
        for (int i = 0; i < 48; i++) { temp[i] ^= provided_data[i]; }
    }
    memcpy(Key, temp, 32);
    memcpy(V, temp + 32, 16);
}

int main() {
    unsigned char entropy[48] = {
        0x06,0x15,0x50,0x23,0x4D,0x15,0x8C,0x5E,0xC9,0x55,0x95,0xFE,0x04,0xEF,0x7A,0x25,
        0x76,0x7F,0x2E,0x24,0xCC,0x2B,0xC4,0x79,0xD0,0x9D,0x86,0xDC,0x9A,0xBC,0xFD,0xE7,
        0x05,0x6A,0x8C,0x26,0x6F,0x9E,0xF9,0x7E,0xD0,0x85,0x41,0xDB,0xD2,0xE1,0xFF,0xA1
    };
    
    memset(kat_key, 0, 32);
    memset(kat_v, 0, 16);
    AES256_CTR_DRBG_Update(entropy, kat_key, kat_v);
    
    for(int i=0;i<32;i++) printf("%02x", kat_key[i]);
    for(int i=0;i<16;i++) printf("%02x", kat_v[i]);
    printf("\n");
    return 0;
}
