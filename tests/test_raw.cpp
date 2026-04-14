#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <stdio.h>

int main() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "slh-dsa-sha2-128f", NULL);
    if (!ctx) { printf("ctx error\n"); return 1; }
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    size_t len = 0;
    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &len)) {
        printf("raw private key supported! len=%zu\n", len);
    } else {
        printf("raw private key NOT supported!\n");
    }
    
    // Try OSSL_PKEY_PARAM_PRIV_KEY
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, &len)) {
         printf("OSSL_PKEY_PARAM_PRIV_KEY supported! len=%zu\n", len);
         unsigned char* buf = new unsigned char[len];
         EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, buf, len, &len);
         printf("Got param!\n");
         
         // try fromdata
         OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
         OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, buf, len);
         OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
         EVP_PKEY_CTX *ctx2 = EVP_PKEY_CTX_new_from_name(NULL, "slh-dsa-sha2-128f", NULL);
         EVP_PKEY_fromdata_init(ctx2);
         EVP_PKEY *pkey2 = NULL;
         if (EVP_PKEY_fromdata(ctx2, &pkey2, EVP_PKEY_KEYPAIR, params)) {
             printf("fromdata successful!\n");
         } else {
             printf("fromdata failed\n");
             ERR_print_errors_fp(stdout);
         }
         EVP_PKEY_CTX_free(ctx2);
         OSSL_PARAM_free(params);
         OSSL_PARAM_BLD_free(bld);
         delete[] buf;
    } else {
         unsigned char* buf = new unsigned char[128];
         size_t len2;
         if (EVP_PKEY_get_raw_private_key(pkey, buf, &len2)) {
            printf("Got via gets_raw_private_key\n");
         }
    }

    EVP_PKEY_free(pkey);
    return 0;
}
