#include "aes_interface.h"

#include "openssl/aes.h"
#include "openssl/evp.h"

struct aes_ctx_t
{
    EVP_CIPHER_CTX *ctx;
};

struct aes_ctx_t *aes_ctx(void)
{
    struct aes_ctx_t *aes_context = malloc(sizeof(struct aes_ctx_t));
    aes_context->ctx = EVP_CIPHER_CTX_new();
    return aes_context;
}

int aes_init(struct aes_ctx_t *encrypt_ctx,
             struct aes_ctx_t *decrypt_ctx, uint8_t key[static AES_BLOCK_SIZE])
{
    EVP_EncryptInit_ex(encrypt_ctx->ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_DecryptInit_ex(decrypt_ctx->ctx, EVP_aes_128_ecb(), NULL, key, NULL);

    return 0;
}

void aes_encrypt(struct aes_ctx_t *encrypt_ctx, uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext,
                 size_t *ciphertext_len)
{
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1
     * bytes */
    int c_len = plaintext_len + AES_BLOCK_SIZE, f_len = 0;

    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(encrypt_ctx->ctx, NULL, NULL, NULL, NULL);

    /* update ciphertext, c_len is filled with the length of ciphertext
     *generated, len is the size of plaintext in bytes */
    EVP_EncryptUpdate(encrypt_ctx->ctx, ciphertext, &c_len, plaintext, plaintext_len);

    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(encrypt_ctx->ctx, ciphertext + c_len, &f_len);
    *ciphertext_len = c_len + f_len;
}

void aes_decrypt(struct aes_ctx_t *decrypt_ctx, uint8_t *ciphertext,
                           size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len)
{
    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = ciphertext_len, f_len = 0;

    EVP_DecryptInit_ex(decrypt_ctx->ctx, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(decrypt_ctx->ctx, plaintext, &p_len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(decrypt_ctx->ctx, plaintext + p_len, &f_len);

    *plaintext_len = p_len + f_len;
}

void aes_clean(struct aes_ctx_t *ctx) { EVP_CIPHER_CTX_free(ctx->ctx); free(ctx); }

#if defined __x86_64__
extern unsigned int OPENSSL_ia32cap_P[];
#define AESNI_CAPABLE (OPENSSL_ia32cap_P[1] & (1 << (57 - 32)))
#endif

void aes_log_status(FILE *stream)
{
    fprintf(stream, "Using OPENSSL_VERSION: %lx (hex)\n", OPENSSL_VERSION_NUMBER);
#if defined __x86_64__
    if (AESNI_CAPABLE)
        fprintf(stream, "Using AES-NI, not good.\n");
    else
        fprintf(stream, "Not using AES-NI, good.\n");
#endif
}
