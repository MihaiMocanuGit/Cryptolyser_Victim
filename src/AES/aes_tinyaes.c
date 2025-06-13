#include "aes.h"

#include "aes_interface.h"

#include <stdlib.h>
#include <string.h>

struct aes_ctx_t
{
    struct AES_ctx ctx;
};

struct aes_ctx_t *aes_ctx(void) { return calloc(1, sizeof(struct aes_ctx_t)); }

int aes_init(struct aes_ctx_t *encrypt_ctx, struct aes_ctx_t *decrypt_ctx, uint8_t key[static 16])
{
    uint8_t iv[16] = {0};
    AES_init_ctx_iv(&encrypt_ctx->ctx, key, iv);
    AES_init_ctx_iv(&decrypt_ctx->ctx, key, iv);

    return 0;
}

int aes_set_iv(struct aes_ctx_t *ctx, const uint8_t iv[static 16])
{
    AES_ctx_set_iv(&ctx->ctx, iv);
    return 0;
}

void aes_encrypt(struct aes_ctx_t *encrypt_ctx, uint8_t *plaintext, size_t plaintext_len,
                 uint8_t *ciphertext, size_t *ciphertext_len)
{
    memcpy(ciphertext, plaintext, plaintext_len);
    *ciphertext_len =
        plaintext_len + (AES_BLOCK_SIZE - plaintext_len % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
    AES_CTR_xcrypt_buffer(&encrypt_ctx->ctx, ciphertext, *ciphertext_len);
}

void aes_decrypt(struct aes_ctx_t *decrypt_ctx, uint8_t *ciphertext, size_t ciphertext_len,
                 uint8_t *plaintext, size_t *plaintext_len)
{
    memcpy(plaintext, ciphertext, ciphertext_len);
    *plaintext_len = ciphertext_len;
    AES_CTR_xcrypt_buffer(&decrypt_ctx->ctx, plaintext, *plaintext_len);
}

void aes_clean(struct aes_ctx_t *ctx) { free(ctx); }

void aes_log_status(FILE *stream) { fprintf(stream, "Using Tiny AES C.\n"); }
