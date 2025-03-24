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
    AES_init_ctx(&encrypt_ctx->ctx, key);
    AES_init_ctx(&decrypt_ctx->ctx, key);

    return 0;
}

void aes_encrypt(struct aes_ctx_t *encrypt_ctx, uint8_t *plaintext, size_t plaintext_len,
                 uint8_t *ciphertext, size_t *ciphertext_len)
{

    memcpy(ciphertext, plaintext, plaintext_len);
    *ciphertext_len = plaintext_len + plaintext_len % AES_BLOCK_SIZE;
    for (size_t cipher_block = 0; cipher_block < *ciphertext_len; cipher_block += AES_BLOCK_SIZE)
        AES_ECB_encrypt(&encrypt_ctx->ctx, ciphertext + cipher_block);
}

void aes_decrypt(struct aes_ctx_t *decrypt_ctx, uint8_t *ciphertext, size_t ciphertext_len,
                 uint8_t *plaintext, size_t *plaintext_len)
{

    memcpy(plaintext, ciphertext, ciphertext_len);
    *plaintext_len = ciphertext_len;
    for (size_t text_block = 0; text_block < *plaintext_len; text_block += AES_BLOCK_SIZE)
        AES_ECB_decrypt(&decrypt_ctx->ctx, plaintext + text_block);
}

void aes_clean(struct aes_ctx_t *ctx) { free(ctx); }

void aes_log_status(FILE *stream) { fprintf(stream, "Using Tiny AES C.\n"); }
