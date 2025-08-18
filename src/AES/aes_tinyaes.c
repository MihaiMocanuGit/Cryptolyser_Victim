#include "aes.h"

#include "aes_interface.h"

#include <stdlib.h>
#include <string.h>

struct aes_ctx_t
{
    struct AES_ctx ctx;
};

const bool aes_ecb_flag = true;
const bool aes_cbc_flag = true;
const bool aes_ctr_flag = true;
const bool aes_ofb_flag = false;
const bool aes_cfb_flag = false;

void aes_log_status(FILE *stream)
{
    fprintf(stream, "Using Tiny AES C.\n");
    fprintf(stream, "ECB: %d\n", aes_ecb_flag);
    fprintf(stream, "CBC: %d\n", aes_cbc_flag);
    fprintf(stream, "CTR: %d\n", aes_ctr_flag);
    fprintf(stream, "OFB: %d\n", aes_ofb_flag);
    fprintf(stream, "CFB: %d\n", aes_cfb_flag);
}

struct aes_ctx_t *aes_ctx(void) { return calloc(1, sizeof(struct aes_ctx_t)); }

void aes_ctx_clean(struct aes_ctx_t *ctx) { free(ctx); }

int aes_ecb_init(struct aes_ctx_t *encrypt_ctx, struct aes_ctx_t *decrypt_ctx,
                 const uint8_t key[static AES_BLOCK_SIZE])
{
    AES_init_ctx(&encrypt_ctx->ctx, key);
    AES_init_ctx(&decrypt_ctx->ctx, key);

    return 0;
}

void aes_ecb_encrypt(struct aes_ctx_t *encrypt_ctx, const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, size_t *ciphertext_len)
{
    memcpy(ciphertext, plaintext, plaintext_len);
    *ciphertext_len =
        plaintext_len + (AES_BLOCK_SIZE - plaintext_len % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
    for (size_t cipher_block = 0; cipher_block < *ciphertext_len; cipher_block += AES_BLOCK_SIZE)
        AES_ECB_encrypt(&encrypt_ctx->ctx, ciphertext + cipher_block);
}

void aes_ecb_decrypt(struct aes_ctx_t *decrypt_ctx, const uint8_t *ciphertext,
                     size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len)
{
    memcpy(plaintext, ciphertext, ciphertext_len);
    *plaintext_len = ciphertext_len;
    for (size_t text_block = 0; text_block < *plaintext_len; text_block += AES_BLOCK_SIZE)
        AES_ECB_decrypt(&decrypt_ctx->ctx, plaintext + text_block);
}

int aes_cbc_init(struct aes_ctx_t *encrypt_ctx, struct aes_ctx_t *decrypt_ctx,
                 const uint8_t key[static AES_BLOCK_SIZE])
{
    uint8_t iv[16] = {0};
    AES_init_ctx_iv(&encrypt_ctx->ctx, key, iv);
    AES_init_ctx_iv(&decrypt_ctx->ctx, key, iv);

    return 0;
}

int aes_cbc_set_iv(struct aes_ctx_t *ctx, const uint8_t iv[static 16])
{
    AES_ctx_set_iv(&ctx->ctx, iv);
    return 0;
}

void aes_cbc_encrypt(struct aes_ctx_t *encrypt_ctx, const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, size_t *ciphertext_len)
{
    memcpy(ciphertext, plaintext, plaintext_len);
    *ciphertext_len =
        plaintext_len + (AES_BLOCK_SIZE - plaintext_len % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
    AES_CBC_encrypt_buffer(&encrypt_ctx->ctx, ciphertext, *ciphertext_len);
}

void aes_cbc_decrypt(struct aes_ctx_t *decrypt_ctx, const uint8_t *ciphertext,
                     size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len)
{
    memcpy(plaintext, ciphertext, ciphertext_len);
    *plaintext_len = ciphertext_len;
    AES_CBC_decrypt_buffer(&decrypt_ctx->ctx, plaintext, ciphertext_len);
}

int aes_ctr_init(struct aes_ctx_t *encrypt_ctx, struct aes_ctx_t *decrypt_ctx,
                 const uint8_t key[static AES_BLOCK_SIZE])
{
    uint8_t iv[16] = {0};
    AES_init_ctx_iv(&encrypt_ctx->ctx, key, iv);
    AES_init_ctx_iv(&decrypt_ctx->ctx, key, iv);

    return 0;
}

int aes_ctr_set_iv(struct aes_ctx_t *ctx, const uint8_t iv[static 16])
{
    AES_ctx_set_iv(&ctx->ctx, iv);
    return 0;
}

void aes_ctr_encrypt(struct aes_ctx_t *encrypt_ctx, const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, size_t *ciphertext_len)
{
    memcpy(ciphertext, plaintext, plaintext_len);
    *ciphertext_len =
        plaintext_len + (AES_BLOCK_SIZE - plaintext_len % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
    AES_CTR_xcrypt_buffer(&encrypt_ctx->ctx, ciphertext, *ciphertext_len);
}

void aes_ctr_decrypt(struct aes_ctx_t *decrypt_ctx, const uint8_t *ciphertext,
                     size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len)
{
    memcpy(plaintext, ciphertext, ciphertext_len);
    *plaintext_len = ciphertext_len;
    AES_CTR_xcrypt_buffer(&decrypt_ctx->ctx, plaintext, *plaintext_len);
}
