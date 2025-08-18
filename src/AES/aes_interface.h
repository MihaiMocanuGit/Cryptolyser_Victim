#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define AES_BLOCK_SIZE 16

extern const bool aes_ecb_flag;
extern const bool aes_cbc_flag;
extern const bool aes_ctr_flag;
extern const bool aes_ofb_flag;
extern const bool aes_cfb_flag;

struct aes_ctx_t;

struct aes_ctx_t *aes_ctx(void);

void aes_log_status(FILE *stream);

//
// ECB
//
int aes_ecb_init(struct aes_ctx_t *encrypt_ctx, struct aes_ctx_t *decrypt_ctx,
                 uint8_t key[static AES_BLOCK_SIZE]);

/// Encrypt len bytes of data. All data going in & out is considered binary
/// @param encrypt_ctx [in/out]
/// @param plaintext [in]
/// @param plaintext_len [in]
/// @param ciphertext [out] Make sure that is has enough space to hold the ciphertext
/// @param ciphertext_len [out]
/// @return
void aes_ecb_encrypt(struct aes_ctx_t *encrypt_ctx, uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, size_t *ciphertext_len);

void aes_ecb_decrypt(struct aes_ctx_t *decrypt_ctx, uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *plaintext, size_t *plaintext_len);

void aes_ctx_clean(struct aes_ctx_t *ctx);

//
// CBC
//
int aes_cbc_init(struct aes_ctx_t *encrypt_ctx, struct aes_ctx_t *decrypt_ctx,
                 uint8_t key[static AES_BLOCK_SIZE]);

int aes_cbc_set_iv(struct aes_ctx_t *ctx, const uint8_t iv[static 16]);

/// Encrypt len bytes of data. All data going in & out is considered binary
/// @param encrypt_ctx [in/out]
/// @param plaintext [in]
/// @param plaintext_len [in]
/// @param ciphertext [out] Make sure that is has enough space to hold the ciphertext
/// @param ciphertext_len [out]
/// @return
void aes_cbc_encrypt(struct aes_ctx_t *encrypt_ctx, uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, size_t *ciphertext_len);

void aes_cbc_decrypt(struct aes_ctx_t *decrypt_ctx, uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *plaintext, size_t *plaintext_len);

void aes_cbc_clean(struct aes_ctx_t *ctx);

//
// CTR
//
int aes_ctr_init(struct aes_ctx_t *encrypt_ctx, struct aes_ctx_t *decrypt_ctx,
                 uint8_t key[static AES_BLOCK_SIZE]);

int aes_ctr_set_iv(struct aes_ctx_t *ctx, const uint8_t iv[static 16]);

/// Encrypt len bytes of data. All data going in & out is considered binary
/// @param encrypt_ctx [in/out]
/// @param plaintext [in]
/// @param plaintext_len [in]
/// @param ciphertext [out] Make sure that is has enough space to hold the ciphertext
/// @param ciphertext_len [out]
/// @return
void aes_ctr_encrypt(struct aes_ctx_t *encrypt_ctx, uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, size_t *ciphertext_len);

void aes_ctr_decrypt(struct aes_ctx_t *decrypt_ctx, uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *plaintext, size_t *plaintext_len);

void aes_ctr_clean(struct aes_ctx_t *ctx);
