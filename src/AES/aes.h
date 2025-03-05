#ifndef CRYPTOLYSER_VICTIM_AES_AES_H_
#define CRYPTOLYSER_VICTIM_AES_AES_H_

#include "openssl/aes.h"
#include "openssl/evp.h"

/**
 * Create a 128 bit key and IV using the supplied key_data. salt can be added
 *for taste. Fills in the encryption and decryption ctx objects and returns 0 on
 *success
 **/
int aes_init(unsigned char key[static 16], EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);

/// Encrypt len bytes of data. All data going in & out is considered binary (unsigned char[])
/// @param e [in/out]
/// @param plaintext [in]
/// @param plaintext_len [in]
/// @param ciphertext_len [out]
/// @param ciphertext [out] Make sure that is has enough space to hold the ciphertext
/// @return
void aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int plaintext_len,
                 int *ciphertext_len, unsigned char *ciphertext);

/*
 * Decrypt len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int ciphertext_len,
                           int *plaintext_len);

#endif // CRYPTOLYSER_VICTIM_AES_AES_H_
