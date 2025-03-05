#include "aes.h"

int aes_init(unsigned char key[static 16], EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
    EVP_EncryptInit_ex(e_ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_128_ecb(), NULL, key, NULL);

    return 0;
}

void aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int plaintext_len,
                 int *ciphertext_len, unsigned char *ciphertext)
{
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1
     * bytes */
    int c_len = plaintext_len + AES_BLOCK_SIZE, f_len = 0;

    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

    /* update ciphertext, c_len is filled with the length of ciphertext
     *generated, len is the size of plaintext in bytes */
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, plaintext_len);

    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);
    *ciphertext_len = c_len + f_len;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int ciphertext_len,
                           int *plaintext_len)
{
    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = ciphertext_len, f_len = 0;
    unsigned char *plaintext = malloc(p_len);

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

    *plaintext_len = p_len + f_len;
    return plaintext;
}
