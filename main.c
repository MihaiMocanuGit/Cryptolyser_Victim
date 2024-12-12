#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdbool.h>
#include <signal.h>

/**
 * Create a 128 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data,
             int key_data_len,
             unsigned char *salt,
             EVP_CIPHER_CTX *e_ctx,
             EVP_CIPHER_CTX *d_ctx)
{
    int i, nrounds = 5;
    unsigned char key[32], iv[32];

    /*
     * Gen key & IV for AES 128 CBC mode. A SHA1 digest is used to hash the supplied key material.
     * nrounds is the number of times the we hash the material. More rounds are more secure but
     * slower.
     */
    i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 16)
    {
        fprintf(stderr, "Key size is %d bits - should be 128 bits\n", i);
        return EXIT_FAILURE;
    }

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_128_cbc(), NULL, key, iv);

    return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = malloc(c_len);

    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
      *len is the size of plaintext in bytes */
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

    *len = c_len + f_len;
    return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = *len, f_len = 0;
    unsigned char *plaintext = malloc(p_len);

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

    *len = p_len + f_len;
    return plaintext;
}

void printHexLine(const char *line_label, unsigned char *input, int len)
{
    printf("%s", line_label);
    for (int i = 0; i < len; ++i)
    {
        printf("%02X ", (unsigned int) input[i]);
    }
    printf("\n");
}

static volatile bool continue_encryption = true;

void intHandler(int dummy)
{
    continue_encryption = false;
    signal(SIGINT, intHandler);
}

int main(int argc, char **argv)
{
    if (signal(SIGINT, intHandler) == SIG_ERR)
    {
        fprintf(stderr, "Could not set signal handler\n");
        return EXIT_FAILURE;
    }

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    unsigned int salt[] = {12345, 54321};
    unsigned char key_data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    int key_data_len = sizeof key_data;
    if (aes_init(key_data, key_data_len, /*(unsigned char *) &salt*/ NULL, en, de))
    {
        fprintf(stderr, "Couldn't initialize AES cipher\n");
        return -1;
    }

    while (continue_encryption)
    {
        unsigned char input[] = {'a', 'n', 'n', 'a', ' ', 'h', 'a', 's', ' ', 'a', 'p', 'p', 'l', 'e', 's', '!', '!'};
        int input_len = sizeof input;
        printHexLine("Input:     \t", input, input_len);

        unsigned char *ciphertext = aes_encrypt(en, input, &input_len);
        printHexLine("Ciphertext:\t", ciphertext, input_len);

        unsigned char *plaintext = aes_decrypt(de, ciphertext, &input_len);
        printHexLine("Plaintext: \t", ciphertext, input_len);
        printf("\n");

        free(ciphertext);
        free(plaintext);
    }
    printf("\nExiting...\n");
    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);

    return 0;
}
