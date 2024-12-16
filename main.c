#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>

#include "AES/aes.h"

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
