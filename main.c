#include "AES/aes.h"
#include "CacheFlush/cache_flush.h"
#include "ConnectionHandler/connection_handler.h"
#include "Cryptolyser_Common/connection_data_types.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printHexLine(const char *line_label, unsigned char *input, uint32_t len)
{
    printf("%s", line_label);
    for (uint32_t i = 0; i < len; ++i)
    {
        printf("%02X ", (unsigned int)input[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Incorrect program parameter: <PORT>\n");
        return EXIT_FAILURE;
    }
    printf("Using OPENSSL_VERSION: %lx (hex)\n", OPENSSL_VERSION_NUMBER);

    struct connection_t *server;
    if (connection_init(&server, atoi(argv[1])))
    {
        perror("Could not initialize connection.\n");
        connection_cleanup(&server);
        return EXIT_FAILURE;
    }

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    unsigned char key_data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    int key_data_len = sizeof key_data;
    if (aes_init(key_data, key_data_len, /*(unsigned char *) &salt*/ NULL, en, de))
    {
        perror("Could not initialize AES cipher.\n");
        goto cleanup;
    }

    printf("Listening on port %s.\n", argv[1]);
    for (;;)
    {
        uint8_t plaintext[CONNECTION_DATA_MAX_SIZE];
        uint32_t plaintext_len;
        uint32_t packet_id;
        if (connection_receive_data_noalloc(server, &packet_id, plaintext, &plaintext_len))
        {
            perror("Could not receive data.\n");
            goto cleanup;
        }

        printf("Packet Id: %u\t Data size: %u\n", packet_id, plaintext_len);
        flush_cache();

        // std::atomic_thread_fence will both be a compiler barrier (disallowing the compiler to
        // reorder instructions across the barrier) and a CPU barrier for that given thread
        // (disallowing the CPU to reorder instructions across the barrier)
        atomic_thread_fence(memory_order_seq_cst);
        struct timespec inbound_time;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, (struct timespec *)&inbound_time);

        int ciphertext_len;
        unsigned char *ciphertext = aes_encrypt(en, plaintext, plaintext_len, &ciphertext_len);

        struct timespec outbound_time;
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, (struct timespec *)&outbound_time);
        atomic_thread_fence(memory_order_seq_cst);

        if (connection_respond_back(server, 0, inbound_time, outbound_time))
        {
            perror("Could not send back timing response.\n");
            free((void *)ciphertext);
            goto cleanup;
        }
        free((void *)ciphertext);
    }

cleanup:
    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);
    connection_cleanup(&server);
    return EXIT_FAILURE;
}
