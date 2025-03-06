#include "AES/aes.h"
#include "CacheFlush/cache_flush.h"
#include "ConnectionHandler/connection_handler.h"
#include "Cryptolyser_Common/connection_data_types.h"
#include "Cryptolyser_Common/cycle_timer.h"

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

#if defined __x86_64__
extern unsigned int OPENSSL_ia32cap_P[];
#define AESNI_CAPABLE (OPENSSL_ia32cap_P[1] & (1 << (57 - 32)))
#endif

int main(int argc, char **argv)
{
#if defined __x86_64__
    if (AESNI_CAPABLE)
        perror("Using AES-NI\n");
    else
        printf("Not using AES-NI\n");
#endif

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

    unsigned char key_data[] = {127, 128, 129, 130, 131, 132, 133, 134,
                                135, 136, 137, 138, 139, 140, 141, 142};
    if (aes_init(key_data, en, de))
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

        printf("Packet Id: %u\t Data size: %u", packet_id, plaintext_len);
        // atomic_thread_fence will both be a compiler barrier (disallowing the compiler to reorder
        // instructions across the barrier) and a CPU barrier for that given thread (disallowing
        // the CPU to reorder instructions across the barrier).
        atomic_thread_fence(memory_order_seq_cst);
        // Flushing the cache to minimize possible timing interference from previous cached
        // encryption runs.
        flush_cache();
        // Declaring input/output variables after the cache flush as the performance benefit might
        // help in reducing timing noise.
        unsigned char ciphertext[CONNECTION_DATA_MAX_SIZE + AES_BLOCK_SIZE];
        int ciphertext_len;

        // Will encrypt only the first block of the plaintext, mimicking Bernstein's approach.
        const uint8_t encryption_length =
            plaintext_len < AES_BLOCK_SIZE ? plaintext_len : AES_BLOCK_SIZE;

        const struct cycle_timer_t inbound_time = time_start();

        aes_encrypt(en, plaintext, encryption_length, &ciphertext_len, ciphertext);

        const struct cycle_timer_t outbound_time = time_end();
        atomic_thread_fence(memory_order_seq_cst);

        if (connection_respond_back(server, packet_id, inbound_time, outbound_time))
        {
            perror("Could not send back timing response.\n");
            goto cleanup;
        }
        printf("\t %ld.%ld -> %ld.%ld\n", inbound_time.t1, inbound_time.t2, outbound_time.t1,
               outbound_time.t2);
    }

cleanup:
    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);
    connection_cleanup(&server);
    return EXIT_FAILURE;
}
