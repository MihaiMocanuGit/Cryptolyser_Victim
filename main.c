#include "AES/aes_interface.h"
#include "CacheFlush/cache_flush.h"
#include "ConnectionHandler/connection_handler.h"
#include "Cryptolyser_Common/connection_data_types.h"
#include "Cryptolyser_Common/cycle_timer.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void printHexLine(const char *line_label, uint8_t *input, uint32_t len)
{
    printf("%s", line_label);
    for (uint32_t i = 0; i < len; ++i)
    {
        printf("%02X ", (unsigned int)input[i]);
    }
}

static void parseKey(const char *keyStr, uint8_t key[static PACKET_KEY_BYTE_SIZE])
{
    char *keyTok = strdup(keyStr);
    char *value = strtok(keyTok, " ");
    unsigned index = 0;
    while (value)
    {
        key[index++] = strtoul(value, NULL, 16);
        value = strtok(NULL, " ");
    }
    free(keyTok);
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Incorrect program parameter: <PORT> <KEY>\n");
        return EXIT_FAILURE;
    }
    aes_log_status(stdout);

    struct connection_t *server;
    if (connection_init(&server, atoi(argv[1])))
    {
        perror("Could not initialize connection.\n");
        connection_cleanup(&server);
        return EXIT_FAILURE;
    }

    uint8_t key_data[PACKET_KEY_BYTE_SIZE];
    parseKey(argv[2], key_data);
    printHexLine("Key: ", key_data, PACKET_KEY_BYTE_SIZE);
    printf("\n");

    struct aes_ctx_t *en = aes_ctx();
    struct aes_ctx_t *de = aes_ctx();

    if (aes_init(en, de, key_data))
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
        uint8_t iv[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        aes_set_iv(en, iv);
        aes_set_iv(de, iv);
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
        uint8_t ciphertext[CONNECTION_DATA_MAX_SIZE + AES_BLOCK_SIZE];
        size_t ciphertext_len;

        // Will encrypt only the first block of the plaintext, mimicking Bernstein's approach.
        const uint8_t encryption_length =
            plaintext_len < AES_BLOCK_SIZE ? plaintext_len : AES_BLOCK_SIZE;

        const struct cycle_timer_t inbound_time = time_start();

        aes_encrypt(en, plaintext, encryption_length, ciphertext, &ciphertext_len);

        const struct cycle_timer_t outbound_time = time_end();
        atomic_thread_fence(memory_order_seq_cst);

        if (connection_respond_back(server, packet_id, ciphertext, inbound_time, outbound_time))
        {
            perror("Could not send back timing response.\n");
            goto cleanup;
        }
        printf("\t %ld.%ld -> %ld.%ld\n", inbound_time.t1, inbound_time.t2, outbound_time.t1,
               outbound_time.t2);
        uint8_t decrypted_plaintext[CONNECTION_DATA_MAX_SIZE];
        size_t decrypted_len;
        aes_decrypt(de, ciphertext, ciphertext_len, decrypted_plaintext, &decrypted_len);
        assert(plaintext_len <= decrypted_len);
        assert(memcmp(decrypted_plaintext, plaintext, plaintext_len));
    }

cleanup:
    aes_clean(en);
    aes_clean(de);
    connection_cleanup(&server);
    return EXIT_FAILURE;
}
