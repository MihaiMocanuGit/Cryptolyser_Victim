#include "AES/aes.h"
#include "CacheFlush/cache_flush.h"
#include "ConnectionHandler/connection_handler.h"
#include "Cryptolyser_Common/connection_data_types.h"

#include <stdatomic.h>
#include <stdbool.h>
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

struct read_params_t
{
    struct connection_t *server;
    pthread_mutex_t buffer_mutex;
    size_t buffer_size;
    size_t buffer_capacity;
    struct connection_packet_t *buffer;
    volatile bool has_data;
};

void *read_continuously(void *read_params)
{
    struct read_params_t *params = read_params;
    params->has_data = false;
    params->buffer_size = 0;
    params->buffer_capacity = 8;
    params->buffer = malloc(params->buffer_capacity * sizeof(struct connection_packet_t));
    printf("Listening for incoming connections.\n");
    for (;;)
    {
        struct connection_packet_t new_packet;
        if (connection_receive_data_noalloc(params->server, &new_packet.packet_id,
                                            new_packet.byte_data, &new_packet.data_length))
        {
            perror("Could not receive data.\n");
            exit(EXIT_FAILURE);
        }
        pthread_mutex_lock(&params->buffer_mutex);
        if (params->buffer_size == params->buffer_capacity)
        {
            size_t new_capacity = params->buffer_capacity * 2;
            struct connection_packet_t *tmp =
                reallocarray(params->buffer, new_capacity, sizeof(struct connection_packet_t));
            if (tmp)
            {
                params->buffer = tmp;
                params->buffer_capacity = new_capacity;
            }
            else
            {
                perror("Could not increase read buffer size.\n");
                exit(EXIT_FAILURE);
            }
        }
        // TODO: If performance is an issue, try with a vector of heap allocated packets. This way
        //  we can hold a ptr to the new packet in the buffer. This would simplify the byte copy
        //  to a ptr move.
        memcpy(params->buffer + params->buffer_size++, &new_packet,
               sizeof(struct connection_packet_t));
        params->has_data = true;
        pthread_mutex_unlock(&params->buffer_mutex);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        perror("Incorrect program parameter: <PORT>\n");
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

    unsigned char key_data[] = {127, 128, 129, 130, 131, 132, 133, 134, 135};
    int key_data_len = sizeof key_data;
    if (aes_init(key_data, key_data_len, /*(unsigned char *) &salt*/ NULL, en, de))
    {
        perror("Could not initialize AES cipher.\n");
        goto cleanup;
    }

    printf("Listening on port %s.\n", argv[1]);
    pthread_mutex_t buffer_mutex;
    if (pthread_mutex_init(&buffer_mutex, NULL))
    {
        perror("Could not initialize buffer mutex.\n");
        goto cleanup;
    }
    struct read_params_t read_params = {.server = server,
                                        .buffer_mutex = buffer_mutex,
                                        .buffer = NULL,
                                        .buffer_capacity = 0,
                                        .buffer_size = 0,
                                        .has_data = false};

    pthread_t read_thread;
    pthread_attr_t read_attr;
    if (pthread_attr_init(&read_attr))
    {
        perror("Could not init read thread attributes.");
        goto cleanup;
    }
    if (pthread_attr_setdetachstate(&read_attr, PTHREAD_CREATE_DETACHED))
    {
        perror("Could not set read thread attributes.");
        goto cleanup;
    }
    if (pthread_create(&read_thread, &read_attr, read_continuously, &read_params))
    {
        perror("Could not create read thread.");
        goto cleanup;
    }
    printf("Finished initializations.\n");
    for (;;)
    {
        size_t simple_wait_stat = 0;
        while (!read_params.has_data)
        {
        }

        struct connection_packet_t current_packet;
        pthread_mutex_lock(&read_params.buffer_mutex);
        memcpy(&current_packet, read_params.buffer + read_params.buffer_size - 1,
               sizeof(struct connection_packet_t));
        read_params.buffer_size--;
        if (read_params.buffer_size == 0)
            read_params.has_data = false;
        pthread_mutex_unlock(&read_params.buffer_mutex);

        printf("Packet Id: %u\t Data size: %u Buffer size %lu: ", current_packet.packet_id,
               current_packet.data_length, read_params.buffer_size);
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
        struct timespec inbound_time;
        struct timespec outbound_time;

        // Will encrypt only the first block of the plaintext, mimicking Bernstein's approach.
        const uint8_t encryption_length = current_packet.data_length < AES_BLOCK_SIZE
                                              ? current_packet.data_length
                                              : AES_BLOCK_SIZE;

        clock_gettime(CLOCK_THREAD_CPUTIME_ID, (struct timespec *)&inbound_time);
        aes_encrypt(en, current_packet.byte_data, encryption_length, &ciphertext_len, ciphertext);
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, (struct timespec *)&outbound_time);
        atomic_thread_fence(memory_order_seq_cst);

        printf("\t %ld.%ld -> %ld.%ld\n", inbound_time.tv_sec, inbound_time.tv_nsec,
               outbound_time.tv_sec, outbound_time.tv_nsec);
        if (connection_respond_back(server, current_packet.packet_id, inbound_time, outbound_time))
        {
            perror("Could not send back timing response.\n");
            goto cleanup;
        }
    }

cleanup:
    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);
    connection_cleanup(&server);
    pthread_mutex_destroy(&buffer_mutex);
    pthread_attr_destroy(&read_attr);
    pthread_cancel(read_thread);
    free(read_params.buffer);
    return EXIT_FAILURE;
}
