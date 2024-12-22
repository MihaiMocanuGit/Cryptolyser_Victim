#include "AES/aes.h"

#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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
    const unsigned short BROADCAST_PORT = 8081;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("Could not create UDP socket\n");
        return EXIT_FAILURE;
    }

    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
    {
        perror("Could not set Broadcast option\n");
        close(sock);
        return EXIT_FAILURE;
    }

    struct sockaddr_in recv_addr;
    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(BROADCAST_PORT);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0)
    {
        perror("Could not bind.\n");
        close(sock);
        return EXIT_FAILURE;
    }

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    unsigned int salt[] = {12345, 54321};
    unsigned char key_data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    int key_data_len = sizeof key_data;
    if (aes_init(key_data, key_data_len, /*(unsigned char *) &salt*/ NULL, en, de))
    {
        perror("Could not initialize AES cipher.\n");
        close(sock);
        return EXIT_FAILURE;
    }

    printf("Listening on port %u\n", BROADCAST_PORT);
    for (;;)
    {

#pragma pack(1)
        struct
        {
            uint64_t data_length;
            uint8_t byteData[500];
        } packet;
#pragma pack(0)

        struct sockaddr_in sender_addr;
        socklen_t sender_len;
        ssize_t receivedLength = recvfrom(sock, &packet, sizeof(packet), 0,
                                          (struct sockaddr *)&sender_addr, &sender_len);
        if (receivedLength < 0)
        {
            perror("Could not receive byte data packet.\n");
            close(sock);
            EVP_CIPHER_CTX_free(en);
            EVP_CIPHER_CTX_free(de);
            return EXIT_FAILURE;
        }
        if ((uint64_t)receivedLength < sizeof(packet.data_length))
        {
            perror("Lost packet data, did not obtain the data length..\n");
            close(sock);
            EVP_CIPHER_CTX_free(en);
            EVP_CIPHER_CTX_free(de);
            return EXIT_FAILURE;
        }
        uint64_t plaintext_len = be64toh(packet.data_length);
        if ((uint64_t)receivedLength < sizeof(packet.data_length) + plaintext_len)
        {
            perror("Lost packet data, did not obtain the whole byte data.\n");
            close(sock);
            EVP_CIPHER_CTX_free(en);
            EVP_CIPHER_CTX_free(de);
            return EXIT_FAILURE;
        }
        unsigned char *plaintext = malloc(plaintext_len);
        if (!plaintext)
        {
            perror("Could not allocate enough space for the data.\n");
            close(sock);
            EVP_CIPHER_CTX_free(en);
            EVP_CIPHER_CTX_free(de);
            return EXIT_FAILURE;
        }
        memcpy(plaintext, packet.byteData, plaintext_len);
        printHexLine("Input:     \t", plaintext, plaintext_len);
        printf("Data size: %lu\n", plaintext_len);

        // This will need further investigation, the compiler is actually free
        // to reorder this sequence. Find a way to stop it, volatile might not
        // do the trick. Check compiler/memory barriers.
        volatile struct timespec inbound_time;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, (struct timespec *)&inbound_time);

        int ciphertext_len;
        volatile unsigned char *ciphertext =
            aes_encrypt(en, plaintext, plaintext_len, &ciphertext_len);

        volatile struct timespec outbound_time;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, (struct timespec *)&outbound_time);

#pragma pack(1)
        struct
        {
            uint64_t inbound_sec;
            uint64_t inbound_nsec;
            uint64_t outbound_sec;
            uint64_t outbound_nsec;
        } timing = {.inbound_sec = htobe64(inbound_time.tv_sec),
                    .inbound_nsec = htobe64(inbound_time.tv_nsec),
                    .outbound_sec = htobe64(outbound_time.tv_sec),
                    .outbound_nsec = htobe64(outbound_time.tv_nsec)};
#pragma pack(0)

        // Send time data back to the sender0
        if (sendto(sock, &timing, sizeof(timing), 0, (struct sockaddr *)&sender_addr,
                   sizeof(sender_addr)) < 0)
        {
            perror("Could not send timing data.\n");
            close(sock);
            EVP_CIPHER_CTX_free(en);
            EVP_CIPHER_CTX_free(de);
            free(plaintext);
            return EXIT_FAILURE;
        }

        free(plaintext);
    }
    return 0;
}
