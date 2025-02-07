#include "connection_handler.h"

#include "connection_data_types.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct connection_t
{
    uint16_t broadcast_port;
    int socket;
    struct sockaddr_in recv_addr;
    struct sockaddr_in sender_addr;
};

int connection_init(struct connection_t **connection, uint16_t port)
{
    errno = 0;
    *connection = calloc(1, sizeof(struct connection_t));
    if (*connection == NULL)
        return errno;

    (*connection)->broadcast_port = port;

    errno = 0;
    (*connection)->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if ((*connection)->socket < 0)
        return errno;

    int broadcast = 1;
    errno = 0;
    if (setsockopt((*connection)->socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) <
        0)
        return errno;

    (*connection)->recv_addr.sin_family = AF_INET;
    (*connection)->recv_addr.sin_port = htobe16((*connection)->broadcast_port);
    (*connection)->recv_addr.sin_addr.s_addr = INADDR_ANY;

    errno = 0;
    if (bind((*connection)->socket, (struct sockaddr *)&(*connection)->recv_addr,
             sizeof((*connection)->recv_addr)) < 0)
        return errno;

    return 0;
}

int connection_reopen_socket(struct connection_t *connection)
{
    errno = 0;
    connection->socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (connection->socket < 0)
        return errno;

    int broadcast = 1;
    errno = 0;
    if (setsockopt(connection->socket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
        return errno;

    errno = 0;
    if (bind(connection->socket, (struct sockaddr *)&connection->recv_addr,
             sizeof(connection->recv_addr)) < 0)
        return errno;

    return 0;
}

int connection_receive_data_noalloc(struct connection_t *connection, uint32_t *packet_id,
                                    uint8_t *data, uint32_t *data_len)
{
    struct connection_packet_t packet;
    socklen_t sender_len = sizeof(connection->sender_addr);
    errno = 0;
    if (recvfrom(connection->socket, &packet, sizeof(packet), 0,
                 (struct sockaddr *)&connection->sender_addr, &sender_len) < 0)
        return errno;

    *packet_id = be32toh(packet.packet_id);
    *data_len = be32toh(packet.data_length);
    memcpy(data, packet.byte_data, *data_len);
    return 0;
}

int connection_receive_data(struct connection_t *connection, uint32_t *packet_id, uint8_t **data,
                            uint32_t *data_len)
{
    struct connection_packet_t packet;
    socklen_t sender_len = sizeof(connection->sender_addr);
    errno = 0;
    if (recvfrom(connection->socket, &packet, sizeof(packet), 0,
                 (struct sockaddr *)&connection->sender_addr, &sender_len) < 0)
        return errno;

    *packet_id = be32toh(packet.packet_id);
    *data_len = be32toh(packet.data_length);
    errno = 0;
    if (!(*data = malloc(*data_len)))
        return errno;

    memcpy(data, packet.byte_data, *data_len);
    return 0;
}

int connection_respond_back(struct connection_t *connection, uint32_t packet_id,
                            struct timespec inbound_time, struct timespec outbound_time)
{
    struct connection_timing_t timing = {.packet_id = htobe32(packet_id),
                                         .inbound_sec = htobe64(inbound_time.tv_sec),
                                         .inbound_nsec = htobe64(inbound_time.tv_nsec),
                                         .outbound_sec = htobe64(outbound_time.tv_sec),
                                         .outbound_nsec = htobe64(outbound_time.tv_nsec)};
    errno = 0;
    if (sendto(connection->socket, &timing, sizeof(timing), 0,
               (struct sockaddr *)&connection->sender_addr, sizeof(connection->sender_addr)) < 0)
        return errno;

    return 0;
}

void connection_close(struct connection_t *connection)
{
    memset(&connection->sender_addr, 0, sizeof(connection->sender_addr));
    close(connection->socket);
}

void connection_cleanup(struct connection_t **connection)
{
    connection_close(*connection);
    memset(*connection, 0, sizeof(**connection));
    free(*connection);
    *connection = NULL;
}
