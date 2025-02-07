#ifndef CRYPTOLYSER_CONNECTION_DATA_TYPES_H
#define CRYPTOLYSER_CONNECTION_DATA_TYPES_H

#include <stdint.h>

/// The maximum 'safe' UDP payload is 508 bytes, so by subtracting the size of packet_id and
/// data_length, we obtain the recommended byte data size.
#define CONNECTION_DATA_MAX_SIZE (508 - 2 * sizeof(uint32_t))

#pragma pack(1)
struct connection_packet_t
{
    uint32_t packet_id;
    uint32_t data_length;
    uint8_t byte_data[CONNECTION_DATA_MAX_SIZE];
};
#pragma pack(0)

#pragma pack(1)
struct connection_timing_t
{
    uint32_t packet_id;
    uint64_t inbound_sec;
    uint64_t inbound_nsec;
    uint64_t outbound_sec;
    uint64_t outbound_nsec;
};
#pragma pack(0)

#endif // CRYPTOLYSER_CONNECTION_DATA_TYPES_H
