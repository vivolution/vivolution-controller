#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define DNS_PORT 53
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_CLASS_IN 1
#define DNS_HEADER_SIZE 12
#define DNS_MAX_PACKET 4096

struct expected_record {
    const char *name;
    const char *ipv4;
};

static const struct expected_record EXPECTED[] = {
    {"sbc1.voice.vivolution.ae", "10.20.2.4"},
    {"sbc2.voice.vivolution.ae", "10.20.2.5"},
};

static uint16_t read_u16(const unsigned char *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static int random_query_id(uint16_t *query_id)
{
    int descriptor = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    ssize_t result;

    if (descriptor < 0) {
        return -1;
    }
    result = read(descriptor, query_id, sizeof(*query_id));
    close(descriptor);
    return result == (ssize_t)sizeof(*query_id) ? 0 : -1;
}

static void write_u16(unsigned char *data, uint16_t value)
{
    data[0] = (unsigned char)(value >> 8);
    data[1] = (unsigned char)(value & 0xffU);
}

static int encode_name(const char *name, unsigned char *output, size_t capacity,
                       size_t *written)
{
    const char *cursor = name;
    size_t offset = 0;

    while (*cursor != '\0') {
        const char *dot = strchr(cursor, '.');
        size_t length = dot ? (size_t)(dot - cursor) : strlen(cursor);
        if (length == 0 || length > 63 || offset + length + 1 >= capacity) {
            return -1;
        }
        output[offset++] = (unsigned char)length;
        memcpy(output + offset, cursor, length);
        offset += length;
        if (!dot) {
            break;
        }
        cursor = dot + 1;
    }
    output[offset++] = 0;
    *written = offset;
    return 0;
}

static int decode_name(const unsigned char *packet, size_t packet_size,
                       size_t start, char *output, size_t output_size,
                       size_t *consumed)
{
    size_t cursor = start;
    size_t resume = 0;
    size_t output_offset = 0;
    size_t steps = 0;

    while (cursor < packet_size && steps++ < packet_size) {
        unsigned char length = packet[cursor];
        if ((length & 0xc0U) == 0xc0U) {
            uint16_t pointer;
            if (cursor + 1 >= packet_size) {
                return -1;
            }
            pointer = (uint16_t)(((uint16_t)(length & 0x3fU) << 8) |
                                 packet[cursor + 1]);
            if (pointer >= packet_size) {
                return -1;
            }
            if (resume == 0) {
                resume = cursor + 2;
            }
            cursor = pointer;
            continue;
        }
        if ((length & 0xc0U) != 0) {
            return -1;
        }
        cursor++;
        if (length == 0) {
            if (output_offset >= output_size) {
                return -1;
            }
            output[output_offset] = '\0';
            *consumed = resume ? resume : cursor;
            return 0;
        }
        if (cursor + length > packet_size ||
            output_offset + length + (output_offset ? 1U : 0U) >= output_size) {
            return -1;
        }
        if (output_offset) {
            output[output_offset++] = '.';
        }
        memcpy(output + output_offset, packet + cursor, length);
        output_offset += length;
        cursor += length;
    }
    return -1;
}

static int skip_record(const unsigned char *packet, size_t packet_size,
                       size_t *offset)
{
    char owner[256];
    size_t cursor;
    uint16_t size;

    if (decode_name(packet, packet_size, *offset, owner, sizeof(owner), &cursor) != 0 ||
        cursor + 10 > packet_size) {
        return -1;
    }
    size = read_u16(packet + cursor + 8);
    cursor += 10;
    if (cursor + size > packet_size) {
        return -1;
    }
    *offset = cursor + size;
    return 0;
}

static int verify_response(const unsigned char *packet, size_t packet_size,
                           uint16_t query_id, const char *name,
                           uint16_t query_type, const struct in_addr *expected)
{
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authorities;
    uint16_t additional;
    size_t offset = DNS_HEADER_SIZE;
    char decoded_name[256];
    uint32_t index;

    if (packet_size < DNS_HEADER_SIZE || read_u16(packet) != query_id) {
        return -1;
    }
    flags = read_u16(packet + 2);
    questions = read_u16(packet + 4);
    answers = read_u16(packet + 6);
    authorities = read_u16(packet + 8);
    additional = read_u16(packet + 10);
    if ((flags & 0x8000U) == 0 || (flags & 0x7800U) != 0 ||
        (flags & 0x0200U) != 0 || (flags & 0x000fU) != 0 || questions != 1) {
        return -1;
    }
    if ((query_type == DNS_TYPE_A && answers != 1) ||
        (query_type == DNS_TYPE_AAAA && answers != 0)) {
        return -1;
    }

    if (decode_name(packet, packet_size, offset, decoded_name,
                    sizeof(decoded_name), &offset) != 0 ||
        strcasecmp(decoded_name, name) != 0 || offset + 4 > packet_size ||
        read_u16(packet + offset) != query_type ||
        read_u16(packet + offset + 2) != DNS_CLASS_IN) {
        return -1;
    }
    offset += 4;

    if (query_type == DNS_TYPE_A) {
        uint16_t record_type;
        uint16_t record_class;
        uint16_t record_size;
        if (decode_name(packet, packet_size, offset, decoded_name,
                        sizeof(decoded_name), &offset) != 0 ||
            strcasecmp(decoded_name, name) != 0 || offset + 10 > packet_size) {
            return -1;
        }
        record_type = read_u16(packet + offset);
        record_class = read_u16(packet + offset + 2);
        record_size = read_u16(packet + offset + 8);
        offset += 10;
        if (record_type != DNS_TYPE_A || record_class != DNS_CLASS_IN ||
            record_size != sizeof(expected->s_addr) ||
            offset + record_size > packet_size ||
            memcmp(packet + offset, &expected->s_addr, record_size) != 0) {
            return -1;
        }
        offset += record_size;
    }

    for (index = 0;
         index < (uint32_t)authorities + (uint32_t)additional;
         index++) {
        if (skip_record(packet, packet_size, &offset) != 0) {
            return -1;
        }
    }
    return offset == packet_size ? 0 : -1;
}

static int query(const struct sockaddr_in *server, const char *name,
                 uint16_t query_type, const struct in_addr *expected)
{
    unsigned char packet[DNS_MAX_PACKET];
    size_t name_size;
    size_t query_size;
    ssize_t response_size;
    uint16_t query_id;
    struct timeval timeout = {.tv_sec = 3, .tv_usec = 0};
    int descriptor = -1;
    int result = -1;

    if (random_query_id(&query_id) != 0) {
        return -1;
    }
    memset(packet, 0, DNS_HEADER_SIZE);
    write_u16(packet, query_id);
    write_u16(packet + 2, 0x0100U);
    write_u16(packet + 4, 1);
    if (encode_name(name, packet + DNS_HEADER_SIZE,
                    sizeof(packet) - DNS_HEADER_SIZE, &name_size) != 0) {
        return -1;
    }
    query_size = DNS_HEADER_SIZE + name_size;
    if (query_size + 4 > sizeof(packet)) {
        return -1;
    }
    write_u16(packet + query_size, query_type);
    write_u16(packet + query_size + 2, DNS_CLASS_IN);
    query_size += 4;

    descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    if (descriptor < 0 ||
        fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        connect(descriptor, (const struct sockaddr *)server, sizeof(*server)) != 0 ||
        send(descriptor, packet, query_size, 0) != (ssize_t)query_size) {
        goto done;
    }
    response_size = recv(descriptor, packet, sizeof(packet), 0);
    if (response_size < 0 ||
        verify_response(packet, (size_t)response_size, query_id, name,
                        query_type, expected) != 0) {
        goto done;
    }
    result = 0;

done:
    if (descriptor >= 0) {
        close(descriptor);
    }
    return result;
}

int main(int argc, char **argv)
{
    struct sockaddr_in server;
    size_t index;

    (void)argv;
    if (argc != 1) {
        return 2;
    }
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, "127.0.0.53", &server.sin_addr) != 1) {
        return 2;
    }

    for (index = 0; index < sizeof(EXPECTED) / sizeof(EXPECTED[0]); index++) {
        struct in_addr expected;
        if (inet_pton(AF_INET, EXPECTED[index].ipv4, &expected) != 1 ||
            query(&server, EXPECTED[index].name, DNS_TYPE_A, &expected) != 0 ||
            query(&server, EXPECTED[index].name, DNS_TYPE_AAAA, &expected) != 0) {
            fprintf(stderr, "private Edge DNS verification failed\n");
            return 3;
        }
    }
    puts("PRIVATE_EDGE_STUB_DNS_OK");
    return 0;
}
