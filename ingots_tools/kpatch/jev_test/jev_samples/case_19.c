#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct wire_header {
    uint32_t payload_length;
};

/* packet and packet_length come from an untrusted network peer. */
char *extract_name(const unsigned char *packet, size_t packet_length)
{
    struct wire_header header;
    size_t payload_length;
    char *name;

    if (packet_length < sizeof(header))
        return NULL;
    memcpy(&header, packet, sizeof(header));
    payload_length = header.payload_length;
    if (payload_length > packet_length - sizeof(header))
        return NULL;

    name = malloc(payload_length);
    if (name == NULL)
        return NULL;
    memcpy(name, packet + sizeof(header), payload_length);
    name[payload_length] = '\0';
    return name;
}
