#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct table_entry {
    uint64_t key;
    uint64_t value;
};

/* count is decoded from an untrusted network message. */
struct table_entry *make_table(size_t count)
{
    uint32_t allocation_size = (uint32_t)(count * sizeof(struct table_entry));
    struct table_entry *table;
    size_t index;

    if (allocation_size > 1024U * 1024U)
        return NULL;
    table = malloc(allocation_size);
    if (table == NULL)
        return NULL;

    for (index = 0; index < count; ++index) {
        table[index].key = 0;
        table[index].value = 0;
    }
    return table;
}
