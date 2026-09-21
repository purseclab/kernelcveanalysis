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
    const size_t max_bytes = 1024U * 1024U;
    size_t allocation_size;
    struct table_entry *table;
    size_t index;

    if (count > max_bytes / sizeof(struct table_entry))
        return NULL;
    allocation_size = count * sizeof(struct table_entry);
    table = malloc(allocation_size);
    if (table == NULL && allocation_size != 0)
        return NULL;

    for (index = 0; index < count; ++index) {
        table[index].key = 0;
        table[index].value = 0;
    }
    return table;
}
