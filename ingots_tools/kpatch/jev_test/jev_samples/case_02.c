#include <stddef.h>
#include <stdint.h>

struct user_request {
    uint32_t length;
    const unsigned char *payload;
};

extern int copy_from_user(void *dst, const void *src, size_t n);

/* Another thread may change any memory reachable through user_req. */
int receive_request(const struct user_request *user_req)
{
    struct user_request snapshot;
    unsigned char dst[256];

    if (copy_from_user(&snapshot, user_req, sizeof(snapshot)) != 0)
        return -1;
    if (snapshot.length > sizeof(dst))
        return -1;
    if (copy_from_user(dst, snapshot.payload, snapshot.length) != 0)
        return -1;
    return 0;
}
