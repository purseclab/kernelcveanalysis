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
    struct user_request header;
    unsigned char dst[256];
    uint32_t length_again;

    if (copy_from_user(&header, user_req, sizeof(header)) != 0)
        return -1;
    if (header.length > sizeof(dst))
        return -1;

    if (copy_from_user(&length_again, &user_req->length,
                       sizeof(length_again)) != 0)
        return -1;
    if (copy_from_user(dst, header.payload, length_again) != 0)
        return -1;
    return 0;
}
