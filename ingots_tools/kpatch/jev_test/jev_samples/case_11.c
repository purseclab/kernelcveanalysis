#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* An untrusted local user controls path and may concurrently replace symlinks. */
int open_tenant_file(const char *path)
{
    const char allowed_root[] = "/srv/tenant-data/";
    char resolved[PATH_MAX];
    size_t root_length = sizeof(allowed_root) - 1;

    if (realpath(path, resolved) == NULL)
        return -1;
    if (strncmp(resolved, allowed_root, root_length) != 0)
        return -1;
    if (resolved[root_length] == '\0')
        return -1;

    return open(path, O_RDONLY | O_CLOEXEC);
}
