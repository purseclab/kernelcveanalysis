#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/openat2.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

static int openat2_readonly(int directory_fd, const char *relative_path)
{
    struct open_how how = {
        .flags = O_RDONLY | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
                   RESOLVE_NO_MAGICLINKS,
    };

    return (int)syscall(SYS_openat2, directory_fd, relative_path,
                        &how, sizeof(how));
}

/* root_fd is an O_PATH fd for /srv/tenant-data opened during startup. */
/* An untrusted local user controls relative_path and directory contents. */
int open_tenant_file(int root_fd, const char *relative_path)
{
    if (relative_path[0] == '/')
        return -1;
    return openat2_readonly(root_fd, relative_path);
}
