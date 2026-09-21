#include <spawn.h>
#include <stddef.h>
#include <sys/wait.h>

/* image is read from an untrusted deployment manifest. */
int inspect_image(const char *image)
{
    char *const arguments[] = {
        (char *)"image-inspect",
        (char *)"--format=json",
        (char *)"--",
        (char *)image,
        NULL,
    };
    char *const environment[] = {
        (char *)"PATH=/usr/bin:/bin",
        NULL,
    };
    pid_t child;
    int status;

    if (posix_spawn(&child, "/usr/bin/image-inspect", NULL, NULL,
                    arguments, environment) != 0)
        return -1;
    if (waitpid(child, &status, 0) < 0)
        return -1;
    return status;
}
