#include <stdio.h>
#include <stdlib.h>

/* image is read from an untrusted deployment manifest. */
int inspect_image(const char *image)
{
    char command[1024];
    int length;

    length = snprintf(command, sizeof(command),
                      "/usr/bin/image-inspect --format=json %s", image);
    if (length < 0 || (size_t)length >= sizeof(command))
        return -1;
    return system(command);
}
