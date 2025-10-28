#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

#define MAPS_POLL_INTERVAL_MS 100
#define MAPS_POLL_TIMEOUT_S 5

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/* Parse a maps line like:
   "00400000-0040b000 r-xp 00000000 fd:01 123456 /path/to/bin"
   Return 0 on success and set *start, *end and pointer to pathname in line (or NULL).
*/
static int parse_maps_line(const char *line, unsigned long long *start, unsigned long long *end, const char **pathname) {
    unsigned long long s=0,e=0;
    const char *p = strchr(line, ' ');
    if (!p) return -1;
    // Parse addresses before first space
    if (sscanf(line, "%llx-%llx", &s, &e) != 2) return -1;
    // find pathname token: it is the last whitespace-separated field if present
    const char *slash = strchr(line, '/');
    if (slash) {
        // pathname starts at slash and runs to newline or end
        const char *nl = strchr(slash, '\n');
        size_t len = nl ? (size_t)(nl - slash) : strlen(slash);
        char *tmp = malloc(len + 1);
        if (!tmp) return -1;
        memcpy(tmp, slash, len);
        tmp[len] = '\0';
        *pathname = tmp; // caller must free
    } else {
        *pathname = NULL;
    }
    *start = s;
    *end = e;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/binary [args...]\n", argv[0]);
        return 2;
    }

    const char *binpath = argv[1];

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* Child: exec the requested binary.
           Use execv so the pathname passed is the program path.
        */
        char **child_argv = &argv[1]; // pass binary and its args
        execv(binpath, child_argv);
        // If execv returns, it failed.
        fprintf(stderr, "execv('%s') failed: %s\n", binpath, strerror(errno));
        _exit(127);
    }

    /* Parent: wait until the child's /proc/<pid>/maps contains mappings for binpath.
       Poll for up to MAPS_POLL_TIMEOUT_S seconds.
    */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)child);

    time_t start_time = time(NULL);
    unsigned long long min_start = ULLONG_MAX;
    unsigned long long max_end = 0;
    int found_any = 0;

    while (1) {
        FILE *f = fopen(maps_path, "r");
        if (f) {
            char *line = NULL;
            size_t len = 0;
            ssize_t read;
            // Free any previous temporary pathname strings carefully
            while ((read = getline(&line, &len, f)) != -1) {
                unsigned long long s,e;
                const char *pathname = NULL;
                if (parse_maps_line(line, &s, &e, &pathname) == 0) {
                    if (pathname) {
                        // check if pathname contains binpath as substring
                        if (strstr(pathname, binpath) != NULL) {
                            if (s < min_start) min_start = s;
                            if (e > max_end) max_end = e;
                            found_any = 1;
                        }
                        free((void*)pathname);
                    }
                }
            }
            free(line);
            fclose(f);
        }

        if (found_any) break;

        if ((time(NULL) - start_time) >= MAPS_POLL_TIMEOUT_S) {
            fprintf(stderr, "Timed out waiting for mappings of %s in %s\n", binpath, maps_path);
            // Optionally detach/kill child. For now, leave running and exit with error.
            return 3;
        }
        // Sleep a short while and retry
        struct timespec ts = {0, MAPS_POLL_INTERVAL_MS * 1000000};
        nanosleep(&ts, NULL);
    }

    if (min_start == ULLONG_MAX || max_end == 0 || max_end <= min_start) {
        fprintf(stderr, "Failed to determine mapping bounds for %s\n", binpath);
        return 4;
    }

    /* Attach to the child process so that /proc/<pid>/mem can be read.
       PTRACE_ATTACH will stop the child. Wait for it.
    */
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        return 5;
    }
    int status;
    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid after attach");
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        return 6;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Child did not stop after attach\n");
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        return 7;
    }

    /* Open /proc/<pid>/mem and read from min_start..max_end */
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)child);
    int memfd = open(mem_path, O_RDONLY);
    if (memfd == -1) {
        perror("open /proc/<pid>/mem");
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        return 8;
    }

    unsigned long long region_size = max_end - min_start;
    // limit reasonable size to avoid trying to allocate huge buffers accidentally
    if (region_size > (1ULL<<31)) {
        fprintf(stderr, "Region size too large: %" PRIu64 " bytes\n", (uint64_t)region_size);
        close(memfd);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        return 9;
    }

    uint8_t *buf = malloc((size_t)region_size);
    if (!buf) {
        perror("malloc");
        close(memfd);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        return 10;
    }

    size_t to_read = (size_t)region_size;
    size_t offset = 0;
    while (to_read > 0) {
        ssize_t n = pread(memfd, buf + offset, to_read, (off_t)(min_start + offset));
        if (n <= 0) {
            if (n == -1 && errno == EINTR) continue;
            // If reading fails because some pages are unreadable, fill with 0 and continue
            // but break to avoid infinite loop
            fprintf(stderr, "pread failed at offset %zu: %s\n", offset, strerror(errno));
            break;
        }
        offset += (size_t)n;
        to_read -= (size_t)n;
    }
    size_t read_bytes = offset;

    /* Print results as requested:
       first line: load address (lowest start) in hex, include 0x prefix
       second line: hex data of the dumped memory (one contiguous hex string, lower-case)
    */
    // Print base address
    printf("0x%llx\n", (unsigned long long)min_start);
    // printf("0x%llx\n", (unsigned long long)max_end);

    // Print hex data; if some bytes were unread, print what was read
    for (size_t i = 0; i < read_bytes; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
    fflush(stdout);

    /* Cleanup: close mem, free buffer, detach child so it can continue */
    free(buf);
    close(memfd);

    if (ptrace(PTRACE_DETACH, child, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_DETACH)");
        // continue; not fatal for output
    }

    // kill child so adb doesn't wait
    if (kill(child, SIGKILL) == -1) {
        perror("kill");
        return 0;
    }

    /* Parent does not wait for child to exit. Exit normally. */
    return 0;
}
