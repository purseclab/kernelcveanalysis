#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/reg.h>   // ORIG_RAX, etc.
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include "common.h"

// --- Simple per-PID state tracking ---
struct pid_state {
    pid_t pid;
    int in_syscall; // 0 = next stop is entry, 1 = next stop is exit
    struct pid_state *next;
};

static struct pid_state *pid_list = NULL;

static struct pid_state *get_state(pid_t pid) {
    struct pid_state *p = pid_list;
    while (p) {
        if (p->pid == pid) return p;
        p = p->next;
    }
    // Create new state if not found
    p = calloc(1, sizeof(*p));
    if (!p) {
        perror("calloc");
        exit(1);
    }
    p->pid = pid;
    p->in_syscall = 0;
    p->next = pid_list;
    pid_list = p;
    return p;
}

static void remove_state(pid_t pid) {
    struct pid_state **pp = &pid_list;
    while (*pp) {
        if ((*pp)->pid == pid) {
            struct pid_state *tmp = *pp;
            *pp = tmp->next;
            free(tmp);
            return;
        }
        pp = &(*pp)->next;
    }
}

typedef enum {
    ARM_32 = 0,
    ARM_64 = 1
} Mode;

Mode mode = 0;

void read_memory(pid_t pid, usize address, usize len, void *buffer) {
    char path_buffer[64] = { 0 };
    snprintf(path_buffer, sizeof(path_buffer) - 1, "/proc/%d/mem", pid);

    FILE *f = fopen(path_buffer, "r");
    assert(f != NULL);
    fseek(f, address, SEEK_SET);
    fread(buffer, sizeof(u8), len, f);
}

// --- User-supplied analyzer stub ---
int analyze_syscall(pid_t pid, struct ptrace_syscall_info *syscall_info) {
    // TODO: fill in with actual checks
    // fprintf(stdout, "pid %d syscall: %lld\n", pid, (long long)syscall_info->entry.nr);

    assert(syscall_info->op == PTRACE_SYSCALL_INFO_ENTRY);

    if ((mode == ARM_32 && syscall_info->entry.nr == 172) || (mode == ARM_64 && syscall_info->entry.nr == 167)) {
        // fprintf(stdout, "found prctl: %llu\n", syscall_info->entry.args[0]);
        if (syscall_info->entry.args[0] == PR_SET_SECCOMP) {
            // printf("found set seccomp\n");
            // fflush(stdout);
            assert(syscall_info->entry.args[1] == SECCOMP_MODE_FILTER);

            usize sock_fprog_addr = syscall_info->entry.args[2];
            struct sock_fprog prog = { 0 };
            read_memory(pid, sock_fprog_addr, sizeof(prog), &prog);
            // printf("sock_fprog { size: %d, len: %p }\n", prog.len, prog.filter);
            // fflush(stdout);

            u8 *filter = calloc(prog.len, sizeof(struct sock_filter));
            read_memory(pid, (usize) prog.filter, prog.len * sizeof(struct sock_filter), filter);
            print_hex(filter, prog.len * sizeof(struct sock_filter));
            fflush(stdout);
        }
    }

    return 0; // 0 = continue, 1 = stop tracing
}

// --- Main tracer ---
int trace_process(pid_t pid) {
    int status;
    int rc = 0;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH");
        return -1;
    }

    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (ptrace(PTRACE_SETOPTIONS, pid, 0,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
               PTRACE_O_TRACESYSGOOD) == -1) {
        perror("PTRACE_SETOPTIONS");
        return -1;
    }

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        perror("PTRACE_SYSCALL");
        return -1;
    }

    while (1) {
        pid_t traced = waitpid(-1, &status, __WALL);
        if (traced == -1) {
            if (errno == EINTR) continue;
            perror("waitpid");
            break;
        }

        // fprintf(stderr, "stopped: %d\n", status);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            remove_state(traced);
            if (traced == pid) {
                rc = 0;
                break;
            }
            continue;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            // Handle fork/clone events
            unsigned int event = (unsigned int)status >> 16;
            if (event == PTRACE_EVENT_FORK ||
                event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {
                unsigned long newpid;
                if (ptrace(PTRACE_GETEVENTMSG, traced, NULL, &newpid) == 0) {
                    // fprintf(stderr, "New child traced: %lu\n", newpid);
                    // FIXME: this errors always
                    if (ptrace(PTRACE_SETOPTIONS, newpid, 0,
                               PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
                               PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD) == -1) {
                        // perror("PTRACE_SETOPTIONS (child)");
                    }
                }
            }

            if (sig == (SIGTRAP | 0x80)) { // syscall stop
                struct pid_state *st = get_state(traced);

                if (!st->in_syscall) {
                    struct ptrace_syscall_info syscall_info = { 0 };
                    // Entry point
                    if (ptrace(PTRACE_GET_SYSCALL_INFO, traced, sizeof(syscall_info), &syscall_info) == -1) {
                        perror("PTRACE_GETREGS");
                    } else {
                        if (analyze_syscall(traced, &syscall_info)) {
                            // fprintf(stderr, "Detaching from pid %d\n", traced);
                            ptrace(PTRACE_DETACH, traced, NULL, NULL);
                            remove_state(traced);
                            if (traced == pid) {
                                rc = 0;
                                break;
                            }
                            continue;
                        }
                    }
                    st->in_syscall = 1;
                } else {
                    // Exit point
                    st->in_syscall = 0;
                }

                // don't send sigtrap
                sig = 0;
            }

            // fprintf(stderr, "restart signal: %d\n", sig);

            if (ptrace(PTRACE_SYSCALL, traced, NULL, sig) == -1) {
                // perror("PTRACE_SYSCALL");
                break;
            }
        }
    }

    return rc;
}

void usage() {
    fprintf(stderr, "Usage: dump_seccomp_filter <pid> <mode>\n");
}

int main(int argc, const char *argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    if (strcmp(argv[2], "arm32") == 0) {
        mode = ARM_32;
    } else if (strcmp(argv[2], "arm64") == 0) {
        mode = ARM_64;
    } else {
        usage();
        return 1;
    }

    return trace_process(pid);
}
