#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

// states of program, will be reexecuted serveral times in different states
#define SWITCH_SELABEL "switch_selabel"
#define SWITCH_UID "switch_uid"

void usage() {
    puts("Usage: runas <uid> <gid> <selinux_label> <command>");
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) {
        usage();
        return 1;
    }

    char self_path[4096] = { 0 };
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len < 0) {
        perror("readlink");
        return 1;
    }
    self_path[len] = '\0';

    char *uid_str = argv[1];
    char *gid_str = argv[2];
    char *selabel = argv[3];
    char *command = argv[4];

    if (argc == 5) {
        // starting off, first run as root
        execlp("su", "su", "0", self_path, uid_str, gid_str, selabel, command, SWITCH_SELABEL, NULL);
    } else if (strcmp(argv[5], SWITCH_SELABEL) == 0) {
        // first disable selinux
        system("setenforce 0");

        // then run as different salabel
        execlp("runcon", "runcon", selabel, self_path, uid_str, gid_str, selabel, command, SWITCH_UID, NULL);
    } else if (strcmp(argv[5], SWITCH_UID) == 0) {
        int send_pipes[2] = { 0 };
        int recv_pipes[2] = { 0 };
        // just used as vlue written over pipe
        char value = 0;

        if (pipe(send_pipes) < 0 || pipe(recv_pipes) < 0) {
            perror("pipe");
            return 1;
        }

        int pid = fork();
        if (pid < 0) {
            perror("fork");
            return 1;
        } else if (pid == 0) {
            close(send_pipes[1]);
            close(recv_pipes[0]);

            read(send_pipes[0], &value, sizeof(value));

            // reanable selinu after waiting
            system("setenforce 1");

            write(recv_pipes[1], &value, sizeof(value));
            return 0;
        } else {
            close(send_pipes[0]);
            close(recv_pipes[1]);

            // switch gid
            // must be done before switching uid otherwise we get permission denied
            gid_t gid = atoi(gid_str);
            if (setresgid(gid, gid, gid) != 0) {
                perror("setresgid");
                return 1;
            }

            // switch uid
            uid_t uid = atoi(uid_str);
            if (setresuid(uid, uid, uid) != 0) {
                perror("setresuid");
                return 1;
            }

            // tell other process the change selinux enforcing
            // have to do this after changing uid since some selinux policy forbid setresuid
            // but some uid don't allow setenforce 1
            write(send_pipes[1], &value, sizeof(value));

            // wait for it to finish
            read(recv_pipes[0], &value, sizeof(value));

            // runn command
            execlp("sh", "sh", "-c", command, NULL);
        }
    } else {
        puts("Invalid options");
        return 1;
    }
    perror("execlp");
    return 1;
}