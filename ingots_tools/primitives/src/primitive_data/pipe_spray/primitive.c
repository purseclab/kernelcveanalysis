#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/**
 * structure for pipe spray configuration
 */
typedef struct {
    int num_pipes;
    size_t data_size;
    void *data;
    int *pipe_fds; // Array to store pipe file descriptors (2 * num_pipes)
} pipe_spray_t;

/**
 * Initialize a pipe spray object.
 */
int init_pipe_spray(pipe_spray_t *spray, int num_pipes, size_t data_size, void *data) {
    spray->num_pipes = num_pipes;
    spray->data_size = data_size;
    spray->data = data;
    spray->pipe_fds = malloc(sizeof(int) * 2 * num_pipes);
    
    if (!spray->pipe_fds) {
        return -1;
    }
    return 0;
}

/**
 * Execute the pipe spray.
 * 
 * Create pipes and write data to them to fill the heap.
 */
int execute_pipe_spray(pipe_spray_t *spray) {
    for (int i = 0; i < spray->num_pipes; i++) {
        if (pipe(&spray->pipe_fds[2*i]) < 0) {
            perror("pipe");
            return -1;
        }
        
        // Write data to the write end of the pipe
        if (write(spray->pipe_fds[2*i + 1], spray->data, spray->data_size) < 0) {
            perror("write");
            return -1;
        }
    }
    return 0;
}

/**
 * Cleanup pipe spray resources.
 */
void cleanup_pipe_spray(pipe_spray_t *spray) {
    if (spray->pipe_fds) {
        for (int i = 0; i < spray->num_pipes; i++) {
            close(spray->pipe_fds[2*i]);
            close(spray->pipe_fds[2*i + 1]);
        }
        free(spray->pipe_fds);
    }
}
