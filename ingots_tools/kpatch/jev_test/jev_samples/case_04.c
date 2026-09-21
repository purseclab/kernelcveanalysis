#include <stdatomic.h>
#include <stdlib.h>

struct connection {
    atomic_uint refs;
    int socket_fd;
};

struct job {
    struct connection *connection;
};

extern int queue_job(struct job *job, void (*worker)(struct job *));
extern void send_status(int fd);

static void connection_get(struct connection *connection)
{
    atomic_fetch_add(&connection->refs, 1);
}

static void connection_put(struct connection *connection)
{
    if (atomic_fetch_sub(&connection->refs, 1) == 1)
        free(connection);
}

static void status_worker(struct job *job)
{
    send_status(job->connection->socket_fd);
    connection_put(job->connection);
    free(job);
}

/* queue_job returns before worker runs and does not manage connection refs. */
int schedule_status(struct connection *connection)
{
    struct job *job = malloc(sizeof(*job));

    if (job == NULL)
        return -1;
    connection_get(connection);
    job->connection = connection;
    if (queue_job(job, status_worker) != 0) {
        connection_put(connection);
        free(job);
        return -1;
    }
    connection_put(connection);
    return 0;
}
