#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct session {
    uint64_t id;
    int audit_fd;
    atomic_uint references;
};

extern pthread_mutex_t session_table_lock;
extern struct session *session_table_lookup(uint64_t id);
extern void write_audit_record(int fd, const char *message);

static void session_get(struct session *session)
{
    atomic_fetch_add(&session->references, 1);
}

static void session_put(struct session *session)
{
    if (atomic_fetch_sub(&session->references, 1) == 1)
        free(session);
}

/* Removal drops the table's reference after unlinking while holding the lock. */
void audit_session(uint64_t id, const char *message)
{
    struct session *session;

    pthread_mutex_lock(&session_table_lock);
    session = session_table_lookup(id);
    if (session != NULL)
        session_get(session);
    pthread_mutex_unlock(&session_table_lock);

    if (session != NULL) {
        write_audit_record(session->audit_fd, message);
        session_put(session);
    }
}
