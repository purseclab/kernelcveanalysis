#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct session {
    uint64_t id;
    int audit_fd;
};

extern pthread_mutex_t session_table_lock;
extern struct session *session_table_lookup(uint64_t id);
extern void write_audit_record(int fd, const char *message);

/* Removal takes session_table_lock, unlinks the entry, and immediately frees it. */
void remove_session(uint64_t id);

void audit_session(uint64_t id, const char *message)
{
    struct session *session;

    pthread_mutex_lock(&session_table_lock);
    session = session_table_lookup(id);
    pthread_mutex_unlock(&session_table_lock);

    if (session != NULL)
        write_audit_record(session->audit_fd, message);
}
