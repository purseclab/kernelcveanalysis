#include <stddef.h>
#include <stdint.h>

struct public_status {
    uint8_t state;
    uint64_t completed_jobs;
    uint16_t queue_depth;
};

extern uint8_t current_state(void);
extern uint64_t completed_job_count(void);
extern uint16_t current_queue_depth(void);
extern int copy_to_user(void *destination, const void *source, size_t size);

/* destination belongs to an untrusted process. */
int get_public_status(void *destination)
{
    struct public_status status = {0};

    status.state = current_state();
    status.completed_jobs = completed_job_count();
    status.queue_depth = current_queue_depth();
    return copy_to_user(destination, &status, sizeof(status));
}
