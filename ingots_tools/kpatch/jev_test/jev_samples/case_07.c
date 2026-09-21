#include <stddef.h>
#include <syslog.h>

static void trim_newline(char *message)
{
    size_t index;

    for (index = 0; message[index] != '\0'; ++index) {
        if (message[index] == '\n') {
            message[index] = '\0';
            return;
        }
    }
}

/* message is supplied by an unauthenticated remote client. */
void audit_client_error(char *message)
{
    trim_newline(message);
    if (message[0] != '\0')
        syslog(LOG_WARNING, message);
}
