// common headers which may be needed
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>

#include <exp_common.h>
#include <root_payload.h>

void exploit() {
  puts("Hello world");

  root_payload();
}

#define EXPLOIT_MAIN exploit();
#include <exploit_entry.h>
