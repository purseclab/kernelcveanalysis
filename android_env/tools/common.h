#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef size_t usize;

void print_hex(const u8 *bytes, usize count) {
  for (usize i = 0; i < count; i++) {
    printf("%02x", bytes[i]);
  }
  printf("\n");
}

#endif
