#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

void read_whole_file(FILE *file) {
  u8 buffer[4096];
  for (;;) {
    usize read_count = fread(buffer, sizeof(u8), 4096, file);
    if (read_count <= 0) {
      break;
    }
    print_hex(buffer, read_count);
  }
  printf("\n");
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "incorrect arg count\n");
    return 1;
  }

  FILE *f = fopen(argv[1], "r");
  if (f == NULL) {
    fprintf(stderr, "failed to open file\n");
    return 1;
  }

  usize offset = strtoull(argv[2], NULL, 10);
  fseek(f, offset, SEEK_SET);

  if (strcmp(argv[3], "-1") == 0) {
    read_whole_file(f);
    return 0;
  }

  usize len = strtoull(argv[3], NULL, 10);

  u8 *buf = calloc(len, sizeof(u8));
  fseek(f, offset, SEEK_SET);
  usize read_count = fread(buf, sizeof(u8), len, f);

  print_hex(buf, read_count);

  return 0;
}
