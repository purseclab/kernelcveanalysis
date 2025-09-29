#include <stdio.h>
#include <stdlib.h>
#include "common.h"

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "incorrect arg count\n");
    return 1;
  }

  usize offset = strtoull(argv[2], NULL, 10);
  usize len = strtoull(argv[3], NULL, 10);
  FILE *f = fopen(argv[1], "r");
  if (f == NULL) {
    fprintf(stderr, "failed to open file\n");
    return 1;
  }

  u8 *buf = calloc(len, sizeof(u8));
  fseek(f, offset, SEEK_SET);
  usize read_count = fread(buf, sizeof(u8), len, f);

  print_hex(buf, read_count);

  return 0;
}
