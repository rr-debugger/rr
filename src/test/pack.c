/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void map_file(const char* name) {
  int fd = open(name, O_RDONLY);
  void* p;

  test_assert(fd >= 0);
  p = mmap(NULL, 65536, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
  test_assert(p != MAP_FAILED);
}

int main(void) {
  map_file("mapped_file");
  map_file("mapped_file2");
  map_file("mapped_file3");
  map_file("mapped_file4");

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
