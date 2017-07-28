/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <limits.h>

static const char dummy_filename[] = "dummy.txt";

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);

  // Request an address where casting to int could corrupt the address on 64-bit
  // (i.e. not near the top or bottom of memory).
  uint8_t* map = mmap((void*)(LONG_MAX / 2), page_size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  // Copy the filename there, and try to use creat. If the address gets
  // truncated, this can cause a segmentation fault.
  memcpy(map, dummy_filename, sizeof(dummy_filename));

  int fd = creat((const char*)map, 0600);
  close(fd);

  test_assert(access(dummy_filename, F_OK) == 0);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
