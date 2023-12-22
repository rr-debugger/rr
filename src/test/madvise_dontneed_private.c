/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = open("/proc/self/exe", O_RDONLY);
  test_assert(fd >= 0);
  char* p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE, fd, 0);
  test_assert(p != MAP_FAILED);
  char* backup = malloc(page_size);
  memcpy(backup, p, page_size);

  memset(p, 0, page_size);
  int ret = madvise(p, page_size, MADV_DONTNEED);
  test_assert(ret == 0);
  test_assert(memcmp(p, backup, page_size) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
