/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  int fd = open("file", O_RDWR | O_CREAT | O_TRUNC, 0700);
  void* block;
  void* mapped_file;
  void* dest;

  test_assert(fd >= 0);
  unlink("file");
  block = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(block != MAP_FAILED);
  mapped_file = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
  test_assert(mapped_file != MAP_FAILED);
  dest = mremap(mapped_file, page_size, page_size, MREMAP_FIXED | MREMAP_MAYMOVE,
                block);
  test_assert(dest == block);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
