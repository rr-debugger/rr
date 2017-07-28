/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int create_segment(size_t num_bytes) {
  char filename[] = "/dev/shm/rr-test-XXXXXX";
  int fd = mkstemp(filename);
  unlink(filename);
  test_assert(fd >= 0);
  ftruncate(fd, num_bytes);
  return fd;
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  size_t num_bytes = 120; /* Not a multiple of the page size */
  int fd = create_segment(num_bytes);
  int* page = mmap(NULL, 2 * page_size, PROT_READ, MAP_SHARED, fd, 0);
  int* data_page = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  int magic = 0xa5a5a5a5;
  for (int* p = data_page; p < data_page + 2 * page_size / sizeof(magic); ++p) {
    *p = magic;
  }

  pwrite64(fd, data_page, 2 * page_size - num_bytes, num_bytes);

  test_assert(*(page + 2 * page_size / sizeof(magic) - 1) == magic);
  atomic_puts("EXIT-SUCCESS");

  return 0;
}
