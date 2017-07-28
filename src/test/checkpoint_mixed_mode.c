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

static void breakpoint(void) {}

int main(void) {
  size_t num_bytes = sysconf(_SC_PAGESIZE);
  int fd = create_segment(num_bytes);
  char* p = mmap(NULL, num_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  char* shared_p;

  p[0] = 77;

  shared_p = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);

  breakpoint();

  test_assert(p[0] == 77);
  test_assert(shared_p[0] == 0);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
