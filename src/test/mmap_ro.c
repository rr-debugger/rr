/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define DUMMY_FILE "dummy.txt"

int main(void) {
  size_t num_bytes = sysconf(_SC_PAGESIZE);
  int fd = open(DUMMY_FILE, O_CREAT | O_EXCL | O_RDWR, 0600);
  int one = 1;
  int* rpage;

  test_assert(fd >= 0);

  test_assert(sizeof(one) == write(fd, &one, sizeof(one)));

  test_assert(0 == fchmod(fd, 0400));

  rpage = mmap(NULL, num_bytes, PROT_READ, MAP_SHARED, fd, 0);
  test_assert(rpage != (void*)-1);

  unlink(DUMMY_FILE);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
