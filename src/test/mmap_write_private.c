/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("output", O_RDWR | O_CREAT, 0777);
  int fd2;
  char* p = (char*)mmap(NULL, 10, PROT_READ,
                        MAP_PRIVATE, fd, 0);
  test_assert(p != MAP_FAILED);

  /* Opening a MAP_PRIVATE-mapped file writable is potentially
     problematic, but it should at least be OK if we don't write to
     it. */
  fd2 = open("output", O_RDWR, 0777);
  test_assert(fd2 >= 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
