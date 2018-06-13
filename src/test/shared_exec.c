/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("output", O_RDWR | O_CREAT, 0777);
  int ret = write(fd, "x", 1);
  test_assert(ret == 1);
  char* p = (char*)mmap(NULL, 1, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  *p = 1;
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
