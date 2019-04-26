/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("output", O_RDWR | O_CREAT, 0777);
  int fd2 = dup(fd);
  /* create a new file description */
  int fd3 = open("output", O_RDWR, 0777);
  int fd4;
  int fd5 = open("output", O_RDONLY, 0777);
  int ret;
  char* p = (char*)mmap(NULL, 10, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);

  ret = write(fd, "x", 1);
  test_assert(ret == 1);
  test_assert(p[0] == 'x');

  ret = write(fd2, "y", 1);
  test_assert(ret == 1);
  test_assert(p[1] == 'y');  

  ret = write(fd3, "z", 1);
  test_assert(ret == 1);
  test_assert(p[0] == 'z');  

  /* Check that an open after the mmap works */
  fd4 = open("output", O_RDWR, 0777);
  ret = write(fd4, "a", 1);
  test_assert(ret == 1);
  test_assert(p[0] == 'a');  

  /* Unmap, write, remap and write again to make sure that works. */
  munmap(p, 10);

  ret = write(fd4, "b", 1);
  test_assert(ret == 1);

  p = (char*)mmap(NULL, 10, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);

  ret = write(fd4, "c", 1);
  test_assert(ret == 1);
  test_assert(p[1] == 'b');
  test_assert(p[2] == 'c');

  /* Make sure a shared mapping from a read-only fd also works */
  p = (char*)mmap(NULL, 10, PROT_READ, MAP_SHARED, fd5, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[1] == 'b');
  test_assert(p[2] == 'c');

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
