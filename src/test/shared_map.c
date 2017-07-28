/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd = open("tmp.txt", O_RDWR | O_CREAT | O_EXCL, 0700);
  ssize_t page_size = sysconf(_SC_PAGESIZE);
  char buf[page_size];
  char* p;
  char* q;
  pid_t child;
  int status;

  test_assert(fd >= 0);
  memset(buf, 1, sizeof(buf));
  test_assert(page_size == write(fd, buf, page_size));
  test_assert(0 == close(fd));

  fd = open("tmp.txt", O_RDWR);
  p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  test_assert(p[0] == 1);
  test_assert(p[9] == 1);
  test_assert(p[10] == 1);
  memset(p, 2, 10);

  child = fork();
  if (!child) {
    q = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    test_assert(q != MAP_FAILED);
    test_assert(q[0] == 2);
    test_assert(q[9] == 2);
    test_assert(q[10] == 1);
    return 77;
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  memset(buf, 3, 10);
  test_assert(10 == pwrite(fd, buf, 10, 0));
  test_assert(0 == fsync(fd));
  test_assert(0 == close(fd));
  test_assert(0 == unlink("tmp.txt"));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
