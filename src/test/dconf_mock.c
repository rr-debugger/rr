/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, __attribute__((unused)) char* argv[]) {
  int fd;
  volatile char* p;
  int count = 0;

  if (argc == 1) {
    test_assert(0 == mkdir("dconf", 0700));
  }
  fd = open("dconf/user", O_CREAT | O_RDWR, 0600);
  test_assert(fd >= 0);
  test_assert(0 == ftruncate(fd, 2));
  size_t page_size = sysconf(_SC_PAGESIZE);
  p = (char*)mmap(NULL, page_size, PROT_READ | (argc == 2 ? PROT_WRITE : 0),
                  MAP_SHARED, fd, 0);
  test_assert(MAP_FAILED != p);

  if (argc == 2) {
    *p = 1;
    test_assert(0 == unlink("dconf/user"));
    test_assert(0 == rmdir("dconf"));
    return 0;
  }

  atomic_puts("ready");
  while (*p == 0) {
    ++count;
    sched_yield();
  }

  atomic_printf("Count = %d\n", count);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
