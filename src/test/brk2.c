/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  long pagesize = sysconf(_SC_PAGESIZE);
  long pagemask = pagesize - 1;
  long offset = pagesize + 1000;
  void* start = (void*)syscall(SYS_brk, (void*)0);
  void* p = (void*)syscall(SYS_brk, start + offset);
  int res;
  void* pp;
  void* q;
  void* r;

  res = mprotect((void*)(((long)start + pagesize - 1) & ~pagemask), pagesize, PROT_READ);
  test_assert(res == 0);

  pp = (void*)syscall(SYS_brk, (void*)0);
  test_assert(pp == p);

  *(char*)p = 77;
  q = (void*)syscall(SYS_brk, p + offset);
  test_assert(p + offset == q);
  test_assert(*(char*)p == 77);

  r = (void*)syscall(SYS_brk, start + 1);
  test_assert(start < r);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
