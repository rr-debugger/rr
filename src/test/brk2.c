/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  void* start = (void*)syscall(SYS_brk, 0);
  void* p = (void*)syscall(SYS_brk, start + 5000);
  int res;
  void* pp;
  void* q;
  void* r;

  res = mprotect((void*)(((long)start + 4095) & ~(long)4095), 4096, PROT_READ);
  test_assert(res == 0);

  pp = (void*)syscall(SYS_brk, 0);
  test_assert(pp == p);

  *(char*)p = 77;
  q = (void*)syscall(SYS_brk, p + 5000);
  test_assert(p + 5000 == q);
  test_assert(*(char*)p == 77);

  r = (void*)syscall(SYS_brk, start + 1);
  test_assert(start < r);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
