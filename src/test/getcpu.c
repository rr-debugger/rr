/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  unsigned* cpu;
  unsigned* node;

  ALLOCATE_GUARD(cpu, -1);
  ALLOCATE_GUARD(node, -1);
  /* The 'tcache' parameter is unused in all kernels rr works on */
  test_assert(0 == syscall(SYS_getcpu, cpu, node, NULL));
  test_assert(*cpu <= 0xffffff);
  test_assert(*node <= 0xffffff);
  VERIFY_GUARD(cpu);
  VERIFY_GUARD(node);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
