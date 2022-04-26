/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  unsigned int* cpu;
  unsigned int* node;

  ALLOCATE_GUARD(cpu, -1);
  ALLOCATE_GUARD(node, -1);
  /* The 'tcache' parameter is unused in all kernels rr works on */
  test_assert(0 == sys_getcpu(cpu, node));
  test_assert(*cpu <= 0xffffff);
  test_assert(*node <= 0xffffff);
  VERIFY_GUARD(cpu);
  VERIFY_GUARD(node);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
