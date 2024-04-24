/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(__attribute__((unused)) uintptr_t wp_addr) {}

void test(uintptr_t wp_addr, uintptr_t store_addr) {
  breakpoint(wp_addr);
  *(uint16_t *)store_addr = 0x0101;

  breakpoint(wp_addr);
  *(uint32_t *)store_addr = 0x02020202;

  breakpoint(wp_addr);
  *(uint64_t *)store_addr = 0x0303030303030303;
}

int main(void) {
  char* m = xmalloc(0x1000);
  uintptr_t aligned_addr = ((uintptr_t)m | 0xff) + 1;
  test(aligned_addr - 1, aligned_addr - 1);
  test(aligned_addr + 16, aligned_addr + 15);

  /* FIXME: Currently fails on arm64. */
  if (0) {
    test(aligned_addr + 15, aligned_addr + 16);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
