/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h) maps over the
 * page of the countdown, then makes syscalls without ticking. rr must leave
 * that mapping alone instead of programming a countdown in it. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

int main(void) {
  int i;
  RR_SOFTTICK();
  atomic_puts("replacing the countdown's page");
  syscall(RR_mmap, RR_SOFTTICKS_COUNTDOWN_ADDR & ~4095L, 4096L, PROT_NONE,
          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1L, 0L);
  /* No ticks from here on: they would fault. */
  for (i = 0; i < 3; ++i) {
    syscall(RR_getpid);
  }
  syscall(RR_write, STDOUT_FILENO, "EXIT-SUCCESS\n", 13);
  syscall(RR_exit_group, 0);
  return 1;
}
