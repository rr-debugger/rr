/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h) in a loop that
 * a timer signal interrupts, debugged with a breakpoint inside the i386 tick
 * sequence: at the borrow from the countdown's high word, which only runs
 * when the low word reaches 0, as when the countdown rr armed runs out. rr
 * must count the tick that stopped there (its borrow is still to come), arm
 * the countdown so that the borrow does not take from it, and recognize the
 * sequence despite the breakpoint; replay must reach every recorded event.
 * Elsewhere every place in the sequence but the trap runs at every tick, so
 * the breakpoint is after the loop. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

static volatile int sigs;

static void handler(__attribute__((unused)) int sig) { ++sigs; }

static __attribute__((noinline, noclone)) void tick(void) {
#ifdef __i386__
  __asm__ __volatile__("tick_seq:\n\t" RR_SOFTTICKS_TICK_ASM "\n\t"
                       ".globl tick_bp\n\t"
                       ".type tick_bp, @function\n\t"
                       ".set tick_bp, tick_seq + 9"
                       ::: RR_SOFTTICKS_TICK_CLOBBERS);
#else
  RR_SOFTTICK();
#endif
}

int main(void) {
  struct itimerval timer = { { 0, 500 }, { 0, 500 } };
  struct itimerval off = { { 0, 0 }, { 0, 0 } };
  long i;

  signal(SIGALRM, handler);
  setitimer(ITIMER_REAL, &timer, NULL);
  for (i = 0; i < 3000000 && sigs < 20; ++i) {
    tick();
  }
  setitimer(ITIMER_REAL, &off, NULL);
#ifndef __i386__
  __asm__ __volatile__(".globl tick_bp\n\t"
                       ".type tick_bp, %%function\n"
                       "tick_bp:" ::: "memory");
#endif
  atomic_printf("signals: %d\n", sigs > 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
