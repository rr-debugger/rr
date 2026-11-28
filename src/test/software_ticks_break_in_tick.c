/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h) in a loop that
 * a timer signal interrupts, debugged with a breakpoint inside the i386 tick
 * sequence: at the borrow from the countdown's high word, which only runs
 * when the low word reaches 0, as when the countdown rr armed runs out. rr
 * must count the tick that stopped there (its borrow is still to come), arm
 * the countdown so that the borrow does not take from it, and recognize the
 * sequence despite the breakpoint; replay must reach every recorded event.
 * Elsewhere every place in the sequence but the trap runs at every tick (the
 * countdown is armed whenever rr runs us, so the guard never skips one), so
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
                       /* After the guard (testb, jnz) and the low
                          word's subl and jnz. */
                       ".set tick_bp, tick_seq + 18"
                       ::: RR_SOFTTICKS_TICK_CLOBBERS);
#else
  RR_SOFTTICK();
#endif
}

int main(void) {
  struct itimerval timer = { { 0, 500 }, { 0, 500 } };
  struct itimerval off = { { 0, 0 }, { 0, 0 } };
  long i;

  /* ITIMER_VIRTUAL, not ITIMER_REAL: it counts only the time we spend running
   * our own code, so the loop runs between any two signals however long rr
   * takes to record one. With ITIMER_REAL, if that takes longer than the
   * period, the next signal is due by the time the handler returns, every
   * time, and the loop never runs again. The kernel checks the timer at its
   * scheduler tick, so the signals can come only once per tick: allow for 20
   * of them at HZ=250. */
  signal(SIGVTALRM, handler);
  setitimer(ITIMER_VIRTUAL, &timer, NULL);
  for (i = 0; i < 30000000 && sigs < 20; ++i) {
    tick();
  }
  setitimer(ITIMER_VIRTUAL, &off, NULL);
#ifndef __i386__
  __asm__ __volatile__(".globl tick_bp\n\t"
                       ".type tick_bp, %%function\n"
                       "tick_bp:" ::: "memory");
#endif
  atomic_printf("signals: %d\n", sigs > 0);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
