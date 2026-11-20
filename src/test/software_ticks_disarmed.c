/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A program that counts its own ticks (include/rr/softticks.h) replaces the
 * page of the countdown with a zero-filled one, as the initializer creates it
 * outside rr, and ticks there. rr leaves that mapping alone. A countdown with
 * its top bit set is disarmed and the ticks must not write it (outside rr all
 * threads tick the one countdown, and a store per tick would keep its cache
 * line moving between their cores); on x86-64 and aarch64 a countdown of 0
 * wraps to 2^64 - 1 at the first tick, which disarms it. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

static void ticks(void) {
  int i;
  for (i = 0; i < 1000; ++i) {
    RR_SOFTTICK();
  }
}

int main(void) {
  volatile uint64_t* countdown = (volatile uint64_t*)RR_SOFTTICKS_COUNTDOWN_ADDR;
  void* page = (void*)(RR_SOFTTICKS_COUNTDOWN_ADDR & ~4095L);

  RR_SOFTTICK();
  atomic_puts("replacing the countdown's page");
  test_assert(page == mmap(page, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
#ifdef __i386__
  /* Here a countdown of 0 has 2^32 ticks to go (the low word wraps without a
     borrow): the initializer disarms the page it creates. */
  *countdown = ~(uint64_t)0;
#else
  RR_SOFTTICK();
  test_assert(*countdown == ~(uint64_t)0);
#endif
  ticks();
  test_assert(*countdown == ~(uint64_t)0);
  /* Any value with the top bit set is disarmed. */
  *countdown = (uint64_t)1 << 63;
  ticks();
  test_assert(*countdown == (uint64_t)1 << 63);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
