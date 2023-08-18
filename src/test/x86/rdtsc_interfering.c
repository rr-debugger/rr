/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

void do_rdtsc_loop(uint32_t with_jump) {
#ifdef __x86_64__
  int i;

  uint64_t prev_tsc = 0;
  for (i = 0; i < 2500000; ++i) {
    uint32_t out;
    uint32_t out_hi;
    asm volatile ("test %%rcx, %%rcx\n\t"
                  // This branch is useless, but let's make sure it works anyway.
                  // In practice, we mostly want to make sure that spurious interfering
                  // branches don't prevent patching so that the `nopl 0(%ax, %ax, 1); rdtsc`
                  // sequence is guaranteed to patch properly.
                  "jnz 1f\n\t"
                  ".byte 0x0f, 0x1f, 0x44, 0x00, 0x00\n\t"
                  "1: rdtsc\n\t"
                  : "=a"(out), "=d"(out_hi)
                  : "c"(with_jump)
                  : "cc");
    uint64_t tsc = ((uint64_t)out_hi << 32) + out;
    test_assert(prev_tsc < tsc);
    prev_tsc = tsc;
  }
#endif
  (void)with_jump;
}

uint64_t rdtsc_interfering_sideeffect(uint32_t do_jump) {
  uint64_t check = 0xdeadbeef;
  uint64_t challenge = 0xfeedbeef;
  uint32_t out = 0;
  uint32_t out_hi = 0;
#ifdef __x86_64__
  asm volatile (
              "xor %%rbx, %%rbx\n\t" // Zero rbx
              "test %%rcx, %%rcx\n\t"
              // This branch is useless, but let's make sure it works anyway.
              // In practice, we mostly want to make sure that spurious interfering
              // branches don't prevent patching so that the `nopl 0(%ax, %ax, 1); rdtsc`
              // sequence is guaranteed to patch properly.
              "jnz 1f\n\t"
              // What instruction exactly this is doesn't really matter, all we
              // care about is that it has a syscallbuf patch and that we can check
              // whether it ran or not.
              "mov %%rdi,%%rbx\n\t"
              "1: rdtsc\n\t"
              : "=a"(out), "=d"(out_hi), "=b"(check)
              : "c"(do_jump), "D"(challenge)
              : "cc");
#endif
  test_assert(check == (do_jump ? 0 : challenge));
  return ((uint64_t)out_hi << 32) + out;
}

int main(void) {
  uint64_t tsc1 = rdtsc_interfering_sideeffect(0);
  uint64_t tsc2 = rdtsc_interfering_sideeffect(1);
  test_assert(tsc1 < tsc2);
  do_rdtsc_loop(0);
  do_rdtsc_loop(1);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
