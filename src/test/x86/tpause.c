/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

enum cpuid_requests {
  CPUID_GETEXTENDEDFEATURES = 0x07,
};

static void cpuid(int code, int subrequest, unsigned int* a, unsigned int* c,
                  unsigned int* d) {
  asm volatile("cpuid"
               : "=a"(*a), "=c"(*c), "=d"(*d)
               : "a"(code), "c"(subrequest)
               : "ebx");
}

int main(void) {
  uint32_t eax, ecx, edx, state = 0;
#ifdef __x86_64__
  register uint32_t r15d __asm__("r15") = state;
#endif
  uint64_t tsc;

  cpuid(CPUID_GETEXTENDEDFEATURES, 0, &eax, &ecx, &edx);
  if (!(ecx & (1 << 5))) {
    // WAITPKG not present.
    atomic_puts("tpause not supported on this system, skipping");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  tsc = __rdtsc() + 1000;
  eax = tsc;
  edx = tsc >> 32;

  asm volatile(
    ".byte 0x66, 0x0f, 0xae, 0xf7;"  // tpause %edi
    "lahf;"
    : "+a"(eax), "+d"(edx)
    : "D"(state)
    : "cc", "memory");

  // All the arith flags should be cleared except CF, which should be set.
  test_assert((uint8_t)(eax >> 8) == 0x3);

#ifdef __x86_64__
  tsc = __rdtsc() + 1000;
  eax = tsc;
  edx = tsc >> 32;

  // Test tpause with a REX prefix since the instruction length
  // is different.
  asm volatile(
    ".byte 0x66, 0x41, 0x0f, 0xae, 0xf7;"  // tpause %r15d
    "lahf;"
    : "+a"(eax), "+d"(edx)
    : "r"(r15d)
    : "cc", "memory");

  // All the arith flags should be cleared except CF, which should be set.
  test_assert((uint8_t)(eax >> 8) == 0x3);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
