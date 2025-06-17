/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__i386__)
/* Don't do anything for 32 bit. */
#elif defined(__x86_64__)
/* nop x 8; rdtsc; mov -17(%rip),%r9; ret */
static const uint8_t code[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                                0x0f, 0x31, 0x4c, 0x8b, 0x0d, 0xef, 0xff, 0xff, 0xff,
                                0xc3 };

static unsigned long do_call(uint8_t* p) {
  unsigned long ret;
  __asm__ __volatile__("call *%1\n\t"
                       "mov %%r9,%%rax" : "=a"(ret) : "r"(p) : "r9", "rdx");
  return ret;
}

static void check_patch(uint8_t* p) { test_assert(p[8] == 0xe9); }
#else
#error unsupported arch
#endif

int main(void) {
#ifdef __x86_64__
  size_t page_size = sysconf(_SC_PAGESIZE);
  uint8_t* p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  memcpy(p, code, sizeof(code));

  test_assert(0 == mprotect(p, page_size, PROT_READ | PROT_EXEC));
  test_assert(do_call(p) == 0x9090909090909090L);
  check_patch(p); // If run outside of rr, we should die here.
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
