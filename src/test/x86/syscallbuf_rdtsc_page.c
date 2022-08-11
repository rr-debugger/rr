/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifdef __i386__
int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
#else
static const uint8_t code[6] = {
  0x0f, 0x31, /* rdtsc */
  /* nop; nop; nop; ret */
  0x90, 0x90, 0x90, 0xc3,
};

static long do_call(uint8_t* page, uint8_t* code, int ecx) {
  long ret;
  mprotect(page, 1, PROT_READ | PROT_EXEC);
  __asm__ __volatile__("call *%3\n\t" : "=a"(ret) :
                       "a"(SYS_sched_yield), "c"(ecx), "d"(code));
  mprotect(page, 1, PROT_READ | PROT_WRITE);
  return ret;
}

static const uint64_t GB = 1024*1024*1024;

int main(void) {
  uint8_t* p = mmap(NULL, 9*GB, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
  test_assert(p != MAP_FAILED);
  munmap(p, 4*GB);
  munmap(p + 5*GB, 4*GB);

  p += 4*GB;
  memcpy(p, code, sizeof(code));
  /* Force allocation of a new syscallbuf stub page for this call */
  do_call(p, p, 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
#endif
