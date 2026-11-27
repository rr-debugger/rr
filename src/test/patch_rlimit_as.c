/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Tests that rr copes with being unable to allocate a stub page to patch a
   syscall because the tracee has lowered RLIMIT_AS below its current address
   space size (e.g. a forked child about to exec). */

#if defined(__x86_64__)
static const uint8_t code[] = {
    0x0f, 0x05, // syscall
    0x90, // nop
    0x90, // nop
    0x90, // nop
    0xc3  // ret
};
#elif defined(__aarch64__)
static const uint8_t code[] = {
    0x1, 0x0, 0x0, 0xd4,    // svc #0
    0xc0, 0x03, 0x5f, 0xd6, // ret
};
#endif

#if defined(__x86_64__) || defined(__aarch64__)
static long do_call(uint8_t* p) {
  long ret;
#if defined(__x86_64__)
  __asm__ __volatile__("call *%2\n\t" : "=a"(ret) : "a"(SYS_getpid), "c"(p));
#else
  register long x8 __asm__("x8") = SYS_getpid;
  register long x0 __asm__("x0") = 0;
  __asm__ __volatile__("blr %2" : "=r"(x0) : "r"(x8), "r"(p) : "x30"); // x30 = lr
  ret = x0;
#endif
  return ret;
}
#endif

int main(void) {
#if defined(__x86_64__) || defined(__aarch64__)
  size_t page_size = sysconf(_SC_PAGESIZE);
  /* Put the code far from everything else, so patching it needs a new stub
     page. */
  uint8_t* p = mmap((void*)0x100000000000, page_size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
  struct rlimit old_limit;
  struct rlimit limit;
  pid_t pid;
  test_assert(p != MAP_FAILED);
  memcpy(p, code, sizeof(code));
  test_assert(0 == mprotect(p, page_size, PROT_READ | PROT_EXEC));

  test_assert(0 == getrlimit(RLIMIT_AS, &old_limit));
  limit = old_limit;
  /* Far smaller than our current address space, so any new mapping fails. */
  limit.rlim_cur = 64 * 1024;
  test_assert(0 == setrlimit(RLIMIT_AS, &limit));
  pid = do_call(p);
  test_assert(0 == setrlimit(RLIMIT_AS, &old_limit));

  test_assert(pid == getpid());
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
