/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__i386__)
/* Don't do anything for 32 bit. */
#elif defined(__x86_64__)
static const uint8_t code[] = { 0x40, 0x80, 0xf6, 0x81, 0x0f, 0x05, 0xc3, 0x99 };

static long do_call(pid_t pid, uint8_t* p) {
  long ret;
  __asm__ __volatile__("call *%2\n\t" : "=a"(ret) : "a"(SYS_kill), "c"(p), "D"(pid), "S"(0x8F));
  return ret;
}

static void check_patch(uint8_t* p) { test_assert(p[0] == 0xe9); }

static int caught_signal = 0;
static void handle_signal(__attribute__((unused)) int sig) { ++caught_signal; }
#else
#error unsupported arch
#endif

int main(void) {
#ifdef __x86_64__
  signal(SIGALRM, handle_signal);

  size_t page_size = sysconf(_SC_PAGESIZE);
  uint8_t* p = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  pid_t pid = getpid();
  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + page_size, page_size));
  memcpy(p, code, sizeof(code));

  test_assert(0 == mprotect(p, page_size, PROT_READ | PROT_EXEC));
  do_call(pid, p);
  do_call(pid, p);
  test_assert(caught_signal == 2);
  check_patch(p); // If run outside of rr, we should die here.
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
