/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifdef __i386__
static const uint8_t code[] = {
    0xcd, 0x80, // int $80
    0x90, // nop
    0x90, // nop
    0x90, // nop
    0xc3  // ret
};
#elif defined(__x86_64__)
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
#else
  #error unsupported arch
#endif

static long do_call(uint8_t* p) {
  long ret;
#if defined (__i386__) || defined(__x86_64__)
  __asm__ __volatile__("call *%2\n\t" : "=a"(ret) : "a"(SYS_getpid), "c"(p));
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = SYS_getpid;
  register long x0 __asm__("x0") = 0;
  __asm__ __volatile__("blr %2" : "=r"(x0) : "r"(x8), "r"(p) : "x30"); // x30 = lr
  ret = x0;
#else
  #error unsupported arch
#endif
  return ret;
}

static void check_patch(uint8_t* p)
{
#if defined (__i386__) || defined(__x86_64__)
  test_assert(p[0] == 0xe9);
#elif defined(__aarch64__)
  uint32_t inst;
  memcpy(&inst, p, sizeof(inst));
  // b to immediate instruction
  test_assert((inst & 0xfc000000) == 0x14000000);
#else
  #error unsupported arch
#endif
}

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  uint8_t* p = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  uint8_t* d = p + page_size - sizeof(code);
  pid_t pid;
  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + page_size, page_size));
  memcpy(d, code, sizeof(code));

  test_assert(0 == mprotect(p, page_size, PROT_READ | PROT_EXEC));
  pid = do_call(d);
  do_call(d);
  check_patch(d);
  test_assert(pid == getpid());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
