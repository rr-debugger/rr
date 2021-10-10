/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* ptr;

static char syscall_bytes[] =
#ifdef __x86_64__
    { 0x0f, 0x05, 0xc3 }
#elif __i386__
    { 0xcd, 0x80, 0xc3 }
#elif defined(__aarch64__)
    { 0x01, 0x00, 0x00, 0xd4,   // svc #0
      0xc0, 0x03, 0x5f, 0xd6 } // ret
#endif
;

static void do_write(int fd, const char* p) {
  size_t ret;
  size_t len = strlen(p);
#ifdef __x86_64__
  __asm__ __volatile__("call *%%rcx\n\t"
                       : "=a"(ret)
                       : "a"(SYS_write), "c"(ptr), "D"(fd), "S"(p), "d"(len));
#elif __i386__
  __asm__ __volatile__("call *%%esi\n\t"
                       : "=a"(ret)
                       : "a"(SYS_write), "S"(ptr), "b"(fd), "c"(p), "d"(len));
#elif __aarch64__
  register long x8 __asm__("x8") = SYS_write;
  register long x7 __asm__("x7") = (long)ptr;
  register long x0 __asm__("x0") = (long)fd;
  register long x1 __asm__("x1") = (long)p;
  register long x2 __asm__("x2") = (long)len;
  __asm__ __volatile__("blr x7\n\t"
                       : "+r"(x0)
                       : "r"(x1), "r"(x2), "r"(x7), "r"(x8));
  ret = x0;
#else
#error Unknown architecture
#endif
  test_assert(ret == len);
}

int main(void) {
  int fd = open("dummy", O_RDWR | O_CREAT | O_EXCL, 0700);
  test_assert(fd >= 0);
  unlink("dummy");
  test_assert(write(fd, syscall_bytes, sizeof(syscall_bytes)) ==
              sizeof(syscall_bytes));

  ptr = mmap(NULL, 2, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
  test_assert(ptr != MAP_FAILED);

  do_write(STDOUT_FILENO, "EXIT-SUCCESS\n");
  return 0;
}
