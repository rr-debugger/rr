/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* ptr;

static char syscall_bytes[] =
#ifdef __x86_64__
    { 0x0f, 0x05, 0xc3 }
#elif __i386__
    { 0xcd, 0x80, 0xc3 }
#else
#error Unknown architecture
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
