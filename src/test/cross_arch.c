/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if !defined(__i386__) && !defined(__x86_64__)
#error "Adjust or disable this test for your architecture"
#else
static int32_t my_syscall(uint32_t syscallno, uint32_t arg1, uint32_t arg2,
                          uint32_t arg3) {
  int32_t ret;
  /* Use int $0x80 to do the syscall. This will use the i386 syscall table
     regardless of whether or not this is a 64bit process or not */
  asm("int $0x80\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      : "=a"(ret)
      : "a"(syscallno), "b"(arg1), "c"(arg2), "d"(arg3));
  return ret;
}
#define SYS32_exit 1  /* write on x64 */
#define SYS32_write 4 /* stat on x64 */
#endif

char token[] = "EXIT-SUCCESS";
int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* low_buffer = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, 0, 0);
  memcpy(low_buffer, token, sizeof(token));
  test_assert(sizeof(token) == my_syscall(SYS32_write, STDOUT_FILENO,
                                          (uintptr_t)low_buffer,
                                          sizeof(token)));
  my_syscall(SYS32_exit, 0, 0, 0);
  test_assert(0 && "Should have exited");
  return 0;
}
