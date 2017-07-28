/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Tests that we can do a syscall from a syscall instruction located on a
   MAP_SHARED page */

static uintptr_t my_syscall(uintptr_t syscall, uintptr_t arg1) {
  uintptr_t ret;
#ifdef __x86_64__
  __asm__ volatile("syscall\n\t" : "=a"(ret) : "a"(syscall), "D"(arg1));
#elif defined(__i386__)
  __asm__ volatile("int $0x80\n\t" : "=a"(ret) : "a"(syscall), "b"(arg1));
#else
#error define syscall here
#endif
  return ret;
}

extern char __executable_start;
void my_brk(uintptr_t brk) { my_syscall(SYS_brk, brk); }

int main(void) {
  /* map another copy of this executable (but MAP_SHARED this time) */
  int fd = open("/proc/self/exe", O_RDONLY);
  test_assert(fd != -1);

  /* Get the size of this executable */
  struct stat stat_buf;
  test_assert(fstat(fd, &stat_buf) == 0);

  /* Map the executable */
  void* map_addr =
      mmap(NULL, stat_buf.st_size, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
  test_assert(map_addr != MAP_FAILED);

  /* Call my_sbrk in the new copy */
  void (*fptr)(uintptr_t) = (void (*)(uintptr_t))(
      (uintptr_t)map_addr +
      ((uintptr_t)&my_brk - (uintptr_t)&__executable_start));
  fptr((uintptr_t)sbrk(0) + sysconf(_SC_PAGESIZE));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
