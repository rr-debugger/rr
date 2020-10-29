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
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = syscall;
  register long x0 __asm__("x0") = (long)arg1;
  __asm__ volatile("svc #0\n\t" : "+r"(x0) : "r"(x8));
  ret = x0;
#else
#error define syscall here
#endif
  return ret;
}

void my_brk(uintptr_t brk) { my_syscall(SYS_brk, brk); }

static uint64_t my_brk_file_offset;

static void callback(__attribute__((unused)) uint64_t env, __attribute__((unused)) char* name, map_properties_t* props) {
  uint64_t addr = (uintptr_t)my_brk;
  if (props->start <= addr && addr < props->end) {
    my_brk_file_offset = addr - props->start + props->offset;
  }
}

int main(void) {
  FILE* maps_file;
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

  maps_file = fopen("/proc/self/maps", "r");
  iterate_maps(0, callback, maps_file);

  /* Call my_sbrk in the new copy */
  void (*fptr)(uintptr_t) = (void (*)(uintptr_t))(
      (uintptr_t)map_addr + (uintptr_t)my_brk_file_offset);
  fptr((uintptr_t)sbrk(0) + sysconf(_SC_PAGESIZE));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
