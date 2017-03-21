/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define RR_PAGE_ADDR 0x70000000

uintptr_t unmappings[1000];
ssize_t nunmappings;

int main(void);
static int contains_symbol(map_properties_t* props, void* symbol) {
  return (props->start <= (uintptr_t)symbol && (uintptr_t)symbol < props->end);
}
void callback(uint64_t env, char* name, map_properties_t* props) {
  if (contains_symbol(props, &main) || contains_symbol(props, unmappings) ||
      /* env is on the stack - this prevents it from being unmapped if
         the kernel gets confused by syscallbuf's stack switching */
      contains_symbol(props, &env) || props->start == RR_PAGE_ADDR ||
      strcmp(name, "[stack]") == 0) {
    return;
  }

  unmappings[2 * nunmappings] = (uintptr_t)props->start;
  unmappings[2 * nunmappings + 1] = (uintptr_t)(props->end - props->start);
  ++nunmappings;
}

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static void my_syscall(uintptr_t syscallno, uintptr_t arg1, uintptr_t arg2,
                       uintptr_t arg3, uintptr_t arg4) {
#ifdef __i386__
  __asm__ __volatile__("int $0x80\n\t" ::"a"(syscallno), "b"(arg1), "c"(arg2),
                       "d"(arg3), "S"(arg4));
#elif defined(__x86_64__)
  register long r10 asm("r10") = arg4;
  __asm__ __volatile__("syscall\n\t" ::"a"(syscallno), "D"(arg1), "S"(arg2),
                       "d"(arg3), "r"(r10));
#else
#error Fill in syscall here
#endif
}

int main(void) {
  FILE* maps_file = fopen("/proc/self/maps", "r");
  int i = 0;
  // Scan and record mappings - we can't mmap over them yet because libc will
  // be gone at some point. After iterate_maps, no C library calls are allowed
  iterate_maps(0, callback, maps_file);
  for (i = 0; i < nunmappings; ++i) {
    my_syscall(RR_mmap2, unmappings[2 * i], unmappings[2 * i + 1], PROT_NONE,
               MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS);
  }
  breakpoint();
  my_syscall(RR_exit, 0, 0, 0, 0);
  // Never reached, but make compiler happy.
  return 1;
}
