/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define MAX_ERRNO 4095

#define RR_PAGE_ADDR 0x70000000
#define RR_THREAD_LOCALS_PAGE_ADDR 0x70001000

struct Unmaps {
  uintptr_t unmappings[1000];
  ssize_t nunmappings;
};

int main(void);
static int contains_symbol(map_properties_t* props, void* symbol) {
  return (props->start <= (uintptr_t)symbol && (uintptr_t)symbol < props->end);
}
void callback(uint64_t env, char* name, map_properties_t* props) {
  if (contains_symbol(props, &main) ||
      /* env is on the stack - this prevents it from being unmapped if
         the kernel gets confused by syscallbuf's stack switching */
      contains_symbol(props, &env) || props->start == RR_PAGE_ADDR ||
      strcmp(name, "[stack]") == 0) {
    return;
  }

  struct Unmaps* u = (struct Unmaps*)(size_t)env;
  u->unmappings[2 * u->nunmappings] = (uintptr_t)props->start;
  u->unmappings[2 * u->nunmappings + 1] = (uintptr_t)(props->end - props->start);
  ++u->nunmappings;
}

static __attribute__((noinline)) void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

intptr_t my_syscall(intptr_t syscallno, intptr_t arg1, intptr_t arg2,
                    intptr_t arg3, intptr_t arg4, intptr_t arg5, intptr_t arg6);

#ifdef __i386__
__asm__("my_syscall:\n\t"
        "push %ebp\n\t"
        "push %esi\n\t"
        "push %edi\n\t"
        "push %ebx\n\t"
        "mov 20(%esp),%eax\n\t"
        "mov 24(%esp),%ebx\n\t"
        "mov 28(%esp),%ecx\n\t"
        "mov 32(%esp),%edx\n\t"
        "mov 36(%esp),%esi\n\t"
        "mov 40(%esp),%edi\n\t"
        "mov 44(%esp),%ebp\n\t"
        "int $0x80\n\t"
        "pop %ebx\n\t"
        "pop %edi\n\t"
        "pop %esi\n\t"
        "pop %ebp\n\t"
        "ret\n\t");
#elif defined(__x86_64__)
__asm__("my_syscall:\n\t"
        "mov %rdi,%rax\n\t"
        "mov %rsi,%rdi\n\t"
        "mov %rdx,%rsi\n\t"
        "mov %rcx,%rdx\n\t"
        "mov %r8,%r10\n\t"
        "mov %r9,%r8\n\t"
        "mov 8(%rsp),%r9\n\t"
        "syscall\n\t"
        "ret\n\t");
#elif defined(__aarch64__)
__asm__("my_syscall:\n\t"
        "mov x8,x0\n\t"
        "mov x0,x1\n\t"
        "mov x1,x2\n\t"
        "mov x2,x3\n\t"
        "mov x3,x4\n\t"
        "mov x4,x5\n\t"
        "mov x5,x6\n\t"
        "svc #0\n\t"
        "ret\n\t");
#else
#error Fill in syscall here
#endif

int main(void) {
  FILE* maps_file = fopen("/proc/self/maps", "r");
  int i = 0;
  struct Unmaps u;
  u.nunmappings = 0;
  // Scan and record mappings - we can't mmap over them yet because libc will
  // be gone at some point. After iterate_maps, no C library calls are allowed
  iterate_maps((size_t)&u, callback, maps_file);
  for (i = 0; i < u.nunmappings; ++i) {
    const int mmap_syscall =
#ifdef __i386__
        RR_mmap2
#elif defined(__x86_64__) || defined(__aarch64__)
        RR_mmap
#else
#error Fill in syscall here
#endif
        ;
    int ret =
        my_syscall(mmap_syscall, u.unmappings[2 * i], u.unmappings[2 * i + 1],
                   PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    // We can't even use test_assert here, because it'll call strerror to printf
    // the failure
    // and we're unmapping libc).
    // NB: Trying to mess with the highest pages on x86-64 gets us an ENOMEM
    // error.
    if (ret <= 0 && ret >= -MAX_ERRNO && ret != -ENOMEM) {
      my_syscall(RR_exit, ret, 0, 0, 0, 0, 0);
    }
  }

  my_syscall(RR_mprotect, RR_THREAD_LOCALS_PAGE_ADDR, 4096,
             PROT_READ | PROT_WRITE, 0, 0, 0);
  *((uint64_t*)RR_THREAD_LOCALS_PAGE_ADDR) = RR_PAGE_ADDR;
  my_syscall(RR_mprotect, RR_THREAD_LOCALS_PAGE_ADDR, 4096, PROT_NONE, 0, 0, 0);

  breakpoint();

  my_syscall(RR_mprotect, RR_THREAD_LOCALS_PAGE_ADDR, 4096, PROT_READ, 0, 0, 0);
  int ret =
      (*((uint64_t*)RR_THREAD_LOCALS_PAGE_ADDR) == RR_PAGE_ADDR) ? 0 : -42;

  my_syscall(RR_exit, ret, 0, 0, 0, 0, 0);
  // Never reached, but make compiler happy.
  return 1;
}
