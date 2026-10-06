/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Our child locks a robust mutex in shared memory and then makes an
   exit_group syscall through an instruction that rr patches. We have rr
   SIGKILL the child just before patching it, after rr has taken the child
   out of the syscall. The kernel marks the mutex's owner as dead, and rr has
   to record that while the child is in its PTRACE_EVENT_EXIT stop, or replay
   of our pthread_mutex_lock() goes wrong.
   Our argument says where the child makes its exit_group:
   - none: in _exit(). rr patches it using the page of stubs that the child
     inherited. On 32-bit x86, _exit() makes its syscall through
     __kernel_vsyscall, which rr has patched already. There the child runs
     exit_group_code instead, from a page where we have had rr patch
     getpid_code before the fork, so the child inherits a page of stubs
     within reach of exit_group_code.
   - "far": in a page that none of rr's pages of stubs is within reach of.
     Patching it needs a new page of stubs, and mapping that fails because
     the child is dying. On x86-64 and aarch64, the page is farther from all
     other mappings than a patched instruction's jump to its stub can reach
     (2GB on x86-64, 128MB on aarch64). On 32-bit x86, that jump reaches
     every address, but a 64-bit rr only uses a page of stubs within 2GB of
     the instruction without wrapping around, and the page is more than 2GB
     above the rr page, right after which rr maps its first page of stubs. */

#if defined(__x86_64__)
/* exit_group(%edi), with 'syscall' followed by 'cmp $-4095,%rax', which
   matches a syscall patch hook */
static const uint8_t exit_group_code[] = {
  0xb8, 0xe7, 0x00, 0x00, 0x00,       /* mov $231,%eax */
  0x0f, 0x05,                         /* syscall */
  0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff, /* cmp $-4095,%rax */
  0xc3                                /* ret */
};
#elif defined(__aarch64__)
/* exit_group(x0), with 'svc #0', which matches the syscall patch hook */
static const uint8_t exit_group_code[] = {
  0xc8, 0x0b, 0x80, 0xd2, /* mov x8, #94 */
  0x01, 0x00, 0x00, 0xd4, /* svc #0 */
  0xc0, 0x03, 0x5f, 0xd6  /* ret */
};
#elif defined(__i386__)
/* getpid(), with 'int $0x80' followed by 'cmp $-4095,%eax', which matches
   a syscall patch hook */
static const uint8_t getpid_code[] = {
  0xb8, 0x14, 0x00, 0x00, 0x00, /* mov $20,%eax */
  0xcd, 0x80,                   /* int $0x80 */
  0x3d, 0x01, 0xf0, 0xff, 0xff, /* cmp $-4095,%eax */
  0xc3                          /* ret */
};
/* exit_group(4(%esp)), with the same instructions around 'int $0x80' */
static const uint8_t exit_group_code[] = {
  0x8b, 0x5c, 0x24, 0x04,       /* mov 4(%esp),%ebx */
  0xb8, 0xfc, 0x00, 0x00, 0x00, /* mov $252,%eax */
  0xcd, 0x80,                   /* int $0x80 */
  0x3d, 0x01, 0xf0, 0xff, 0xff, /* cmp $-4095,%eax */
  0xc3                          /* ret */
};
#else
#error unsupported arch
#endif

#ifdef __i386__
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define RR_PAGE_ADDR 0x70000000

/* Returns a new page more than 2GB above the rr page and the pages that rr
   maps right after it. We use 0xf8000000 if it's free. It normally is: the
   kernel puts the mappings it picks the address of at least 128MB below
   the top of the address space (0xffffe000), and the stack is at the top.
   Otherwise, e.g. if rr's chaos mode has put a mapping there, we look for
   another free page, in steps of 1MB. */
static uint8_t* map_far_page(size_t page_size) {
  const uintptr_t first = 0xf8000000;
  const uintptr_t start = RR_PAGE_ADDR + 0x80000000 + (1 << 20);
  const uintptr_t end = 0xfe000000;
  uintptr_t addr = first;

  do {
    uint8_t* p =
        mmap((void*)addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == (uint8_t*)addr) {
      return p;
    }
    /* Before Linux 4.17, the address is only a hint. */
    if (p != MAP_FAILED) {
      test_assert(0 == munmap(p, page_size));
    }
    addr += 1 << 20;
    if (addr == end) {
      addr = start;
    }
  } while (addr != first);
  test_assert(0 && "No free page far enough from the rr page");
  return NULL;
}

/* Returns a copy of exit_group_code in a new page. If `far`, the page is
   from map_far_page(). Otherwise we first run a copy of getpid_code in the
   page, and rr patches it using a page of stubs within reach of our page.
   The copies are half a page apart, farther than rr looks around an
   instruction for branches into the bytes it patches. */
static uint8_t* map_exit_group_code(int far) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  uint8_t* p;

  if (far) {
    p = map_far_page(page_size);
    memcpy(p, exit_group_code, sizeof(exit_group_code));
    return p;
  }
  p = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);
  memcpy(p, getpid_code, sizeof(getpid_code));
  memcpy(p + page_size / 2, exit_group_code, sizeof(exit_group_code));
  test_assert(((pid_t (*)(void))p)() == getpid());
  return p + page_size / 2;
}
#else
/* Runs exit_group_code from a page in the middle of an 8GB range that was
   free, i.e. 4GB from all other mappings. */
static void exit_group_far(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  size_t span = (size_t)8 << 30;
  uint8_t* p = mmap(NULL, span, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  uint8_t* code;

  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p, span));
  code = mmap(p + span / 2, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  test_assert(code == p + span / 2);
  memcpy(code, exit_group_code, sizeof(exit_group_code));
  __builtin___clear_cache((char*)code, (char*)code + sizeof(exit_group_code));
  ((void (*)(int))code)(0);
}
#endif

int main(int argc, char* argv[]) {
  pthread_mutex_t* mutex = mmap(NULL, sizeof(*mutex), PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  const char* mode = argc > 1 ? argv[1] : "";
  pthread_mutexattr_t attr;
  int status;
  pid_t child;
#ifdef __i386__
  uint8_t* code = map_exit_group_code(!strcmp(mode, "far"));
#endif

  test_assert(!strcmp(mode, "") || !strcmp(mode, "far"));
  test_assert(mutex != MAP_FAILED);
  test_assert(0 == pthread_mutexattr_init(&attr));
  test_assert(0 == pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
  test_assert(0 == pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST));
  test_assert(0 == pthread_mutex_init(mutex, &attr));

  child = fork();
  if (!child) {
    test_assert(0 == pthread_mutex_lock(mutex));
    rr_arm_kill(RRCALL_KILL_BEFORE_SYSCALL_PATCH, SYS_exit_group, 0);
#ifdef __i386__
    ((void (*)(int))code)(0);
#else
    if (!strcmp(mode, "far")) {
      exit_group_far();
    }
#endif
    _exit(0);
  }
  test_assert(child == waitpid(child, &status, 0));
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
    atomic_puts("child was killed");
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }
  test_assert(EOWNERDEAD == pthread_mutex_lock(mutex));
  test_assert(0 == pthread_mutex_consistent(mutex));
  test_assert(0 == pthread_mutex_unlock(mutex));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
