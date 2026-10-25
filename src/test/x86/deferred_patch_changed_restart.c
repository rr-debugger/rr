/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The main thread blocks in futex() waits made from 'mov $0xca,%eax;
   syscall', a site rr patches at the syscall's exit, since the patch
   region ends with the syscall instruction. Another thread interrupts each
   wait with a signal, and the futex() doesn't restart as it was:
   - At the first site, SIGUSR1's SA_RESTART handler changes the syscall
     number to getppid().
   - At the second site, SIGALRM's handler has no SA_RESTART, so the
     futex() fails with EINTR.
   Each site must return what the syscall made there returns, and rr must
   have patched each site when it returns. */

#if defined(__x86_64__)

/* Each site starts a 256-byte block, so that rr's check for branches into
   the patch region doesn't find bytes of the next function that look like
   one. */
#define FUTEX_SITE(name)                                                     \
  extern char name##_start[] __attribute__((visibility("hidden")));        \
  static __attribute__((noinline, aligned(256))) long name(                \
      int* uaddr, int op, int val) {                                       \
    long ret;                                                              \
    register long r10 __asm__("r10") = 0;                                  \
    __asm__ volatile(#name "_start:\n\t"                                   \
                     "mov $0xca,%%eax\n\t"                                 \
                     "syscall\n\t"                                         \
                     /* Match no hook pattern with the following bytes */ \
                     "cmp $0x77,%%rax\n\t"                                 \
                     : "=a"(ret)                                           \
                     : "D"(uaddr), "S"((long)op), "d"((long)val), "r"(r10) \
                     : "rcx", "r11", "flags", "memory");                   \
    return ret;                                                            \
  }

FUTEX_SITE(futex_site_new_syscall)
FUTEX_SITE(futex_site_no_restart)

enum TestCase { NEW_SYSCALL, NO_RESTART };

static int word_a;
static int other_word;
static pid_t main_tid;
static enum TestCase test_case;

static void handle_usr1(__attribute__((unused)) int sig,
                        __attribute__((unused)) siginfo_t* si, void* user) {
  ucontext_t* ctx = (ucontext_t*)user;
  test_assert(ctx->uc_mcontext.gregs[REG_RAX] == SYS_futex);
  test_assert(ctx->uc_mcontext.gregs[REG_RDI] == (long)&word_a);
  ctx->uc_mcontext.gregs[REG_RAX] = SYS_getppid;
}

static void handle_alrm(__attribute__((unused)) int sig) {}

static void* signal_thread(__attribute__((unused)) void* p) {
  pid_t tid = __atomic_load_n(&main_tid, __ATOMIC_SEQ_CST);
  enum TestCase tc = __atomic_load_n(&test_case, __ATOMIC_SEQ_CST);
  test_assert(tid > 1);
  wait_for_task_asleep_in_syscall(tid, SYS_futex, (long)&word_a);
  test_assert(0 == syscall(SYS_tgkill, getpid(), tid,
                           tc == NO_RESTART ? SIGALRM : SIGUSR1));
  return NULL;
}

typedef void* (*SyscallbufPtr)(void);

/* rr patches syscall sites when it records with the syscall buffer, i.e.
   when its preload library gave this thread a syscall buffer. */
static int syscallbuf_enabled(void) {
  SyscallbufPtr syscallbuf_ptr =
      (SyscallbufPtr)dlsym(RTLD_DEFAULT, "syscallbuf_ptr");
  return syscallbuf_ptr && syscallbuf_ptr();
}

static void check_patched(long (*futex_site)(int*, int, int), char* start,
                          int patched) {
  int i;
  /* A patched site starts with a jump to rr's stub. */
  if (patched) {
    test_assert((uint8_t)start[0] == 0xe9);
  }
  for (i = 0; i < 3; ++i) {
    test_assert(0 == futex_site(&other_word, FUTEX_WAKE, 1));
  }
}

int main(void) {
  struct sigaction sa;
  pthread_t thread;
  int patched = syscallbuf_enabled();

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = handle_usr1;
  sa.sa_flags = SA_RESTART | SA_SIGINFO;
  test_assert(0 == sigaction(SIGUSR1, &sa, NULL));
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_alrm;
  test_assert(0 == sigaction(SIGALRM, &sa, NULL));
  __atomic_store_n(&main_tid, sys_gettid(), __ATOMIC_SEQ_CST);

  __atomic_store_n(&test_case, NEW_SYSCALL, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  test_assert(getppid() == futex_site_new_syscall(&word_a, FUTEX_WAIT, 0));
  test_assert(0 == pthread_join(thread, NULL));
  check_patched(futex_site_new_syscall, futex_site_new_syscall_start, patched);

  __atomic_store_n(&test_case, NO_RESTART, __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, signal_thread, NULL));
  test_assert(-EINTR == futex_site_no_restart(&word_a, FUTEX_WAIT, 0));
  test_assert(0 == pthread_join(thread, NULL));
  check_patched(futex_site_no_restart, futex_site_no_restart_start, patched);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif
