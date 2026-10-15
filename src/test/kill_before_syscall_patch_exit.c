/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* Our child's main thread makes a syscall through an instruction sequence
   that rr patches at syscall entry, and has rr SIGKILL it just before rr
   takes it out of the syscall to patch it. So the patching fails with the
   task stopped at its PTRACE_EVENT_EXIT. rr must then handle that exit,
   not carry on as if the syscall had been entered (which would resume the
   task out of its PTRACE_EVENT_EXIT stop). The child has another thread so
   that its main thread can't be reaped as soon as it gets past
   PTRACE_EVENT_EXIT. */

static long patchable_getppid(void) {
  long ret = SYS_getppid;
#ifdef __x86_64__
  /* 'syscall' followed by 'cmp $-4095,%rax' matches a syscall patch hook. */
  __asm__ __volatile__("syscall\n\t"
                       "cmp $-4095,%%rax\n\t"
                       : "+a"(ret)
                       :
                       : "rcx", "r11", "memory", "cc");
#else
  ret = syscall(SYS_getppid);
#endif
  return ret;
}

static void* do_thread(__attribute__((unused)) void* p) {
  pause();
  return NULL;
}

/* rr only patches syscalls when the syscallbuf is enabled. */
static int will_patch_syscalls(void) {
#ifdef __x86_64__
  return getenv("_RR_USE_SYSCALLBUF") != NULL;
#else
  return 0;
#endif
}

int main(void) {
  int status;
  int expect_kill =
      rr_arm_kill(RRCALL_KILL_NONE, 0, 0) && will_patch_syscalls();
  pid_t child = fork();
  if (!child) {
    pthread_t thread;
    pthread_create(&thread, NULL, do_thread, NULL);
    if (expect_kill) {
      rr_arm_kill(RRCALL_KILL_BEFORE_SYSCALL_PATCH_EXIT, SYS_getppid, 0);
    }
    patchable_getppid();
    test_assert(!expect_kill && "Should have been killed");
    return 0;
  }
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  if (expect_kill) {
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
