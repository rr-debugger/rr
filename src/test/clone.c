/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int futex(int* uaddr, int op, int val, const struct timespec* timeout,
                 int* uaddr2, int val2) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val2);
}

static pid_t child_tid;
static pid_t child_tid_copy;

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

static int child(__attribute__((unused)) void* arg) {
  sigset_t set;
  int fd;
  char byte = 'x';

  /* Be careful in here. This thread was set up by a raw clone() call
   * without TLS support so many things won't work, e.g. atomic_printf.
   */

  /* Do some syscall-bufferable syscalls to make sure that works.
   * The syscallbuf will not have been set up, but the syscalls should
   * still work by not buffering them. */
  fd = open("/dev/zero", O_RDONLY);
  test_assert(fd >= 0);
  test_assert(1 == read(fd, &byte, 1));
  test_assert(0 == byte);
  test_assert(0 == close(fd));

  sigfillset(&set);
  /* NB: we have to naughtily make the linux assumption that
   * sigprocmask is per-task, because we're not a real
   * pthread. */
  test_assert(0 ==
              syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &set, NULL, _NSIG / 8));

  /* clone() should have set child_tid to our tid */
  child_tid_copy = child_tid;
  breakpoint();

  /* We cannot return normally here.  Some clone() implementations call |_exit|
     after the clone function returns; some call SYS_exit.  For consistency
     and correctness's sake, we need to call SYS_exit here. */
  syscall(SYS_exit, 0);

  /* NOT REACHED */
  return 0;
}

int main(void) {
  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int tid;
  sigset_t set;
  test_assert(stack != MAP_FAILED);

  sys_gettid();
  /* NB: no syscalls in between the sys_gettid() above and this
   * clone(). */
  breakpoint();

  /* Warning: strace gets the parameter order wrong and will print
     child_tidptr as 0 here. */
  tid = clone(child, stack + stack_size,
              CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD | CLONE_SIGHAND |
                  CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID,
              NULL, &child_tid, NULL, &child_tid);

  atomic_printf("clone()d pid: %d\n", tid);
  test_assert(tid > 0);

  futex(&child_tid, FUTEX_WAIT, tid, NULL, NULL, 0);
  test_assert(child_tid_copy == tid);
  /* clone() should have cleared child_tid now */
  test_assert(child_tid == 0);

  sys_gettid();

  sigfillset(&set);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));

  /* NB: no syscalls in between the sys_gettid() above and this
   * clone(). */
  breakpoint();
  tid = clone(child, stack + stack_size,
              CLONE_SIGHAND /*must also have CLONE_VM*/, NULL, NULL, NULL);

  atomic_printf("clone(CLONE_SIGHAND)'d tid: %d\n", tid);
  test_assert(-1 == tid);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
