/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int futex(int* uaddr, int op, int val, const struct timespec* timeout,
                 int* uaddr2, int val2) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val2);
}

static pid_t child_tid;

static int child_SIGKILL(__attribute__((unused)) void* arg) {
  kill(getpid(), SIGKILL);
  return 0;
}

static int child_SIGSEGV(__attribute__((unused)) void* arg) {
  kill(getpid(), SIGSEGV);
  return 0;
}

int main(void) {
  int status = 0;

  size_t page_size = sysconf(_SC_PAGESIZE);
  void *shared_page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  *(pid_t*)shared_page = (pid_t)-1;

  if ((child_tid = fork()) == 0) {
    const size_t stack_size = 1 << 20;
    void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    /* We spawn a thread in the same address space, but in a different
     *  thread group. */
    pid_t tid = clone(child_SIGKILL, stack + stack_size,
                CLONE_VM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID,
                NULL, &child_tid, NULL, &child_tid);

    test_assert(tid > 0);

    futex(&child_tid, FUTEX_WAIT, tid, NULL, NULL, 0);
    /* clone() should have cleared child_tid now */
    test_assert(child_tid == 0);
    test_assert(tid == waitpid(tid, &status, __WALL));
    test_assert(WIFSIGNALED(status));

    tid = clone(child_SIGSEGV, stack + stack_size,
                CLONE_VM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID,
                NULL, shared_page, NULL, shared_page);
    test_assert(tid > 0);

    test_assert(tid = waitpid(tid, &status, __WALL));
    test_assert(WIFSIGNALED(status));
    return 0;
  }

  test_assert(child_tid > 0);
  test_assert(child_tid == waitpid(child_tid, &status, __WALL));
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) {
    atomic_puts("Old (<5.16) kernel behavior");
    // In this case the value of *shared_page is nondeterministic.
    // If the child_SIGKILL task exits first, it's sharding address space
    // with the fork() child so the kernel will clear *shared_page.
    // But the fork() child can exit first, in which case when the
    // child_SIGKILL task exits, it's not sharing its address space with
    // any other task, and the kernel doesn't clear *shared_page.
    // This is observable if you run this test under `strace -f` on
    // a < 5.16 kernel; for me, it causes the test to fail if we check
    // *shared_page == 0 here.
  } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    atomic_puts("New (5.16+) kernel behavior");
    test_assert(*(pid_t*)shared_page == 0);
  } else {
    test_assert(0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
