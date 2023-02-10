/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

// In this test we attempt to set up the following situation:
// 1. The parent process gets kicked out of the futex wait by a signal.
// 2. The child process execs and rr commandeers the parent process for cleanup.
// 3. AutoRemoteSyscalls uses PTRACE_INTERRUPT to work around #3141
// 4. rr attempts to inject the signal and sees a spurious group stop from the
//    PTRACE_INTERRUPT.

pid_t parent_tid;
pid_t child_pid;

static int futex(int* uaddr, int op, int val, const struct timespec* timeout,
                 int* uaddr2, int val2) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val2);
}

static int child(__attribute__((unused)) void* arg) {
  sched_yield();

  tgkill(parent_tid, parent_tid, SIGUSR1);
  char* execv_argv[] = {"/proc/self/exe", "--inner", NULL};
  execve("/proc/self/exe", execv_argv, NULL);
  test_assert(0 && "Exec should not have failed");

  /* NOT REACHED */
  return 0;
}

static void usr1_handler(
                    __attribute__((unused)) int sig,
                    __attribute__((unused)) siginfo_t* si,
                    __attribute__((unused)) void* p) {
  atomic_printf("EXIT-SUCCESS\n");
  kill(child_pid, SIGKILL);
  exit(0);
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
    test_assert(strcmp(argv[1], "--inner") == 0);
    pause();
    return 0;
  }

  parent_tid = sys_gettid();

  struct sigaction sa;

  sa.sa_sigaction = usr1_handler;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigaction(SIGUSR1, &sa, NULL);

  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(stack != MAP_FAILED);

  size_t page_size = sysconf(_SC_PAGESIZE);
  int* futex_addr = (int*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(futex_addr != MAP_FAILED);
  *futex_addr = 0;

  child_pid = clone(child, stack + stack_size, CLONE_VM | SIGCHLD, NULL, NULL, NULL,
              NULL);

  // Wait on the futex addr. This is a restartable syscall and we're expecting
  // that the child's exec will kick us out of the syscall with register state
  // indicating the potential for a restart.
  futex(futex_addr, FUTEX_WAIT, 0, NULL, NULL, 0);
  test_assert(0 && "Futex should not have returned");
}
