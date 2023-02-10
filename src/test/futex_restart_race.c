/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_internal.h"

// This test is extremely sensitive to scheduling differences.
// Essentially the key ingredients that need to happen are:
//
// Condition 1. A futex system call gets interrupted by a signal
// Condition 2. ... But the signal gets dequeued by another thread
// Condition 3. ... and before rr schedules it again, yet another thread performs an execve
// Condition 4. ... and rr notices that the signal-interrupted happened
// Condition 5. ... and every other thread is blocked, so it is forced to use the signal-interrupted thread for execve-cleanup
// Condition 6. ... And the AutoRemoteSyscall is forced through the non-singlestep path

int pid_pipe[2];
pid_t parent_pid;

static int futex(int* uaddr, int op, int val, const struct timespec* timeout,
                 int* uaddr2, int val2) {
  sigset_t set;
  sigemptyset(&set);
  // Block SIGTRAP to force non-singlestep path in AutoRemoteSyscall (Condition 6)
  sigaddset(&set, SIGTRAP);
  pthread_sigmask(SIG_BLOCK, &set, NULL);
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val2);
}

static void handle_usr1(__attribute__((unused)) int sig) {
  test_assert(0 && "Should have been dequeued in sigtimedwait");
}

static void *do_thread(void* futex_addr) {
  atomic_printf("Thread tid is %d\n", sys_gettid());
  pid_t thread_tid = sys_gettid();
  int ret = write(pid_pipe[1], &thread_tid, sizeof(pid_t));
  test_assert(ret == sizeof(pid_t));
  futex(futex_addr, FUTEX_WAIT, 0, NULL, NULL, 0);
  test_assert(0); // Should not return. If the bug happens, futex returns with -512 (ERESTARTSYS)
  return NULL;
}

char* execv_argv[] = {"/proc/self/exe", "--inner", NULL};
static int clone_child(void *unused) {
  (void)unused;
  // Give the parent a chance to enter wait4.
  for (int i = 0; i < 5; ++i)
    sched_yield();
  kill(parent_pid, SIGUSR1);
  execve("/proc/self/exe", execv_argv, NULL);
  test_assert(0 && "Exec should not have failed");
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc == 2) {
    test_assert(strcmp(argv[1], "--inner") == 0);
    return 0;
  }

  if (!running_under_rr()) {
    atomic_puts("WARNING: This test only works under rr.");
    atomic_puts("EXIT-SUCCESS");
    exit(0);
  }

  parent_pid = getpid();
  int ret = pipe(pid_pipe);
  test_assert(ret == 0);

  // Make sure that SIGUSR1 is able to be sent to both threads.
  signal(SIGUSR1, handle_usr1);

  size_t page_size = sysconf(_SC_PAGESIZE);
  int* futex_addr = (int*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                               MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(futex_addr != MAP_FAILED);
  *futex_addr = 0;

  char *child_stack = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(child_stack != MAP_FAILED);

  pthread_t thread;
  pthread_create(&thread, NULL, do_thread, futex_addr);

  pid_t thread_tid;
  ret = read(pid_pipe[0], &thread_tid, sizeof(pid_t));
  test_assert(ret == sizeof(pid_t));

  siginfo_t info;
  sigset_t set;
  sigemptyset(&set);
  // Block all relevant signals on the main thread to make sure that
  // the thread gets selected to receive the signal (Condition 1).
  // Corner case: Because we do waitpid below, the kernel internally removes
  // SIGCHLD from the blocked list for this thread and does not wake up
  // the thread. To work around this, we send SIGUSR1 as well.
  sigaddset(&set, SIGCHLD);
  sigaddset(&set, SIGUSR1);
  ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
  test_assert(ret == 0);

  // Make sure the thread had a chance to enter the futex.
  for (int i = 0; i < 10; ++i) {
    sched_yield();
  }

  // Prevent rr from scheduling the thread until we've properly established all
  // the required conditions for reproducing the bug.
  rr_freeze_tid(thread_tid, 1);
  // Like vfork, but without suspending the parent thread
  pid_t child = clone(clone_child, child_stack + page_size, CLONE_VM | SIGCHLD, NULL);
  test_assert(child != -1);
  int status;
  // Make sure that this thread is blocked while the child's execve
  // happens, to make sure the thread is selected to perform execve
  // cleanup (Condition 5).
  // N.B.: vfork could work here also (and was used in the original bug report),
  // but is racy, because vfork gets released before the ptrace exec notification happens.
  pid_t waited = waitpid(-1, &status, 0);
  test_assert(waited == child);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  // Dequeue all signals before we allow the thread to run again (Condition 2).
  for (int i = 0; i < 2; ++i) {
    int sig = sigwaitinfo(&set, &info);
    test_assert(sig == SIGCHLD || sig == SIGUSR1);
  }
  rr_freeze_tid(thread_tid, 0);
  // Make sure the thread gets a chance to run before it's shot down.
  sched_yield();

  atomic_puts("EXIT-SUCCESS");
  exit(0);
}
