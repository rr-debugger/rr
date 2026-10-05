/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* SIGCONT doesn't end ptrace stops, including the group stops of tracees.
   In each case below, a SIGCONT is pending for a tracee in a ptrace stop,
   and the tracer yields so that the rr scheduler looks at the tracee. The
   tracee must still be in its stop afterwards. */

static int to_child_fds[2];
static int from_child_fds[2];
static int thread_fds[2];

static void yield_a_lot(void) {
  int i;
  for (i = 0; i < 10; ++i) {
    sched_yield();
  }
}

/* Returns true if the child is sleeping in its read() of to_child_fds[0]. */
static int child_blocked_in_read(pid_t child) {
  char path[PATH_MAX];
  char buf[1024];
  char* p;
  long nr;
  unsigned long arg1;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/%d/stat", child);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  if (p[2] != 'S') {
    return 0;
  }

  sprintf(path, "/proc/%d/syscall", child);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  return sscanf(buf, "%ld 0x%lx", &nr, &arg1) == 2 && nr == SYS_read &&
         arg1 == (unsigned long)to_child_fds[0];
}

static void kill_child(pid_t child) {
  int status;
  test_assert(0 == kill(child, SIGKILL));
  do {
    test_assert(child == waitpid(child, &status, 0));
  } while (!WIFSIGNALED(status));
}

/* A tracee in a PTRACE_INTERRUPT stop, with a blocked SIGCONT pending. */
static void interrupt_stop(void) {
  struct user_regs_struct regs;
  sigset_t set;
  pid_t child;
  int status;
  char ch;

  if (0 == (child = fork())) {
    sigemptyset(&set);
    sigaddset(&set, SIGCONT);
    test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
    test_assert(0 == kill(getpid(), SIGCONT));
    test_assert(1 == write(from_child_fds[1], "r", 1));
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    return;
  }
  test_assert(1 == read(from_child_fds[0], &ch, 1));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  while (!child_blocked_in_read(child)) {
    sched_yield();
  }
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP);
  yield_a_lot();
  ptrace_getregs(child, &regs);
  kill_child(child);
}

/* A seized tracee in a group stop, which its tracer sends SIGCONT. */
static void group_stop(void) {
  struct user_regs_struct regs;
  pid_t child;
  int status;
  char ch;

  if (0 == (child = fork())) {
    test_assert(1 == write(from_child_fds[1], "r", 1));
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    return;
  }
  test_assert(1 == read(from_child_fds[0], &ch, 1));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSTOP));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_STOP << 16) | (SIGSTOP << 8) | 0x7f));
  test_assert(0 == kill(child, SIGCONT));
  yield_a_lot();
  ptrace_getregs(child, &regs);
  /* Linux reports a PTRACE_EVENT_STOP for the SIGCONT first, but rr doesn't
     emulate that. */
  do {
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
    test_assert(child == waitpid(child, &status, 0));
  } while (status != ((SIGCONT << 8) | 0x7f));
  kill_child(child);
}

/* A stopped child that its parent attaches to, then sends SIGCONT. */
static void attach_to_stopped(void) {
  struct user_regs_struct regs;
  pid_t child;
  int status;
  char ch;

  if (0 == (child = fork())) {
    test_assert(0 == raise(SIGSTOP));
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    return;
  }
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(0 == kill(child, SIGCONT));
  yield_a_lot();
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  ptrace_getregs(child, &regs);
  kill_child(child);
}

static void* thread_main(__attribute__((unused)) void* p) {
  pid_t tid = sys_gettid();
  char ch;
  test_assert(sizeof(tid) == write(from_child_fds[1], &tid, sizeof(tid)));
  test_assert(1 == read(thread_fds[0], &ch, 1));
  return NULL;
}

/* A stopped process whose second thread its parent attaches to. The parent
   sends that thread SIGCONT. Linux continues the process's untraced threads,
   whichever thread a SIGCONT is for, so the main thread must answer. */
static void traced_thread_sigcont(void) {
  struct user_regs_struct regs;
  pthread_t thread;
  pid_t child;
  pid_t tid;
  int status;
  char ch;

  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, thread_main, NULL));
    while (1) {
      test_assert(1 == read(to_child_fds[0], &ch, 1));
      test_assert(1 == write(from_child_fds[1], &ch, 1));
    }
  }
  test_assert(sizeof(tid) == read(from_child_fds[0], &tid, sizeof(tid)));
  test_assert(0 == kill(child, SIGSTOP));
  test_assert(0 < waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_SEIZE, tid, NULL, NULL));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == syscall(SYS_tgkill, child, tid, SIGCONT));
  yield_a_lot();
  ch = 'x';
  test_assert(1 == write(to_child_fds[1], &ch, 1));
  test_assert(1 == read(from_child_fds[0], &ch, 1));
  test_assert(ch == 'x');
  ptrace_getregs(tid, &regs);
  test_assert(0 == kill(child, SIGKILL));
  test_assert(tid == waitpid(tid, &status, __WALL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

int main(void) {
  pid_t self = getpid();

  test_assert(0 == pipe(to_child_fds));
  test_assert(0 == pipe(from_child_fds));
  test_assert(0 == pipe(thread_fds));

  interrupt_stop();
  if (getpid() != self) {
    return 77;
  }
  group_stop();
  if (getpid() != self) {
    return 77;
  }
  attach_to_stopped();
  if (getpid() != self) {
    return 77;
  }
  traced_thread_sigcont();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
