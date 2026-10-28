/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void check_siginfo(const siginfo_t* si, pid_t child, int code,
                          int status) {
  test_assert(si->si_signo == SIGCHLD);
  test_assert(si->si_code == code);
  test_assert(si->si_pid == child);
  test_assert(si->si_status == status);
}

/* Waits until |child| has a stop to report, and leaves it reportable. */
static void wait_for_stop(pid_t child) {
  siginfo_t si;
  test_assert(0 == waitid(P_PID, child, &si, WSTOPPED | WNOWAIT));
  test_assert(si.si_pid == child);
}

static void wait_pgid_zero(siginfo_t* si, int options) {
  memset(si, 0, sizeof(*si));
  test_assert(0 == waitid(P_PGID, 0, si, options));
}

int main(void) {
  siginfo_t si;
  pid_t child;
  int ret;

  /* Use a process group of our own. When the group we were started in was
     created outside our pid namespace, getpgid() returns 0 for us and our
     children, so a tracer that took the id 0 for process group 0 would
     still match them. */
  if (getpgid(0) != getpid()) {
    test_assert(0 == setpgid(0, 0));
  }

  /* Before Linux 5.4 (821cc7b0b205), waitid(P_PGID, 0, ...) fails with
     EINVAL. */
  ret = waitid(P_PGID, 0, &si, WEXITED | WNOHANG);
  if (ret < 0 && errno == EINVAL) {
    atomic_puts("waitid(P_PGID, 0, ...) not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == -1 && errno == ECHILD);

  /* A job-control stop that is pending when waitid() starts */
  child = fork();
  if (!child) {
    kill(getpid(), SIGSTOP);
    return 77;
  }
  test_assert(child > 0);
  wait_for_stop(child);
  wait_pgid_zero(&si, WSTOPPED | WNOHANG);
  check_siginfo(&si, child, CLD_STOPPED, SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  wait_pgid_zero(&si, WEXITED);
  check_siginfo(&si, child, CLD_EXITED, 77);

  /* A job-control stop that happens before or during waitid() */
  child = fork();
  if (!child) {
    kill(getpid(), SIGSTOP);
    return 77;
  }
  test_assert(child > 0);
  wait_pgid_zero(&si, WSTOPPED);
  check_siginfo(&si, child, CLD_STOPPED, SIGSTOP);
  test_assert(0 == kill(child, SIGCONT));
  wait_pgid_zero(&si, WEXITED);
  check_siginfo(&si, child, CLD_EXITED, 77);

  /* A ptrace stop of a child we trace */
  child = fork();
  if (!child) {
    test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
    kill(getpid(), SIGSTOP);
    return 77;
  }
  test_assert(child > 0);
  wait_for_stop(child);
  wait_pgid_zero(&si, WSTOPPED | WNOHANG);
  check_siginfo(&si, child, CLD_TRAPPED, SIGSTOP);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  wait_pgid_zero(&si, WEXITED);
  check_siginfo(&si, child, CLD_EXITED, 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
