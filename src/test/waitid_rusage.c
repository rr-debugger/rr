/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* glibc's waitid() has no rusage argument. */
static int waitid_ru(pid_t pid, siginfo_t* si, int options,
                     struct rusage* ru) {
  return syscall(SYS_waitid, P_PID, pid, si, options, ru);
}

static void check_timeval(const struct timeval* tv) {
  test_assert(tv->tv_sec >= 0);
  test_assert(tv->tv_usec >= 0 && tv->tv_usec < 1000000);
}

int main(void) {
  int fds[2];
  char ch;
  pid_t pid;
  siginfo_t si;
  struct rusage ru;
  struct rusage ru_unchanged;

  test_assert(0 == pipe(fds));
  pid = fork();
  if (!pid) {
    /* If the parent dies, read() sees EOF: nothing hangs. */
    test_assert(0 == close(fds[1]));
    test_assert(1 == read(fds[0], &ch, 1));
    _exit(0);
  }
  test_assert(pid > 0);
  test_assert(0 == close(fds[0]));

  /* Nothing to report: the kernel leaves *ru alone. */
  memset(&si, 0xff, sizeof(si));
  memset(&ru, 0xff, sizeof(ru));
  memset(&ru_unchanged, 0xff, sizeof(ru_unchanged));
  test_assert(0 == waitid_ru(pid, &si, WEXITED | WNOHANG, &ru));
  test_assert(si.si_pid == 0);
  test_assert(0 == memcmp(&ru, &ru_unchanged, sizeof(ru)));

  /* The child exits: the kernel fills *ru. */
  test_assert(1 == write(fds[1], "x", 1));
  test_assert(0 == waitid_ru(pid, &si, WEXITED, &ru));
  test_assert(si.si_signo == SIGCHLD);
  test_assert(si.si_code == CLD_EXITED);
  test_assert(si.si_pid == pid);
  test_assert(si.si_status == 0);
  /* ru_maxrss can be 0: the kernel reads only the shared part of the
     child's RSS counters, and per-CPU counts move there in batches of
     max(32, 2 * nr_cpus) pages, more than a child this small may use. */
  test_assert(0 != memcmp(&ru, &ru_unchanged, sizeof(ru)));
  test_assert(ru.ru_maxrss >= 0);
  check_timeval(&ru.ru_utime);
  check_timeval(&ru.ru_stime);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
