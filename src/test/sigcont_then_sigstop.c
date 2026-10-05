/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 24

static void send_sigcont(pid_t child, int pidfd, int i) {
  siginfo_t si;

  memset(&si, 0, sizeof(si));
  si.si_signo = SIGCONT;
  si.si_code = SI_QUEUE;
  si.si_pid = getpid();
  si.si_uid = getuid();
  switch (i % 6) {
    case 0:
      test_assert(0 == kill(child, SIGCONT));
      break;
    case 1:
      test_assert(0 == syscall(RR_tkill, child, SIGCONT));
      break;
    case 2:
      test_assert(0 == syscall(RR_tgkill, child, child, SIGCONT));
      break;
    case 3:
      test_assert(0 == syscall(RR_rt_sigqueueinfo, child, SIGCONT, &si));
      break;
    case 4:
      test_assert(0 ==
                  syscall(RR_rt_tgsigqueueinfo, child, child, SIGCONT, &si));
      break;
    case 5:
      if (pidfd >= 0) {
        test_assert(0 ==
                    syscall(RR_pidfd_send_signal, pidfd, SIGCONT, NULL, 0));
      } else {
        test_assert(0 == kill(child, SIGCONT));
      }
      break;
  }
}

int main(void) {
  int fds[2];
  pid_t child;
  int pidfd;
  int status;
  int i;
  char ch;

  test_assert(0 == pipe(fds));
  child = fork();
  if (!child) {
    test_assert(1 == read(fds[0], &ch, 1));
    return 77;
  }

  /* Send some of the SIGCONTs with pidfd_send_signal, if we have it. */
  pidfd = syscall(RR_pidfd_open, child, 0);
  if (pidfd < 0) {
    test_assert(errno == ENOSYS);
  } else if (syscall(RR_pidfd_send_signal, pidfd, 0, NULL, 0) < 0) {
    test_assert(errno == ENOSYS);
    pidfd = -1;
  }

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    test_assert(0 == kill(child, SIGSTOP));
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    /* The SIGCONT continues the child right away. The next SIGSTOP may
       discard the pending SIGCONT before the child runs, but must still stop
       the child again. */
    send_sigcont(child, pidfd, i);
  }

  test_assert(1 == write(fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
