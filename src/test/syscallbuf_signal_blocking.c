/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];
static int got_sigs;

static void handle_sig(__attribute__((unused)) int sig,
                       __attribute__((unused)) siginfo_t* info,
                       __attribute__((unused)) void* mcontext) {
  write(pipe_fds[1], "x", 1);
  ++got_sigs;
}

int main(void) {
  struct sigaction sa;
  struct sigevent sevp;
  char ch;
  timer_t id;
  struct itimerspec timeout = { { 0, 0 }, { 0, 1000000 } };
  struct syscall_info read_syscall = { SYS_read, { 0, 0, 0, 0, 0, 0 } };
  SyscallWrapper delayed_syscall = get_delayed_syscall();

  test_assert(0 == pipe(pipe_fds));

  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sa.sa_sigaction = handle_sig;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  sa.sa_flags = SA_RESTART;
  sa.sa_handler = SIG_IGN;
  sigaction(SIGTRAP, &sa, NULL);

  sevp.sigev_notify = SIGEV_SIGNAL;
  sevp.sigev_signo = SIGUSR1;
  test_assert(0 == timer_create(CLOCK_MONOTONIC, &sevp, &id));
  test_assert(0 == timer_settime(id, 0, &timeout, NULL));

  /* This will hang unless SIGUSR1 is processed before we read from the pipe */
  read_syscall.args[0] = pipe_fds[0];
  read_syscall.args[1] = (long)&ch;
  read_syscall.args[2] = 1;
  delayed_syscall(&read_syscall);

  test_assert(got_sigs == 1);

  /* Should be ignored */
  raise(SIGTRAP);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
