/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "ptrace_util.h"

static void* do_thread(void* arg) {
  int pipe_fd = *(int*)arg;
  uint32_t tid = sys_gettid();

  write(pipe_fd, &tid, 4);
  /* Sleep long enough that it will be noticed if it's not interrupted. */
  sleep(1000);

  return NULL;
}

int main(void) {
  pid_t child, child2;
  uint32_t msg;
  int status;
  int pipe_fds[2];
  struct user_regs_struct regs;

  test_assert(0 == pipe(pipe_fds));

  if (0 == (child = fork())) {
    pthread_t t;

    pthread_create(&t, NULL, do_thread, &pipe_fds[1]);
    pthread_join(t, NULL);

    return 77;
  }

  test_assert(4 == read(pipe_fds[0], &msg, 4));
  child2 = (pid_t)msg;
  close(pipe_fds[0]);
  sched_yield();

  /* Hit the entire process group with a SIGSTOP. */
  tgkill(child, child, SIGSTOP);

  /* Force the rr scheduler to run. */
  sched_yield();

  /* Now seize the stopped task. */
  test_assert(0 == ptrace(PTRACE_SEIZE, child2, 0, 0));
  test_assert(child2 == waitpid(child2, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  /* Do something that requires the task to be stopped. */
  ptrace_getregs(child2, &regs);

  /* Verify that we can resume from group stops. */
  test_assert(0 == ptrace(PTRACE_CONT, child2, 0, 0));
  /* Force the rr scheduler to run. */
  sched_yield();
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child2, 0, 0));
  test_assert(child2 == waitpid(child2, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
