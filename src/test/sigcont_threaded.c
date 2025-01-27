/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void *child_process_extra_thread(__attribute__((unused)) void *extra_thread) {
  int r;

  // Slap in a sched_yield or two here so that the parent process is going to be
  // blocked in pthread_join.
  sched_yield();
  sched_yield();

  // Now, stop ourselves. We'll be unstopped by the parent process.
  r = kill(sys_gettid(), SIGSTOP);
  test_assert(r == 0);

  // Now allow self to exit, and the thread-group-leader can continue.
  return NULL;
}

static void child_process(void) {
  pthread_t extra_thread;
  int r;
  // Spawn an additional thread
  r = pthread_create(&extra_thread, NULL, child_process_extra_thread, NULL);
  test_assert(r == 0);

  // Wait for the child thread we made. It will send SIGSTOP to the process.
  r = pthread_join(extra_thread, NULL);
  test_assert(r == 0);
}

static void parent_process(pid_t pid) {
  int wait_status, r;
  pid_t wpid;

  // Wait for the child process to have sent itself SIGSTOP
  wpid = waitpid(pid, &wait_status, WUNTRACED);
  test_assert(wpid == pid);
  test_assert(WIFSTOPPED(wait_status));
  test_assert(WSTOPSIG(wait_status) == SIGSTOP);

  // Let it continue
  r = kill(pid, SIGCONT);
  test_assert(r == 0);

  // Now the child process should actually exit
  wpid = waitpid(pid, &wait_status, 0);
  test_assert(wpid == pid);
  test_assert(WIFEXITED(wait_status));
}

int main(void) {
  pid_t pid = fork();
  test_assert(pid != -1);
  if (pid == 0) {
    child_process();
  } else {
    parent_process(pid);
    atomic_puts("EXIT-SUCCESS");
  }
  return 0;
}
