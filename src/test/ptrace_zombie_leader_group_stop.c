/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* We trace the main thread of a child with two threads. The main thread
   exits and stays a zombie while the other thread lives, then we stop the
   child and interrupt the main thread. An exiting task doesn't take part
   in a group stop or a PTRACE_INTERRUPT, so Linux reports no stop of the
   main thread to us. */

static void* child_thread_main(void* p) {
  int ready_fd = (int)(uintptr_t)p;
  pid_t tid = sys_gettid();
  test_assert(sizeof(tid) == write(ready_fd, &tid, sizeof(tid)));
  for (;;) {
    pause();
  }
  return NULL;
}

int main(void) {
  int ready_fds[2];
  int exit_fds[2];
  pthread_t thread;
  pid_t child;
  pid_t tid;
  int status;
  char c = 'x';
  char state;

  test_assert(0 == pipe(ready_fds));
  test_assert(0 == pipe(exit_fds));
  if (0 == (child = fork())) {
    test_assert(0 == pthread_create(&thread, NULL, child_thread_main,
                                    (void*)(uintptr_t)ready_fds[1]));
    test_assert(1 == read(exit_fds[0], &c, 1));
    syscall(SYS_exit, 0);
  }
  test_assert(child > 0);
  test_assert(sizeof(tid) == read(ready_fds[0], &tid, sizeof(tid)));
  test_assert(tid > 1);

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(1 == write(exit_fds[1], &c, 1));
  while (get_task_state(child) != 'Z') {
    sched_yield();
  }

  test_assert(0 == kill(child, SIGSTOP));
  /* Wait until the other thread has stopped. */
  do {
    state = get_task_state(tid);
    sched_yield();
  } while (state != 'T' && state != 't');

  test_assert(0 == waitpid(child, &status, __WALL | WNOHANG));

  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(0 == waitpid(child, &status, __WALL | WNOHANG));

  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
