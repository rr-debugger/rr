/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* This test spawns a ptracer and a ptracee, where the ptracee has 10
   sub-threads.
   The pracer attaches to all the ptracee's threads, then exits.
   We check that all ptracee threads are resumed. */

static int status_pipe[2];
static int tid_pipe[2];
static int ready_pipe[2];
static int thread_wait_pipe[2];

static void write_tid(void) {
  pid_t tid = sys_gettid();
  test_assert(sizeof(tid) == write(tid_pipe[1], &tid, sizeof(tid)));
}

static pid_t read_tid(void) {
  pid_t tid;
  test_assert(sizeof(tid) == read(tid_pipe[0], &tid, sizeof(tid)));
  return tid;
}

static void* child_thread(__attribute__((unused)) void* p) {
  char ch = 0;
  write_tid();
  test_assert(1 == read(thread_wait_pipe[0], &ch, 1));
  test_assert('W' == ch);
  return NULL;
}

static int child_runner(void) {
  char ch = 0;
  pthread_t threads[10];
  int i;

  write_tid();
  for (i = 0; i < 10; ++i) {
    pthread_create(&threads[i], NULL, child_thread, NULL);
  }

  atomic_printf("Waiting on ready_pipe\n");
  test_assert(1 == read(ready_pipe[0], &ch, 1));
  test_assert(ch == 'R');

  for (i = 0; i < 10; ++i) {
    char ch2 = 'W';
    test_assert(1 == write(thread_wait_pipe[1], &ch2, 1));
  }
  for (i = 0; i < 10; ++i) {
    atomic_printf("Joining thread %d\n", i);
    pthread_join(threads[i], NULL);
  }

  char ok = 'K';
  test_assert(1 == write(status_pipe[1], &ok, 1));

  return 77;
}

static int ptracer(void) {
  pid_t child;
  int status;
  char ready = 'R';
  int i;
  pid_t child_tids[11];

  if (0 == (child = fork())) {
    return child_runner();
  }

  for (i = 0; i < 11; ++i) {
    child_tids[i] = read_tid();
  }
  for (i = 0; i < 11; ++i) {
    int ret;
    test_assert(0 == ptrace(PTRACE_ATTACH, child_tids[i], NULL, NULL));
    ret = waitpid(child_tids[i], &status, __WALL);
    atomic_printf("waitpid on %d gives %d with errno=%d\n", child_tids[i], ret,
                  errno);
    test_assert(ret == child_tids[i]);
    test_assert(status == ((SIGSTOP << 8) | 0x7f));
  }

  test_assert(1 == write(ready_pipe[1], &ready, 1));

  /* Now just exit, and all child threads should resume */
  return 44;
}

int main(void) {
  char ch = 0;
  pid_t ptracer_pid;
  int status;

  test_assert(0 == pipe(ready_pipe));
  test_assert(0 == pipe(tid_pipe));
  test_assert(0 == pipe(status_pipe));
  test_assert(0 == pipe(thread_wait_pipe));

  if (0 == (ptracer_pid = fork())) {
    return ptracer();
  }

  test_assert(ptracer_pid == waitpid(ptracer_pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);

  test_assert(1 == read(status_pipe[0], &ch, 1));
  test_assert(ch == 'K');

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
