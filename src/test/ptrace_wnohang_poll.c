/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define NUM_THREADS 50

static int parent_to_child_fds[2];

static void* do_thread(__attribute__((unused)) void* p) {
  /* Our tracer polls for this signal-delivery stop. */
  test_assert(0 == syscall(SYS_tgkill, getpid(), sys_gettid(), SIGUSR1));
  return NULL;
}

int main(void) {
  pid_t child;
  char ch;
  int status;
  int i;

  test_assert(0 == pipe(parent_to_child_fds));

  if (0 == (child = fork())) {
    /* If the parent dies, our read() sees EOF: nothing hangs. */
    test_assert(0 == close(parent_to_child_fds[1]));
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    for (i = 0; i < NUM_THREADS; ++i) {
      pthread_t thread;
      test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));
      test_assert(0 == pthread_join(thread, NULL));
    }
    /* Wait until our tracer has reaped the last thread. If we exited
       first, the thread's exit status would be ours. */
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACECLONE));
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));

  for (i = 0; i < NUM_THREADS; ++i) {
    unsigned long msg;
    pid_t tid;
    pid_t ret;
    int polls;

    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == ((PTRACE_EVENT_CLONE << 16) | (SIGTRAP << 8) | 0x7f));
    test_assert(0 == ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg));
    tid = (pid_t)msg;
    /* The thread is our tracee, but not our child. */
    test_assert(tid == waitpid(tid, &status, __WALL));
    test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP);
    test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, (void*)0));
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));

    /* Poll for the thread's signal-delivery stop. A WNOHANG wait that
       returns 0 must not have consumed the stop (or written *status).
       The stop usually comes within the first few polls; after many,
       sleep between polls so that a lost stop doesn't flood the
       recording. */
    polls = 0;
    while (1) {
      status = -1;
      ret = waitpid(tid, &status, WNOHANG | __WALL);
      if (ret == tid) {
        break;
      }
      test_assert(ret == 0);
      test_assert(status == -1);
      if (++polls < 100) {
        sched_yield();
      } else {
        usleep(10000);
      }
    }
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGUSR1);
    /* Suppress the signal and let the thread exit. */
    test_assert(0 == ptrace(PTRACE_CONT, tid, NULL, (void*)0));
    test_assert(tid == waitpid(tid, &status, __WALL));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  test_assert(1 == write(parent_to_child_fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
