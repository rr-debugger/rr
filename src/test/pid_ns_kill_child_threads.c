/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#define NUM_THREADS_PER_GRANDCHILD 5

static void* do_thread(__attribute__((unused)) void* p) {
  pause();
  return NULL;
}

static void do_grandchild(void) {
  pthread_t thread;
  /* Reduce thread priority so rr doesn't schedule these threads unless we want it to */
  setpriority(PRIO_PROCESS, 0, 5);
  for (int i = 0; i < NUM_THREADS_PER_GRANDCHILD; ++i) {
    pthread_create(&thread, NULL, do_thread, NULL);
  }
  pause();
}

int main(void) {
  pid_t pid;
  int pipe_fds[2];
  char ch;
  pipe(pipe_fds);
  struct timespec ts = { 0, 1000000 };

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  /* This is the first child, therefore PID 1 in its PID namespace.
     Spawn some grandchildren that don't exit by themselves but spawn some threads.

     The bug we're looking for here is:
     * zap_pid_ns_processes tears down the pid-namespace children of our child
     * we get the PTRACE_EVENT_EXIT for that grandchild's thread-group leader before we've seen the
     exit event of all of its child threads
     * The grandchild's thread-group leader reaches zombie state but we don't reap it
     (because we can't safely do so until all its child threads have been reaped)
     * So we just carry on leaving the thread-group leader unreaped. But later on
     when we try to kill our child, the pid-namespace root, we're unable to observe
     its exit because it is waiting to reap the thread-group leader zombie, and it can't.
  */
  pid = fork();
  test_assert(pid >= 0);
  if (!pid) {
    pid = fork();
    test_assert(pid >= 0);
    if (!pid) {
      do_grandchild();
    }
    write(pipe_fds[1], "x", 1);
    pause();
  }

  read(pipe_fds[0], &ch, 1);

  atomic_puts("EXIT-SUCCESS");
  kill(pid, SIGKILL);
  nanosleep(&ts, NULL);
  
  return 0;
}
