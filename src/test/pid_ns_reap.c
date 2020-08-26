/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) {
  /* This will try to exit_group while we have a child alive in our
     pid namespace. The kernel will insist on killing and reaping the
     child before this task can complete its exit. */
  exit(66);
}

int main(void) {
  pid_t pid;
  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  /* This is the first child, therefore PID 1 in its PID namespace */
  pid = fork();
  test_assert(pid >= 0);
  if (pid == 0) {
    struct timespec ts = { 0, 10000000 };
    pthread_t thread;
    pid_t ns_child;
    test_assert(getpid() == 1);

    ns_child = fork();
    test_assert(ns_child >= 0);
    if (ns_child == 0) {
      pid_t ns_grandchild = fork();
      if (ns_grandchild == 0) {
        sleep(10);
      }
      return 0;
    }

    /* Make time to allow grandchild to reparent to us */
    nanosleep(&ts, NULL);

    /* Test exiting from a non-main thread */
    pthread_create(&thread, NULL, do_thread, NULL);
    pthread_exit(NULL);
  }

  int status;
  waitpid(pid, &status, 0);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 66);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
