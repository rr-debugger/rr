/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#define NUM_THREADS 2

static int trigger_last_thread_pipe[2];
static int trigger_pid_ns_init_exit_pipe[2];

static void* do_thread(void* p) {
  int index = (intptr_t)p;
  /* Reduce thread priority so rr doesn't schedule these threads unless we want it to */
  setpriority(PRIO_PROCESS, 0, index + 1);
  if (index == NUM_THREADS - 1) {
    char ch;
    read(trigger_last_thread_pipe[0], &ch, 1);
    /* Kick off the init process exit ...
       after our exit_group has started. */
    write(trigger_pid_ns_init_exit_pipe[1], "x", 1);
    exit(1);
  }
  pause();
  return NULL;
}

static int do_pid_ns_init(void) {
  pid_t child;
  char ch;
  pipe(trigger_last_thread_pipe);
  pipe(trigger_pid_ns_init_exit_pipe);

  test_assert(0 == unshare(CLONE_NEWPID));
  child = fork();
  if (!child) {
    pid_t inner_child;
    for (int i = 0; i < NUM_THREADS; ++i) {
      pthread_t thread;
      pthread_create(&thread, NULL, do_thread, (void*)(intptr_t)i);
    }

    inner_child = fork();
    if (!inner_child) {
      pause();
      return 0;
    }

    write(trigger_last_thread_pipe[1], "y", 1);
    pause();
    return 0;
  }
  read(trigger_pid_ns_init_exit_pipe[0], &ch, 1);
  /* Trigger exit that will zap_pid_ns_processes for our child tasks */
  return 77;
}

static void do_detect_glibc_bug(void) {
  pid_t child;
  int status;
  unshare(CLONE_NEWPID);
  child = fork();
  if (!child) {
    exit(0);
  }
  wait(&status);
  exit(WIFSIGNALED(status));
}

static int detect_glibc_bug_inner(void) {
  int status;
  pid_t pid = fork();
  test_assert(pid >= 0);
  if (!pid) {
    do_detect_glibc_bug();
  }
  wait(&status);
  return WEXITSTATUS(status) != 0;
}

/* Detect https://sourceware.org/legacy-ml/libc-alpha/2017-05/msg00378.html */
static int detect_glibc_bug(void) {
  int status;
  pid_t pid = fork();
  if (!pid) {
    close(STDERR_FILENO);
    if (-1 == try_setup_ns(CLONE_NEWPID)) {
      exit(0);
    }
    exit(detect_glibc_bug_inner());
  }
  wait(&status);
  return WEXITSTATUS(status);
}

int main(void) {
  pid_t pid;
  int status;

  if (detect_glibc_bug()) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  pid = fork();
  test_assert(pid >= 0);
  if (!pid) {
    return do_pid_ns_init();
  }

  test_assert(pid == waitpid(pid, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
