/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#define NUM_THREADS 10

static int trigger_last_thread_pipe[2];
static int trigger_pid_ns_init_exit_pipe[2];
static int toplevel_exit_pipe[2];

static void* do_thread(void* p) {
  int index = (intptr_t)p;
  /* Reduce thread priority so rr doesn't schedule these threads unless we want it to */
  setpriority(PRIO_PROCESS, 0, 5);
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

/**
 * 1) make the last thread of 'child' do an 'exit_group', initiating kill of all threads
 * in particular 'child's main thread, which advances to PTRACE_EVENT_EXIT
 * 2) then have the pid_ns_init process exit, triggering kernel's zap_pid_ns_processes
 * for 'child' and 'inner_child'
 * 3) this kicks 'child' out of PTRACE_EVENT_EXIT (without rr having seen it)
 * 4) 'child' then enters its own zap_pid_ns_processes and waits on the exit of
 * 'inner_child'
 * 5) rr sees that 'child' has been reaped, but it's not in STOPPED state nor
 * is it in EXITED state.
 */
static int do_pid_ns_init(void) {
  pid_t child;
  char ch;
  pipe(trigger_last_thread_pipe);

  unshare(CLONE_NEWPID);
  child = fork();
  if (!child) {
    pid_t inner_child;
    for (int i = 0; i < NUM_THREADS; ++i) {
      pthread_t thread;
      pthread_create(&thread, NULL, do_thread, (void*)(intptr_t)i);
    }

    test_assert(0 == unshare(CLONE_NEWPID));
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
  write(toplevel_exit_pipe[1], "q", 1);
  return 77;
}

int main(void) {
  pid_t pid;
  char ch;

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("Insufficient permissions, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  atomic_puts("EXIT-SUCCESS");

  pipe(trigger_pid_ns_init_exit_pipe);
  pipe(toplevel_exit_pipe);
  pid = fork();
  test_assert(pid >= 0);
  if (!pid) {
    return do_pid_ns_init();
  }

  read(toplevel_exit_pipe[0], &ch, 1);
  return 0;
}
