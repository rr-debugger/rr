/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

static int child_to_parent[2];

/* Do a busy delay loop that changes registers so won't trigger
   rr's spinlock-detection heuristic */
static void delay(void) {
#if defined(__x86_64__) || defined(__i386__)
  asm("mov $10000000,%%ecx\n\t"
      "1: loop 1b\n\t"
      : : : "ecx", "memory");
#else
  /* Does this actually change registers on ARM??? */
  int i;
  static volatile char ch;
  for (i = 0; i < 10000000; ++i) {
    ch = i % 3;
  }
#endif
}

static void* run_child_thread(__attribute__((unused)) void* p) {
  setpriority(PRIO_PROCESS, 0, 10);
  write(child_to_parent[1], "x", 2);
  /* Make sure it stays runnable so rr can switch to us without
     trying to observe a state change */
  for (;;) {
    delay();
  }
  return NULL;
}

static int do_child(void) {
  pthread_t thread;
  char cc;

  pthread_create(&thread, NULL, run_child_thread, NULL);
  read(child_to_parent[0], &cc, 1);
  return 66;
}

int main(void) {
  pid_t child;
  int status;
  char cc;
  struct timespec ts = { 0, 1000000 };

  if (-1 == try_setup_ns(CLONE_NEWPID)) {
    /* We may not have permission to set up namespaces, so bail. */
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }

  pipe(child_to_parent);
  child = fork();
  if (!child) {
    return do_child();
  }
  atomic_printf("off-main-thread id = %d\n", child + 1);

  read(child_to_parent[0], &cc, 1);
  /* Delay a bit. During this delay the child's main thread
     will complete its exit, triggering a thread-group exit;
     the child main thread will proceed to its PTRACE_EVENT_EXIT stop,
     rr will process that too, and the
     child main thread will complete exit and go into zombie state.
     rr will not schedule the child off-main thread since it has lower priority,
     so that thread will advance to its PTRACE_EVENT_EXIT stop and wait there. */
  delay();

  atomic_printf("sending SIGKILL to %d\n", child);
  kill(child, SIGKILL);
  /* Delay a bit more. During this delay the child's off-main thread will
     respond to the SIGKILL by exiting its PTRACE_EVENT_EXIT stop and going into
     zombie state. rr still won't schedule that thread and doesn't know anything
     about it exiting. */
  delay();

  atomic_printf("Sleeping...\n");
  /* Let the now-dead task resume without waiting for it to change state (since
     rr thinks it's not blocked). */
  nanosleep(&ts, NULL);

  test_assert(child == waitpid(child, &status, 0));
  /* We should exit normally with status 66 but if scheduling is particularly messed
     up we could see SIGKILL. */
  test_assert((WIFEXITED(status) && WEXITSTATUS(status) == 66) ||
              (WIFSIGNALED(status) && WTERMSIG(status) == 9));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
