/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int child_to_parent[2];

static void* run_child_thread(__attribute__((unused)) void* p) {
  setpriority(PRIO_PROCESS, 0, 10);
  atomic_printf("off-main-thread id = %d\n", sys_gettid());
  write(child_to_parent[1], "x", 1);
  pause();
  return NULL;
}

static int do_child(void) {
  pthread_t thread;

  pthread_create(&thread, NULL, run_child_thread, NULL);
  pause();
  return 66;
}

/* Do a busy delay loop that changes registers so won't trigger
   rr's spinlock-detection heuristic */
static void delay(void) {
#if defined(__x86_64__) || defined(__i386__)
  asm("mov $10000000,%%ecx\n\t"
      "1: loop 1b\n\t"
      : : : "ecx");
#else
  /* Does this actually change registers on ARM??? */
  int i;
  static volatile char ch;
  for (i = 0; i < 10000000; ++i) {
    ch = i % 3;
  }
#endif
}

int main(int argc, __attribute__((unused)) char** argv) {
  pid_t child;
  pid_t exec_child;
  int status;
  char cc;
  char* execv_argv[] = {"/proc/self/exe", "dummy", NULL};

  if (argc > 1) {
    return 99;
  }

  pipe(child_to_parent);
  child = fork();
  if (!child) {
    return do_child();
  }

  read(child_to_parent[0], &cc, 1);
  atomic_printf("sending SIGTERM to %d\n", child);
  kill(child, SIGTERM);
  /* Delay a bit. During this delay the child's main thread
     will handle SIGTERM, rr will schedule it and process the SIGTERM,
     triggering a thread-group exit; the child main thread will proceed
     to its PTRACE_EVENT_EXIT stop, rr will process that too, and the
     child main thread will complete exit and go into zombie state.
     rr will not schedule the child off-main thread since it has lower priority,
     so that thread will advance to its PTRACE_EVENT_EXIT stop and wait there. */
  delay();

  atomic_printf("Sleeping...\n");
  /* Do an execve. Here we'll see the child off-main thread's PTRACE_EVENT_EXIT
     stop but we won't act on it because we're in an execve for another
     thread group */
  exec_child = fork();
  if (exec_child == 0) {
    execve("/proc/self/exe", execv_argv, NULL);
  }
  test_assert(exec_child == waitpid(exec_child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 99);

  atomic_printf("sending SIGKILL to %d\n", child);
  assert(kill(child, SIGKILL) == 0);
  /* Delay a bit more. During this delay the child's off-main thread will
     respond to the SIGKILL by exiting its PTRACE_EVENT_EXIT stop and going into
     zombie state. rr still won't schedule that thread and doesn't know anything
     about it exiting. */
  delay();

  atomic_printf("Sleeping...\n");
  /* Do a second execve. Here rr will see the child's off-main thread go into
     the zombie state but we still won't act on it because we're in yet another
     execve for yet another thread group. */
  exec_child = fork();
  if (exec_child == 0) {
    execve("/proc/self/exe", execv_argv, NULL);
  }
  test_assert(exec_child == waitpid(exec_child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 99);

  /* Finally, make the child's off-main thread schedulable by making the last
     surviving higher-priority task sleep. */
  sleep(1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
