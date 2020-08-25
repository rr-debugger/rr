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

int main(__attribute__((unused)) int argc, char** argv) {
  int fd = open(argv[0], O_RDONLY);
  pid_t child;
  int status;
  char cc;
  struct timespec ts = { 0, 1000000 };

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

  atomic_printf("sending SIGKILL to %d\n", child);
  kill(child, SIGKILL);
  /* Delay a bit more. During this delay the child's off-main thread will
     respond to the SIGKILL by exiting its PTRACE_EVENT_EXIT stop and going into
     zombie state. rr still won't schedule that thread and doesn't know anything
     about it exiting. */
  delay();

  /* Trigger the logic that scans tracee tasks to see if they have the file open
     for writing. */
  mmap(NULL, 4091, PROT_READ, MAP_SHARED, fd, 0);

  atomic_printf("Sleeping...\n");
  /* Try scheduling the now-dead task to make sure we survive that */
  nanosleep(&ts, NULL);

  /* Make sure we can fork after that, i.e. we didn't mess up the state of our
     tracee communication socket. */
  child = fork();
  if (!child) {
    return 77;
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
