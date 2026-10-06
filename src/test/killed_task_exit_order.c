/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* When the child's main thread stops for SIGBUS, we have rr SIGKILL it
   before rr looks at the stop. The child's other thread hasn't run yet, so
   it dies in the stop it started in. The main thread read that thread's
   CLONE_CHILD_CLEARTID tid, which the kernel clears when the thread exits,
   so the main thread's execution up to the SIGBUS must come before the
   other thread's exit in the trace. */

static volatile pid_t child_tid;

static int thread_fn(__attribute__((unused)) void* p) {
  while (1) {
    pause();
  }
  return 0;
}

static void child(void) {
  const size_t stack_size = 1 << 16;
  char* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int fd = open("dummy", O_RDWR | O_CREAT | O_TRUNC, 0600);
  volatile char* p;

  test_assert(stack != MAP_FAILED);
  test_assert(fd >= 0);
  test_assert(0 == unlink("dummy"));
  /* The file is empty, so touching this mapping raises SIGBUS. */
  p = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE, MAP_SHARED, fd,
           0);
  test_assert(p != MAP_FAILED);

  rr_arm_kill(RRCALL_KILL_AFTER_SIGNAL_STOP_WAIT, SIGBUS, 0);
  test_assert(clone(thread_fn, stack + stack_size,
                    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                        CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID |
                        CLONE_CHILD_CLEARTID,
                    NULL, &child_tid, NULL, &child_tid) > 0);
  if (child_tid) {
    *p = 1;
  }
  _exit(77);
}

int main(void) {
  pid_t pid;
  int status;

  pid = fork();
  if (!pid) {
    child();
  }
  test_assert(pid == waitpid(pid, &status, 0));
  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
    atomic_puts("child was killed");
  } else {
    /* Without rr */
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
