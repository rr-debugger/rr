/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 1000

static int fds[2];

/* Returns true if the child is sleeping in its read() of fds[0]. */
static int child_blocked_in_read(pid_t child) {
  char path[PATH_MAX];
  char buf[1024];
  char* p;
  long nr;
  unsigned long arg1;
  int fd;
  ssize_t len;

  sprintf(path, "/proc/%d/stat", child);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  p = strrchr(buf, ')');
  test_assert(p != NULL);
  if (p[2] != 'S') {
    return 0;
  }

  sprintf(path, "/proc/%d/syscall", child);
  fd = open(path, O_RDONLY);
  test_assert(fd >= 0);
  len = read(fd, buf, sizeof(buf) - 1);
  test_assert(len > 0);
  buf[len] = 0;
  test_assert(0 == close(fd));
  return sscanf(buf, "%ld 0x%lx", &nr, &arg1) == 2 && nr == SYS_read &&
         arg1 == (unsigned long)fds[0];
}

int main(void) {
  pid_t child;
  int status;
  int i;
  char ch;

  test_assert(0 == pipe(fds));

  if (0 == (child = fork())) {
    test_assert(1 == read(fds[0], &ch, 1));
    return 77;
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  for (i = 0; i < NUM_ITERATIONS; ++i) {
    /* Interrupt the child while it's blocked in read(), and resume it. */
    while (!child_blocked_in_read(child)) {
      sched_yield();
    }
    test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
    test_assert(child == waitpid(child, &status, 0));
    /* Linux reports a PTRACE_EVENT_STOP with SIGTRAP here, but rr doesn't
       emulate that exactly. */
    test_assert(WIFSTOPPED(status));
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  }

  test_assert(1 == write(fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
