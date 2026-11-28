/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* The child has rr SIGKILL it while rr handles a desched signal for one of
   its buffered syscalls (the read() below, which blocks, or the write(), if
   waking us preempts it): right after the child reports its next stop
   there, before rr looks at the stop.

   The stop the child is killed in is usually a second desched signal,
   which the child leaves before rr reads it. At a syscall stop, the child
   can instead get to its PTRACE_EVENT_EXIT stop before rr reads its
   registers. Either way, rr must handle the child's exit without resuming
   it.

   In chaos mode, the syscall buffer traces runs of read()s and write()s
   that it could buffer, so the read() can block in a traced syscall,
   without a desched signal, and then nothing kills the child. So before
   each read() the child tells us that it's about to read, and we answer
   with a byte that ends that read() if it blocks. The child reads again
   until rr kills it. */

/* Chaos mode traces runs of 1 to 50 of these syscalls, and puts at least
   10 buffered ones before each run of more than 5, so 100 tries (200
   syscalls) are plenty. */
#define MAX_TRIES 100

int main(void) {
  int to_parent[2];
  int to_child[2];
  pid_t child;
  int status;
  int i;
  char ch;

  test_assert(0 == pipe(to_parent));
  test_assert(0 == pipe(to_child));
  /* rr patches syscalls in a task on their first use, so do a write() and a
     read() here, to make the child's go through the syscall buffer. */
  test_assert(1 == write(to_child[1], "x", 1));
  test_assert(1 == read(to_child[0], &ch, 1));

  if (0 == (child = fork())) {
    if (!rr_arm_kill(RRCALL_KILL_AFTER_DESCHED_STOP_WAIT, 0, 0)) {
      /* Without rr */
      kill(getpid(), SIGKILL);
    }
    for (i = 0; i < MAX_TRIES; ++i) {
      test_assert(1 == write(to_parent[1], "r", 1));
      /* This blocks until we get the parent's answer, unless it's there
         already. */
      test_assert(1 == read(to_child[0], &ch, 1));
    }
    return 77;
  }
  test_assert(child > 0);

  /* Once the child has exited, read() returns 0. We keep our read end of
     to_child open, so that writing to it doesn't fail then. */
  test_assert(0 == close(to_parent[1]));
  while (1 == read(to_parent[0], &ch, 1)) {
    test_assert(1 == write(to_child[1], "x", 1));
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
