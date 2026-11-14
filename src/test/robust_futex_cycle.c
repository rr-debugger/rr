/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A child exits with a robust futex list whose entry is its own next entry,
   which never leads back to the head. The kernel walks at most
   ROBUST_LIST_LIMIT entries of a list when a task exits. */

struct entry {
  struct robust_list list;
  uint32_t futex;
};

static struct {
  struct robust_list_head head;
  struct entry entry;
} cycle;

int main(void) {
  int status;
  pid_t child;

  child = fork();
  if (!child) {
    cycle.head.list.next = &cycle.entry.list;
    cycle.head.futex_offset = offsetof(struct entry, futex);
    cycle.head.list_op_pending = NULL;
    cycle.entry.list.next = &cycle.entry.list;
    cycle.entry.futex = 0;
    test_assert(0 ==
                syscall(SYS_set_robust_list, &cycle.head, sizeof(cycle.head)));
    _exit(0);
  }
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
