/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* The kernel doesn't pass robust futex lists on to new tasks. */

struct entry {
  struct robust_list list;
  uint32_t futex;
};

struct lists {
  struct robust_list_head head;
  struct entry entry;
};

/* Shared with the children */
static struct lists* shared;

static int take_futex(__attribute__((unused)) void* p) {
  shared->entry.futex = sys_gettid();
  return 0;
}

/* Runs fn in a child process that doesn't register robust lists itself
   (unlike the child of glibc's fork()), and waits for it. Returns its pid. */
static pid_t run_child(int (*fn)(void*)) {
  static char stack[65536];
  int status;
  pid_t child =
      clone(fn, (void*)(((uintptr_t)stack + sizeof(stack)) & ~(uintptr_t)15),
            SIGCHLD, NULL);
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  return child;
}

int main(void) {
  void* old_head;
  size_t old_len;
  pid_t child;

  shared = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  test_assert(shared != MAP_FAILED);

  /* Replace glibc's list with a list of a futex that's free */
  test_assert(0 == syscall(SYS_get_robust_list, 0, &old_head, &old_len));
  shared->head.list.next = &shared->entry.list;
  shared->head.futex_offset = offsetof(struct entry, futex);
  shared->head.list_op_pending = NULL;
  shared->entry.list.next = &shared->head.list;
  shared->entry.futex = 0;
  test_assert(
      0 == syscall(SYS_set_robust_list, &shared->head, sizeof(shared->head)));
  /* A child takes the futex and exits. It doesn't have our list, so the
     futex keeps its tid. */
  child = run_child(take_futex);
  test_assert(shared->entry.futex == (uint32_t)child);
  test_assert(0 == syscall(SYS_set_robust_list, old_head, old_len));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
