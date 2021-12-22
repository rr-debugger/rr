/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#define NUM_READERS 10

static int parent_to_child[2];
static int child_to_parent[2];

int main(void) {
  int ret, status;
  char ch;

  // This test is a bit non-deterministic, because it relies on the kernel's
  // scheduling behavior. The scheduling we're looking to test is:
  //   1. The parent process releases the readers from `read` syscall.
  //   2. The reader gets scheduled and advances to the syscall exit trap.
  //   3. The parent gets scheduled and kills the reader.
  //   4. `rr` gets scheduled and sees the exit trap.
  //
  // There are several ways this can go wrong. If the reader doesn't get scheduled
  // before the parent's kill syscall, then rr will never see the syscall exit
  // trap, which doesn't trigger the behavior we're interested in. Similarly,
  // if the reader gets scheduled before `rr`, then it gets advanced to the
  // exit trap again and rr will similarly never see it.
  //
  // To increase our chances of seeing this scheduling behavior, we lower the
  // priority of the test executable here. The idea is to make rr more likely
  // to run if it's runnable at all, in order to decrease the likelihood of
  // the readers being scheduled again between points 3. and 4. above (while
  // keeping the parent and the readers at the same priority to hopefully get
  // the kernel to at least schedule one of the readers at point 2).
  int prio = getpriority(PRIO_PROCESS, 0);
  setpriority(PRIO_PROCESS, 0, prio >= 15 ? 20 : prio + 5);

  test_assert(0 == pipe(parent_to_child));
  test_assert(0 == pipe(child_to_parent));

  pid_t pids[NUM_READERS];
  for (int i = 0; i < NUM_READERS; ++i) {
    pids[i] = fork();
    if (pids[i] == 0) {
        test_assert(1 == write(child_to_parent[1], "x", 1));
        test_assert(1 == read(parent_to_child[0], &ch, 1) && ch == 'y');
        pause();
        return 77;
    }
  }

  // Phase 1: Wait for all readers to become ready.
  char chs[NUM_READERS];
  int sum = 0;
  while (sum < NUM_READERS) {
    ret = read(child_to_parent[0], &chs, NUM_READERS);
    test_assert(ret > 0);
    sum += ret;
  }

  // Phase 2: Release readers from `read` syscall.
  test_assert(NUM_READERS == write(parent_to_child[1], chs, NUM_READERS));

  // Phase 3: Kill readers.
  for (int i = 0; i < NUM_READERS; ++i) {
    kill(pids[i], SIGKILL);
  }

  for (int i = 0; i < NUM_READERS; ++i) {
    test_assert(waitpid(pids[i], &status, 0) == pids[i]);
    test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
