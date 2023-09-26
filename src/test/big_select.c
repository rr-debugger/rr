/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_LONGS (FD_SETSIZE/(8 * sizeof(long)) + 1)

int main(void) {
  struct {
    long longs[NUM_LONGS];
  } *fdset;
  int ret;
  int pipe_fds[2];
  struct timeval timeout = { 0, 0 };
  struct rlimit rlim = { FD_SETSIZE + 1, FD_SETSIZE + 1 };
  if (setrlimit(RLIMIT_NOFILE, &rlim)) {
    atomic_puts("Can't set necessary rlimit, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  ret = pipe(pipe_fds);
  test_assert(ret == 0);
  ret = dup2(pipe_fds[0], FD_SETSIZE);
  test_assert(ret == FD_SETSIZE);

  ALLOCATE_GUARD(fdset, 'a');
  memset(fdset->longs, 0, sizeof(fdset->longs));
  fdset->longs[NUM_LONGS - 1] = -1;
  ret = select(FD_SETSIZE + 1, (fd_set*)fdset, NULL, NULL, &timeout);
  test_assert(ret == 0);
  VERIFY_GUARD(fdset);

  test_assert(fdset->longs[NUM_LONGS - 1] == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
