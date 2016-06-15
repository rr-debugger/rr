/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {

  int p[2];
  int size;
  int nsize;

  test_assert(pipe(p) != -1);

  size = fcntl(p[0], F_GETPIPE_SZ);

  if (size == -1 && errno == EINVAL)
  {
    // should we succeed when PIPE_SZ is not supported?
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  atomic_printf("actual pipe size: %i\n", size);

  test_assert(-1 != fcntl(p[0], F_SETPIPE_SZ, size + getpagesize()));

  nsize = fcntl(p[0], F_GETPIPE_SZ);
  atomic_printf("new pipe size: %i\n", nsize);

  test_assert(nsize >= size + getpagesize());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
