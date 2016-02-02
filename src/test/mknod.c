/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define FILENAME "foo"
#define MODE (S_IFIFO)

int main(void) {
  int result;
  struct stat* st;

  result = mknod(FILENAME, MODE, 0);
  test_assert(result == 0);

  ALLOCATE_GUARD(st, 'x');
  test_assert(stat(FILENAME, st) == 0);

  test_assert(st->st_mode == MODE);
  FREE_GUARD(st);

  result = mknod(FILENAME, MODE, 0);

  test_assert(result < 0);
  test_assert(errno == EEXIST);

  unlink(FILENAME);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
