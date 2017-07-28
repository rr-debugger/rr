/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define FILENAME "foo"
#define MODE S_IFIFO

int main(void) {
  struct stat* st;

  test_assert(mknod(FILENAME, MODE, 0) == 0);

  ALLOCATE_GUARD(st, 'x');
  test_assert(stat(FILENAME, st) == 0);
  test_assert(st->st_mode == MODE);
  VERIFY_GUARD(st);

  test_assert(mknod(FILENAME, MODE, 0) < 0);
  test_assert(errno == EEXIST);

  test_assert(0 == unlink(FILENAME));

  test_assert(mknodat(AT_FDCWD, FILENAME, MODE, 0) == 0);

  test_assert(stat(FILENAME, st) == 0);
  test_assert(st->st_mode == MODE);
  VERIFY_GUARD(st);

  test_assert(0 == unlink(FILENAME));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
