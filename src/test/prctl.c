/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  char setname[16] = "prctl-test";
  char getname[16];

  test_assert(0 == prctl(PR_SET_NAME, setname));

  test_assert(0 == prctl(PR_GET_NAME, getname));
  atomic_printf("set name `%s'; got name `%s'\n", setname, getname);
  test_assert(!strcmp(getname, setname));

  test_assert(0 == prctl(PR_SET_DUMPABLE, 0));
  test_assert(0 == prctl(PR_GET_DUMPABLE));

  test_assert(0 == prctl(PR_SET_DUMPABLE, 1));
  test_assert(1 == prctl(PR_GET_DUMPABLE));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
