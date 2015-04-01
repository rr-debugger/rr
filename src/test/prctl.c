/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  char setname[16] = "prctl-test";
  char getname[16];
  unsigned long slack = sizeof(unsigned long) == 4 ? 1024*1024*1024 :
    (unsigned long)(1024LL*1024*1024*8);

  test_assert(0 == prctl(PR_SET_NAME, setname));
  test_assert(0 == prctl(PR_GET_NAME, getname));
  atomic_printf("set name `%s'; got name `%s'\n", setname, getname);
  test_assert(!strcmp(getname, setname));

  test_assert(0 == prctl(PR_SET_DUMPABLE, 0));
  test_assert(0 == prctl(PR_GET_DUMPABLE));

  test_assert(0 == prctl(PR_SET_DUMPABLE, 1));
  test_assert(1 == prctl(PR_GET_DUMPABLE));

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));

  test_assert(0 == prctl(PR_SET_TIMERSLACK, slack));
  /* prctl coerces its result to int */
  test_assert((int)slack == prctl(PR_GET_TIMERSLACK));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
