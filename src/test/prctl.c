/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  char setname[16] = "prctl-test";
  char getname[16];

  prctl(PR_SET_NAME, setname);

  prctl(PR_GET_NAME, getname);
  atomic_printf("set name `%s'; got name `%s'\n", setname, getname);
  test_assert(!strcmp(getname, setname));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
