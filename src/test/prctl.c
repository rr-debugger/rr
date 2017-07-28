/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  char setname[16] = "prctl-test";
  char getname[16];
  unsigned long slack = sizeof(unsigned long) == 4
                            ? 1024 * 1024 * 1024
                            : (unsigned long)(1024LL * 1024 * 1024 * 8);
  int sig = 99;
  int tsc = 99;
  int dummy;

  test_assert(0 == prctl(PR_SET_KEEPCAPS, 0));
  test_assert(0 == prctl(PR_GET_KEEPCAPS));

  test_assert(0 == prctl(PR_SET_KEEPCAPS, 1));
  test_assert(1 == prctl(PR_GET_KEEPCAPS));

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

  test_assert(0 ==
              prctl(PR_MCE_KILL, PR_MCE_KILL_SET, PR_MCE_KILL_EARLY, 0, 0));
  test_assert(PR_MCE_KILL_EARLY == prctl(PR_MCE_KILL_GET, 0, 0, 0, 0));

  test_assert(-1 == prctl(PR_GET_ENDIAN, &dummy) && errno == EINVAL);
  test_assert(-1 == prctl(PR_GET_FPEMU, &dummy) && errno == EINVAL);
  test_assert(-1 == prctl(PR_GET_FPEXC, &dummy) && errno == EINVAL);
  test_assert(-1 == prctl(PR_GET_UNALIGN, &dummy) && errno == EINVAL);

  test_assert(0 == prctl(PR_GET_PDEATHSIG, (unsigned long)&sig));
  test_assert(sig == 0);

  test_assert(0 == prctl(PR_GET_TSC, (unsigned long)&tsc));
  test_assert(tsc == PR_TSC_ENABLE);

  test_assert(0 == prctl(PR_GET_SECCOMP));

  int reaper;
  test_assert(0 == prctl(PR_SET_CHILD_SUBREAPER, 1));
  test_assert(0 == prctl(PR_GET_CHILD_SUBREAPER, &reaper));
  test_assert(reaper == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
