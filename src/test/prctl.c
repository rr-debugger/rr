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

  unsigned int size = 0;
  test_assert(0 == prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, &size, 0, 0));
  test_assert(size != 0);

  // On a kernel without PR_SET_VMA, this will return EINVAL.
  // On a kernel with it, it should return EBADF, because
  // the rr page is not an anonymous mapping.
  static size_t size = sysconf(_SC_PAGE_SIZE);
  test_assert(-1 == prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7000000, size, "foo") &&
              (errno == EINVAL || errno == EBADF));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
