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

  // PR_SET_MM_ARG_START needs CAP_SYS_RESOURCE
  int ret = prctl(PR_SET_MM, PR_SET_MM_ARG_START, setname, 0, 0);
  test_assert(0 == ret || (-1 == ret && errno == EPERM));

  // PR_SET_MM_ARG_END needs CAP_SYS_RESOURCE
  ret = prctl(PR_SET_MM, PR_SET_MM_ARG_END, setname + sizeof(setname), 0, 0);
  test_assert(0 == ret || (-1 == ret && errno == EPERM));

  // On a kernel without PR_SET_VMA, this will return EINVAL.
  // On a kernel with PR_SET_VMA but without CONFIG_ANON_VMA_NAME,
  // it will return ENOMEM.
  // On a kernel with it, it should return EBADF, because
  // the rr page is not an anonymous mapping.
  ssize_t page_size = sysconf(_SC_PAGE_SIZE);
  test_assert(-1 == prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7000000, page_size, "foo") &&
              (errno == EINVAL || errno == EBADF || errno == ENOMEM));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
