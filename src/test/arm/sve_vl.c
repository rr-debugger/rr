/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <sys/prctl.h>
#include <errno.h>

#ifndef PR_SVE_SET_VL
#define PR_SVE_SET_VL 50
#endif
#ifndef PR_SVE_GET_VL
#define PR_SVE_GET_VL 51
#endif
#ifndef PR_SVE_VL_LEN_MASK
#define PR_SVE_VL_LEN_MASK 0xffff
#endif

int main(void) {
  int vl = prctl(PR_SVE_GET_VL);
  /* Skip on hardware without SVE support. */
  if (vl == -1 && errno == EINVAL) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(vl > 0);
  int len = vl & PR_SVE_VL_LEN_MASK;
  test_assert(len > 0);

  /* Set the same vector length we already have. */
  int ret = prctl(PR_SVE_SET_VL, len);
  test_assert(ret >= 0);
  test_assert((ret & PR_SVE_VL_LEN_MASK) == len);

  /* Confirm GET still returns the same value. */
  int vl2 = prctl(PR_SVE_GET_VL);
  test_assert((vl2 & PR_SVE_VL_LEN_MASK) == len);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
