/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);

  /* which path is taken here is out of our control */
  if (ret == -1) {
    test_assert(errno == EINVAL || errno == ENODEV);
    test_assert(-1 == prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
                            PR_SPEC_ENABLE, 0, 0) &&
                (errno == ENXIO || errno == EINVAL));
  } else if (ret != PR_SPEC_NOT_AFFECTED) {
    if (ret & PR_SPEC_PRCTL) {
      if (ret & PR_SPEC_ENABLE) {
        test_assert(0 == prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
                               PR_SPEC_DISABLE, 0, 0));
        test_assert(
            prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0) &
            PR_SPEC_DISABLE);
      } else if (ret & PR_SPEC_DISABLE) {
        test_assert(0 == prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
                               PR_SPEC_ENABLE, 0, 0));
        test_assert(
            prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0) &
            PR_SPEC_ENABLE);
      } else {
        test_assert(ret & PR_SPEC_FORCE_DISABLE);
        test_assert(-1 == prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
                                PR_SPEC_ENABLE, 0, 0) &&
                    errno == EPERM);
      }
    } else {
      test_assert(-1 == prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS,
                              PR_SPEC_ENABLE, 0, 0) &&
                  errno == ENXIO);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
