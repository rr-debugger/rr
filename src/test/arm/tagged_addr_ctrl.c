#include "util.h"

#include <linux/prctl.h>
#include <sys/prctl.h>
#include <errno.h>

int main(void) {
  int ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
  // Skip the test on pre-5.4 kernels which predate the prctl.
  if (ret == -1 && errno == EINVAL) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);

  ret = prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0);
  test_assert(ret == 0);

  ret = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
  test_assert(ret == PR_TAGGED_ADDR_ENABLE);

  // We don't support MTE yet.
  ret = prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_ASYNC,
              0, 0, 0);
  test_assert(ret == -1 && errno == EINVAL);

  atomic_puts("EXIT-SUCCESS");
}
