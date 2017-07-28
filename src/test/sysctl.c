/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <sys/sysctl.h>

int main(void) {
  int name[2] = { CTL_KERN, KERN_RTSIGMAX };
  int sig_max = -1;
  size_t len = sizeof(sig_max);

  name[0] = CTL_KERN;
  name[1] = KERN_RTSIGMAX;
  if (sysctl(name, 2, &sig_max, &len, NULL, 0) == -1) {
    /* many kernels don't support this */
    atomic_printf("sysctl KERN_RTSIGMAX returned errno %d\n", errno);
    atomic_puts("EXIT-SUCCESS");
  } else {
    test_assert(len == sizeof(sig_max));
    atomic_printf("sysctl KERN_RTSIGMAX returned %d\n", sig_max);
    test_assert(sig_max > 0);
    atomic_puts("EXIT-SUCCESS");
  }
  return 0;
}
