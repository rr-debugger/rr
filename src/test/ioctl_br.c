/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#include <linux/if_bridge.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
  if (try_setup_ns(CLONE_NEWNET)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  int sk, ret;
  unsigned long args[3];

  sk = socket(AF_INET, SOCK_STREAM, 0);
  if (sk < 0) {
    return 0;
  }

  args[0] = BRCTL_GET_VERSION;
  args[1] = args[2] = 0;
  ret = ioctl(sk, SIOCGIFBR, &args);
  if (ret < 0) {
    test_assert(errno == EOPNOTSUPP);
  } else {
    atomic_printf("version=%d\n", ret);
  }

  if (sizeof (void *) == 4) {
      // In 32 bit compatibility mode, the only operation supported is
      // BRCTL_GET_VERSION; see old_bridge_ioctl in the kernel sources for
      // details.
      atomic_puts("EXIT-SUCCESS");
      return 0;
  }

  // nonsense operation
  args[0] = 0x13371337;
  args[1] = args[2] = 0;
  ret = ioctl(sk, SIOCGIFBR, &args);
  test_assert(ret < 0 && errno == EOPNOTSUPP);

  args[0] = BRCTL_ADD_BRIDGE;
  args[1] = (unsigned long)"mybridge";
  args[2] = 0;
  ret = ioctl(sk, SIOCGIFBR, &args);
  if (ret < 0) {
    atomic_printf("error adding bridge: %d\n", errno);
  }

  int bridges[1024];
  args[0] = BRCTL_GET_BRIDGES;
  args[1] = (unsigned long)bridges;
  args[2] = sizeof(bridges) / sizeof(int);
  ret = ioctl(sk, SIOCGIFBR, &args);
  if (ret < 0) {
    atomic_printf("error BRCTL_GET_BRIDGES: %d\n", errno);
  } else {
    for (int i = 0; i < ret; ++i) {
      atomic_printf("bridge: %d\n", bridges[i]);
    }
  }

  args[0] = BRCTL_DEL_BRIDGE;
  args[1] = (unsigned long)"mybridge";
  args[2] = 0;
  ret = ioctl(sk, SIOCGIFBR, &args);
  if (ret < 0) {
    atomic_printf("error BRCTL_DEL_BRIDGE: %d\n", errno);
  }

  close(sk);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
