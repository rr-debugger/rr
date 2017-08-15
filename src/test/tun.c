/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

static void test_tun(void) {
  struct ifreq* ifr;
  int* features;
  int* sndbuf;
  int* hdrsz;
  struct sock_fprog* fprog;
  int fd = open("/dev/net/tun", O_RDWR);

  if (fd < 0) {
    atomic_puts("Can't open /dev/net/tun --- not supported?");
    atomic_puts("EXIT-SUCCESS");
    exit(0);
  }

  ALLOCATE_GUARD(features, 0);
  test_assert(ioctl(fd, TUNGETFEATURES, (void*)features) == 0);
  VERIFY_GUARD(features);
  test_assert((*features & IFF_TAP) != 0);

  ALLOCATE_GUARD(ifr, 'a');
  memset(ifr, 0, sizeof(*ifr));
  ifr->ifr_flags = IFF_TAP;
  test_assert(ioctl(fd, TUNSETIFF, (void*)ifr) == 0);
  VERIFY_GUARD(ifr);
  test_assert(ifr->ifr_name[0] != 0);
  atomic_printf("ifname: %s\n", ifr->ifr_name);

  ALLOCATE_GUARD(ifr, 0);
  test_assert(ioctl(fd, TUNGETIFF, (void*)ifr) == 0);
  VERIFY_GUARD(ifr);
  test_assert((ifr->ifr_flags & IFF_TAP) != 0);
  test_assert(ifr->ifr_name[0] != 0);

  ALLOCATE_GUARD(sndbuf, 0);
  test_assert(ioctl(fd, TUNGETSNDBUF, (void*)sndbuf) == 0);
  VERIFY_GUARD(sndbuf);
  test_assert(*sndbuf > 0);

  ALLOCATE_GUARD(hdrsz, 0);
  test_assert(ioctl(fd, TUNGETVNETHDRSZ, (void*)hdrsz) == 0);
  VERIFY_GUARD(hdrsz);
  test_assert(*hdrsz > 0);

  ALLOCATE_GUARD(fprog, 'x');
  test_assert(ioctl(fd, TUNGETFILTER, (void*)fprog) == 0);
  VERIFY_GUARD(fprog);
  test_assert(fprog->len == 0);
}

int main(void) {
  if (-1 == try_setup_ns(CLONE_NEWNET)) {
    atomic_printf("EXIT-SUCCESS");
    return 0;
  }

  test_tun();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
